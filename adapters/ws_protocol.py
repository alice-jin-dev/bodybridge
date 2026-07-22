"""第 3 层设备协议 · 帧的构造与解析（纯函数，零 I/O）。

桥和设备之间只说两种话（JSON 文本帧）：
    cmd    桥 → 设备   {"v":1,"type":"cmd","id":"...","command":"say","params":{...}}
    result 设备 → 桥   {"v":1,"type":"result","id":"...","ok":...,"message":...,
                        "data":...,"error":...,"retryable":...}

心跳不在这一层：走 websockets 库的协议级 ping/pong（ping_interval）。两个主流
ESP32 固件库（Links2004/arduinoWebSockets、gilmaimon/ArduinoWebsockets）收到
Ping 都在库内自动回 Pong，固件零业务代码，服务"上手求快"。app 层心跳唯一多出
的"固件主循环没卡死"保证，已被命令的 25s deadline -> timeout 兜底覆盖（timeout
语义正是"可能执行了、也可能没有"），不必重复保障。所以协议帧只有 cmd / result。

本模块连 websockets 都不 import：怎么收发是网络层（server.py 的 /device）的事，
这里只管"说什么话"，好脱离网络单测。铁律 3：解析任何外部输入都不许崩，最坏只
返回一个"该忽略"的结果 + 一句给日志看的人话原因。
"""
import json
from dataclasses import dataclass

from .base import DeviceResult

# 协议版本。V1 只会说 v=1；收到别的版本一律忽略（不"宽进"）——协议改版通常意味
# 着字段语义变了，宽进解析新版帧最坏会成功解出一个语义错误的 result 喂给 Claude
# （撒谎），而忽略最坏只是丢一条（沉默）。整个 offline/timeout 设计都遵循"宁可说
# 不确定，不可说假话"，版本宽进违背这个精神。
PROTOCOL_VERSION = 1

TYPE_CMD = "cmd"
TYPE_RESULT = "result"


@dataclass
class ParseOutcome:
    """parse_result_frame 的返回。不变式：要么成功、要么忽略，二选一——
      成功  -> frame_id 与 result 有值，ignore_reason 为 None
      忽略  -> ignore_reason 有值（人话，给日志），frame_id/result 为 None
    另有 debug_note：不参与成功/忽略判定，只在"收下了但有点不对劲"时留一句痕迹
    （目前唯一用途：result 缺 message）。调用方按 debug 级别打印即可。
    """

    frame_id: str | None = None
    result: DeviceResult | None = None
    ignore_reason: str | None = None
    debug_note: str | None = None

    @classmethod
    def accept(cls, frame_id: str, result: DeviceResult,
               debug_note: str | None = None) -> "ParseOutcome":
        return cls(frame_id=frame_id, result=result, debug_note=debug_note)

    @classmethod
    def ignore(cls, reason: str) -> "ParseOutcome":
        return cls(ignore_reason=reason)


def build_cmd_frame(frame_id: str, command: str, params: dict | None) -> str:
    """桥 -> 设备：把一条命令序列化成 JSON 文本帧。

    frame_id 由调用方（Adapter）生成后传入——生成要用随机源，是副作用，留在外面
    本函数才是确定性的、好测。ensure_ascii=False：让"你好"这类中文在线上保持可读、
    也更省字节。
    """
    frame = {
        "v": PROTOCOL_VERSION,
        "type": TYPE_CMD,
        "id": frame_id,
        "command": command,
        "params": params,
    }
    return json.dumps(frame, ensure_ascii=False)


def parse_result_frame(text) -> ParseOutcome:
    """设备 -> 桥：防御性解析一个收到的帧。永不抛异常（铁律 3）。

    逐层兜底，任何一步不对就"忽略 + 一句人话原因"，绝不断连、绝不崩：
      1. 不是合法 JSON（text 是 bytes/None/乱码都在这层被兜住）
      2. 不是 JSON 对象
      3. 版本 v != 本桥版本            -> 忽略（宁可沉默不可撒谎，见 PROTOCOL_VERSION）
      4. type 不是 "result"（含未知帧类型）
      5. 缺 id 或 id 不是非空字符串    -> 无法与在途命令对应
      6. ok 缺失或不是 bool            -> 信封不可信
    过了以上才把五字段复原成 DeviceResult。桥不做语义转换，只搬运。
    """
    try:
        obj = json.loads(text)
    except Exception:
        return ParseOutcome.ignore("收到的帧不是合法 JSON，已忽略。")

    if not isinstance(obj, dict):
        return ParseOutcome.ignore("收到的帧不是 JSON 对象，已忽略。")

    v = obj.get("v")
    if v != PROTOCOL_VERSION:
        return ParseOutcome.ignore(
            f"收到 v={v!r}，本桥仅支持 v={PROTOCOL_VERSION}，已忽略。"
        )

    frame_type = obj.get("type")
    if frame_type != TYPE_RESULT:
        return ParseOutcome.ignore(
            f"收到未知/非预期帧类型 type={frame_type!r}"
            f"（本桥只处理 '{TYPE_RESULT}'），已忽略。"
        )

    frame_id = obj.get("id")
    if not isinstance(frame_id, str) or frame_id == "":
        return ParseOutcome.ignore(
            "result 帧缺少有效的 id（无法与在途命令对应），已忽略。"
        )

    ok = obj.get("ok")
    if not isinstance(ok, bool):
        return ParseOutcome.ignore(
            f"result(id={frame_id}) 的 ok 字段缺失或不是布尔值"
            f"（收到 {ok!r}），信封不可信，已忽略。"
        )

    # --- 帧可信，复原成 DeviceResult ---
    debug_note = None
    message = obj.get("message")
    if not isinstance(message, str):
        # message 本该总在；缺了/类型不对 -> 兜成空串照收（ok/id 才是信封关键，
        # message 只是给人看的话，Claude 靠 error 码判断），但留痕方便排查固件 bug。
        debug_note = (
            f"result(id={frame_id}) 缺 message 或类型不对（{message!r}），已兜成空串。"
        )
        message = ""

    # retryable 只在失败时有意义；非 bool 一律当 False，绝不用 bool() 强转
    # （bool("false") 会是 True，是个坑）。
    retryable = obj.get("retryable", False)
    if not isinstance(retryable, bool):
        retryable = False

    # data 不校验类型，原样搬运（桥不解释语义）。它来自 json.loads，必是 JSON 可
    # 序列化值（str/list/dict/数字/bool/None）——即便设备发来 str 或数组也不会炸：
    # to_dict() 只是把它放进普通 dict，真正的序列化由上层 MCP 的 json.dumps 负责，
    # 而 json.loads 能解出的值 json.dumps 必能原样写回（JSON 往返的天然保证）。
    # error 同理，原样搬运。
    result = DeviceResult(
        ok=ok,
        message=message,
        data=obj.get("data"),
        error=obj.get("error"),
        retryable=retryable,
    )
    return ParseOutcome.accept(frame_id, result, debug_note=debug_note)
