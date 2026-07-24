"""ESP32 设备 Adapter（第 3 层 · WebSocket 长连接的第一个真实设备插槽）。

设备是主动连桥的一方：ESP32 固件用 WebSocket 客户端连到 server.py 的 /device
端点，握手时带 Authorization: Bearer <BODYBRIDGE_DEVICE_TOKEN>。桥这侧只认抽象
DeviceAdapter 契约，换设备＝换这个文件，桥身不动。

本文件当前是【骨架】，分步落地，边界如下：
  - 本步(第 3 步)：立起类 + 单连接状态 + setup/teardown + 三个方法的结构。
    "没设备连着"的路径(-> offline)本步就完整、可测；"设备连着后真去对话"的
    happy path 依赖后续步骤。
  - 第 4 步：server.py 注册 /device 端点，握手鉴权、单连接(新踢旧)，连接建立/
    断开时把 self._connection 塞入/清空；pong 超时库关连时也在关连路径【立刻】
    清空(= 立刻标 offline，不撒谎)。
  - 第 6 步：_send_and_wait 里真正生成 id、登记在途表(上限 MAX_INFLIGHT)、
    build_cmd_frame 发出、在 deadline 内等对应 result。

契约铁律：三个方法 + setup + _send_and_wait 永不向外抛异常——做不到的事一律用
DeviceResult(ok=False) 如实告知("小狗歪头"哲学)。
"""
import asyncio
import sys
import uuid

from .base import DeviceAdapter, DeviceResult, ErrorCode
from .ws_protocol import build_cmd_frame

# 保留命令名：get_status / list_capabilities 复用 cmd 帧问设备(见下方两个方法)，
# 因此占用了设备命令空间里这两个名字。⚠️ 接入文档须写明"以下为当前保留命令名
# (会随版本增加)"，固件业务指令不得重定义；措辞给未来留口。
CMD_GET_STATUS = "get_status"
CMD_LIST_CAPABILITIES = "list_capabilities"


def _disconnect_timeout_result() -> DeviceResult:
    """连接断开（新连接顶替旧的 / 当前连接掉线）时，用来叫醒所有还在等的
    _send_and_wait 的信封。这些命令的帧多半已经发出（先登记后发帧），设备到底
    处理没处理，桥不知道——只能是 timeout，绝不能是 offline（offline = 确定没到
    设备，这里恰恰不确定，说 offline 就是撒谎，违背"宁可说不确定、不可说假话"）。
    """
    return DeviceResult.failure(
        ErrorCode.TIMEOUT,
        "设备连接已断开，这条命令可能已经执行、也可能没有，"
        "请先查一下设备状态再决定要不要重发。",
        retryable=False,
    )


class ESP32Adapter(DeviceAdapter):
    # 本 adapter 支持设备主动持长连接，端点据此放行 /device（见 server.py）。
    supports_direct_connection = True

    def __init__(self, max_inflight: int = 8) -> None:
        # 廉价内存构造，永不 I/O(契约)。_connection = 当前设备的 websockets 连接
        # 对象，由 /device 端点(第 4 步)经 attach/detach 塞入/清空；None = 没有设备
        # 连着。单连接"新踢旧"的切换逻辑就在下面 attach/detach 里（决策 2）。
        self._connection = None
        # 在途命令表：frame_id -> 正在等这条 result 的 asyncio.Future[DeviceResult]。
        # 谁 await（_send_and_wait）、谁 set_result（deliver_result / 断线清算），
        # 见下方方法。max_inflight 由第 7 步切换时传入 server.py 的 MAX_INFLIGHT
        # （adapter 不 import server，避免循环依赖，所以走构造参数）；默认 8 只是
        # 让这个类脱离 server 也能独立构造、独立测试。
        self._inflight: dict[str, "asyncio.Future"] = {}
        self._max_inflight = max_inflight

    def attach_connection(self, connection) -> object | None:
        # 单连接"新踢旧"：先把指针指向新连接（绝无 None 空窗，也绝不同时指两条），
        # 返回旧连接交给端点关闭。单线程 asyncio 下这行赋值是原子的。
        old = self._connection
        self._connection = connection
        # 决策 7：此刻 _inflight 里的条目全部属于【正被替换掉的旧连接】——它们的
        # 帧多半已经发出（先登记后发帧），设备到底处理没处理不知道，只能用 timeout
        # 立刻叫醒，不能让它们干等到 _safe 的 25s 才知道连接已经换了。
        self._fail_all_inflight(_disconnect_timeout_result())
        return old

    def detach_connection(self, connection) -> None:
        # compare-and-clear：只有"当前记录的就是这一条"才清空。被顶掉的旧连接稍后
        # 断开走到这里时，_connection 已是新连接、不是它自己 -> 不清，新连接毫发无伤。
        # 这是"旧连接的清理不会误杀刚接上的新连接"的关键（决策 2）。
        if self._connection is connection:
            self._connection = None
            # 决策 7：这条连接掉线，它名下还在等的命令同样立刻用 timeout 叫醒
            # （不是 offline——理由同 attach：帧多半已发出，不确定设备处理没处理，
            # 说 offline 就是撒谎；见 _disconnect_timeout_result 的说明）。
            self._fail_all_inflight(_disconnect_timeout_result())

    def _fail_all_inflight(self, result: DeviceResult) -> None:
        """把当前在途表里所有还没完成的 future 一次性用 result 叫醒，然后清空表。
        整表替换（而非原地遍历 + pop）：先把 self._inflight 换成新空 dict，再遍历
        旧表，这样遍历过程中不会有人往正在遍历的字典里增删。fut.done() 判断是防御
        ——万一 deliver_result 恰好抢先 set 过（理论上二者都在同步代码里，不会真的
        并发，但双重保险不多花一行），避免对同一个 Future 二次 set_result 而抛异常。
        """
        pending, self._inflight = self._inflight, {}
        for fut in pending.values():
            if not fut.done():
                fut.set_result(result)

    # --- 生命周期 ---------------------------------------------------------
    async def setup(self) -> DeviceResult:
        # "开始监听"语义：设备主动连桥，真正的监听是 /device 路由(第 4 步注册)，
        # adapter 这里没有要主动做的 I/O，直接成功。
        # ⚠️ setup 成功 ≠ 设备在线：此刻可能一台设备都没连上。未连上时三个方法
        #    如实返回 offline，绝不出现"桥活着但 get_status 骗说在线"。
        # message 只进 server 的 stderr 运维日志、永不发给 Claude，故用 ASCII 英文。
        return DeviceResult.success("listening for device connections.")

    async def teardown(self) -> None:
        # 关闭当前连接、清空状态，永不抛(契约)。先清引用再关，避免关的过程中
        # 又有人读到一个"正在关"的连接。
        conn = self._connection
        self._connection = None
        if conn is not None:
            try:
                await conn.close()
            except Exception:
                pass  # 关闭期抛异常是关闭流程经典 bug，吞掉，尽力而为
        return None

    # --- 三个契约方法 -----------------------------------------------------
    async def send_command(self, command: str,
                           params: dict | None = None) -> DeviceResult:
        return await self._send_and_wait(command, params)

    async def get_status(self) -> DeviceResult:
        # get_status 复用 cmd 问设备(保留命令名)，拿真实状态(电量等)。
        # ⚠️ 因此它【不是】廉价的瞬时读操作：也走在途表、也吃桥侧 deadline。
        #    设备离线 -> offline；在线但没回 -> timeout。别当它是读一个本地变量。
        return await self._send_and_wait(CMD_GET_STATUS, None)

    async def list_capabilities(self) -> DeviceResult:
        # list_capabilities 同样问设备(保留命令名)，由固件说了算、更诚实。
        # 方向备忘(不实现)：能力清单基本不变，将来若要开"缓存"的口子，优先给
        #    list_capabilities，别给 get_status——电量一直在变，缓存 get_status 会
        #    骗 Claude(违背"具身状态不返回旧数据"这条既有决策)。
        return await self._send_and_wait(CMD_LIST_CAPABILITIES, None)

    # --- 发送 + 等待回执 + 投递（第 6 步接线）--------------------------------
    async def _send_and_wait(self, command: str,
                             params: dict | None) -> DeviceResult:
        """三个方法唯一的对设备出口。永不向外抛 Exception（契约）。

        唯一放行的是 CancelledError：桥侧 deadline 由 server._safe 的 wait_for 施加，
        超时会 cancel 本协程、在 await fut 处注入 CancelledError。它是协作式取消信号
        （BaseException，不是 Exception），必须让它继续传播给 wait_for 转成 TIMEOUT——
        我们只在 finally 里清表，绝不吞它。吞了 deadline 就失效了。
        """
        conn = self._connection
        if conn is None:
            # offline = 命令【确定没到】设备，retryable=True。
            return DeviceResult.failure(
                ErrorCode.OFFLINE,
                "设备当前没有连接到桥，指令没发出去。",
                retryable=True,
            )

        # 在途表已满：桥主动挡下（命令根本没发出去，同 offline 一样"确定没到"）→ BUSY。
        # len 检查到下面存表之间【没有 await】，asyncio 单线程下这段是原子的，绝不会
        # 两个协程同时通过检查而超额。
        if len(self._inflight) >= self._max_inflight:
            return DeviceResult.failure(
                ErrorCode.BUSY,
                "设备正忙，同时处理的命令太多了，请稍后再试。",
                retryable=True,
            )

        frame_id = uuid.uuid4().hex
        fut = asyncio.get_running_loop().create_future()

        # ⭐【先登记再发帧 —— 顺序是并发核心，这三步不能乱】
        #   建 fut（上一行）→ 存表（下一行）→ 发帧（下面的 send_text）。
        #   存表是同步语句、零窗口：哪怕发帧的 await 一让出控制权 result 就回来，
        #   deliver_result 也必能在表里 pop 到这个 fut（决策 3：窗口为零，不是减小）。
        self._inflight[frame_id] = fut
        try:
            try:
                frame = build_cmd_frame(frame_id, command, params)  # 纯函数，不让出控制权
                await conn.send_text(frame)                          # ← 发帧（真正让出的 await）
            except Exception:
                # ⬅【分界点 A：send 异常 → offline】send_text 这一下就抛 = 命令【确定没
                #    发出去】。与"已发出后才断线"（→ timeout，走 attach/detach 的断线清算，
                #    见 _disconnect_timeout_result）泾渭分明：没发出去=offline，发出去了
                #    但不知设备处理没=timeout。
                return DeviceResult.failure(
                    ErrorCode.OFFLINE,
                    "指令没能发送到设备（连接可能刚断开），没发出去。",
                    retryable=True,
                )
            # 帧已发出，等回执：deliver_result 命中→真 result；断线清算→timeout 信封；
            # _safe 超时→在这一行被 cancel（CancelledError 放行给 wait_for）。
            return await fut
        finally:
            # ⬅【三条路统一清表，且只此一处 pop】成功 return / send 异常 return /
            #    超时 cancel 抛出 —— 都汇到这里。pop(..., None)：断线清算是【整表搬走】
            #    （self._inflight 换成新空表），那时这里 pop 打在新表上得 None、无害，
            #    绝不会二次清或误清——这正是块 2 _fail_all_inflight 用整表替换的用意。
            self._inflight.pop(frame_id, None)

    def deliver_result(self, frame_id: str, result: DeviceResult) -> None:
        """收帧循环（server.py /device，块 4 接线）收到设备回的 result 时调用，把它
        投给正在 _send_and_wait 里 await 这个 frame_id 的调用方（决策 4）。同步方法：
        set_result 只是 schedule 那个协程恢复，无 I/O。

        pop 不到（得 None）= 这条 result 无主：对应命令已超时被 finally 清走、或本就
        没登记过这个 id（设备乱回）—— 自然实现"超时后到达的 result 一律丢弃"。丢弃时
        记一行日志【带上 frame_id】：这正是最需要线索的场景，好一眼区分"回执来晚了"
        （有这条日志）和"设备根本没回"（连这条都没有）。
        """
        fut = self._inflight.pop(frame_id, None)
        if fut is None:
            # 运维日志（进 server stderr、永不发 Claude）→ ASCII，防 GBK 控制台乱码。
            safe_id = frame_id.encode("ascii", "backslashreplace").decode("ascii")
            print(f"[bodybridge] esp32: dropped an unmatched result (id={safe_id!r}); "
                  "its command likely already timed out.", file=sys.stderr)
            return
        # done() 双保险：能 pop 到就说明没被断线清算整表搬走、按理还没 set，但绝不对
        # 已完成的 Future 二次 set_result（会抛）。
        if not fut.done():
            fut.set_result(result)
