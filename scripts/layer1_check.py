"""Regression checks for the device Adapter send-loop (layer 1, in-memory).

Complements scripts/contract_check.py (DeviceResult / _safe contract) and
scripts/oauth_flow_check.py (OAuth chain). This one drives WebSocketAdapter's
concurrency invariants through a FakeConnection stand-in -- register -> send_text
-> await fut -> deliver_result wakes it -> in-flight table cleared -- covering
offline / busy / timeout / disconnect-drain / orphan-result.

Run it any time after touching adapters/websocket.py's send loop or in-flight
table:

    python scripts/layer1_check.py

Pure in-memory: no uvicorn, no port bound, no network/auth. FakeConnection is our
own stand-in, so it does NOT exercise the real starlette WebSocket send path
(that's layer 2) nor real ESP32 hardware -- green here != a real device works.
Exit code is 0 if every check passes, 1 otherwise.
"""
import asyncio
import json
import os
import sys

# stdout 转 utf-8 + backslashreplace：任何字符都不会让 print 崩（GBK 控制台防护）。
sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")

# 让脚本能 import 到项目模块（脚本在 scripts/，项目根是它的上一级）。
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from adapters.websocket import WebSocketAdapter    # noqa: E402
from adapters.base import DeviceResult, ErrorCode  # noqa: E402


class FakeConnection:
    """假的 starlette WebSocket 替身：只实现 _send_and_wait 用到的 send_text 和
    attach/teardown 用到的 close。可配置三种行为：
      auto_reply=True   收到 cmd 帧后，稍后回一个成功 result（模拟设备正常回执）
      auto_reply=False  收到但静默不回（模拟占住在途 / 等断线清算 / 等超时）
      raise_on_send     send_text 直接抛（模拟"发帧那一下连接刚断"）
    """

    def __init__(self, adapter, *, auto_reply=True, raise_on_send=False):
        self._adapter = adapter
        self._auto_reply = auto_reply
        self._raise_on_send = raise_on_send
        self.sent = []       # 记录发出的帧文本，供断言
        self.closed = False

    async def send_text(self, text):
        if self._raise_on_send:
            raise RuntimeError("simulated send failure (connection just dropped)")
        self.sent.append(text)
        if self._auto_reply:
            frame = json.loads(text)
            frame_id = frame["id"]
            command = frame.get("command")
            result = DeviceResult.success(
                f"fake device handled '{command}'.",
                data={"echo": command, "battery": 87},
            )
            # call_soon：保证 _send_and_wait 已从 send_text 返回、走到 await fut
            # 挂起之后才投递 —— 真正跑一遍"挂起 -> 叫醒"，而不是未挂起就已 done。
            asyncio.get_running_loop().call_soon(
                self._adapter.deliver_result, frame_id, result
            )

    async def close(self, code=1000, reason=None):
        self.closed = True


PASS = 0
FAIL = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    tag = "[PASS]" if ok else "[FAIL]"
    if ok:
        PASS += 1
    else:
        FAIL += 1
    print(f"{tag} {name}" + (f"  --  {detail}" if detail else ""))


async def scenario_get_status_woken():
    adapter = WebSocketAdapter(max_inflight=8)
    adapter.attach_connection(FakeConnection(adapter, auto_reply=True))
    res = await asyncio.wait_for(adapter.get_status(), timeout=2)
    check("核心1: get_status 被回执叫醒 -> ok",
          res.ok and res.error is None,
          f"ok={res.ok} error={res.error}")
    check("核心1: 回路结束后在途表清空", len(adapter._inflight) == 0,
          f"inflight={len(adapter._inflight)}")


async def scenario_send_command_woken():
    adapter = WebSocketAdapter(max_inflight=8)
    fake = FakeConnection(adapter, auto_reply=True)
    adapter.attach_connection(fake)
    res = await asyncio.wait_for(
        adapter.send_command("say", {"text": "hi"}), timeout=2)
    check("核心2: send_command 被回执叫醒 -> ok", res.ok,
          f"ok={res.ok} error={res.error}")
    sent = json.loads(fake.sent[0]) if fake.sent else {}
    check("核心2: 发出的确是正确 cmd 帧",
          sent.get("type") == "cmd" and sent.get("command") == "say"
          and isinstance(sent.get("id"), str) and bool(sent.get("id")),
          f"sent={sent}")


async def scenario_offline_no_conn():
    adapter = WebSocketAdapter(max_inflight=8)
    res = await asyncio.wait_for(adapter.get_status(), timeout=2)  # 未 attach
    check("分支: 没连接 -> offline (retryable=True)",
          res.error == ErrorCode.OFFLINE and res.retryable is True,
          f"error={res.error} retryable={res.retryable}")


async def scenario_busy_when_full():
    adapter = WebSocketAdapter(max_inflight=1)
    fake = FakeConnection(adapter, auto_reply=False)  # 不回，占住 slot
    adapter.attach_connection(fake)
    task = asyncio.create_task(adapter.get_status())
    await asyncio.sleep(0)  # 让它跑到 await fut，占上唯一的 slot
    check("分支: 满表前置 in-flight=1", len(adapter._inflight) == 1,
          f"inflight={len(adapter._inflight)}")
    res = await asyncio.wait_for(
        adapter.send_command("say", {"text": "x"}), timeout=2)
    check("分支: 在途满 -> busy (retryable=True)",
          res.error == ErrorCode.BUSY and res.retryable is True,
          f"error={res.error} retryable={res.retryable}")
    adapter.detach_connection(fake)          # 清理：断线叫醒挂着的 task
    await asyncio.wait_for(task, timeout=2)


async def scenario_send_raises_offline():
    adapter = WebSocketAdapter(max_inflight=8)
    adapter.attach_connection(FakeConnection(adapter, raise_on_send=True))
    res = await asyncio.wait_for(adapter.get_status(), timeout=2)
    check("分支: send_text 抛 -> offline (确定没发出去)",
          res.error == ErrorCode.OFFLINE and res.retryable is True,
          f"error={res.error} retryable={res.retryable}")
    check("分支: send 异常后在途表清空 (finally pop)",
          len(adapter._inflight) == 0, f"inflight={len(adapter._inflight)}")


async def scenario_disconnect_timeout():
    adapter = WebSocketAdapter(max_inflight=8)
    fake = FakeConnection(adapter, auto_reply=False)  # 不回
    adapter.attach_connection(fake)
    task = asyncio.create_task(adapter.get_status())
    await asyncio.sleep(0)  # 跑到 await fut
    check("分支: 断线前置 in-flight=1", len(adapter._inflight) == 1,
          f"inflight={len(adapter._inflight)}")
    adapter.detach_connection(fake)          # 断线清算
    res = await asyncio.wait_for(task, timeout=2)
    check("分支: 断线清算 -> timeout 叫醒 (不撒谎成 offline)",
          res.error == ErrorCode.TIMEOUT and res.retryable is False,
          f"error={res.error} retryable={res.retryable}")
    check("分支: 断线后在途表清空", len(adapter._inflight) == 0,
          f"inflight={len(adapter._inflight)}")


async def scenario_orphan_result_dropped():
    adapter = WebSocketAdapter(max_inflight=8)
    # 没有任何在途，投一个无主 result：应 pop 得 None、打一条日志、绝不崩。
    try:
        adapter.deliver_result("nonexistent-id", DeviceResult.success("late"))
        check("分支: 无主/迟到 result 丢弃不崩", True)
    except Exception as e:
        check("分支: 无主/迟到 result 丢弃不崩", False,
              f"raised {type(e).__name__}: {e}")


async def main():
    scenarios = [
        scenario_get_status_woken,
        scenario_send_command_woken,
        scenario_offline_no_conn,
        scenario_busy_when_full,
        scenario_send_raises_offline,
        scenario_disconnect_timeout,
        scenario_orphan_result_dropped,
    ]
    for scen in scenarios:
        try:
            await scen()
        except asyncio.TimeoutError:
            check(f"{scen.__name__} (未在 2s 内完成 -> future 没被叫醒)", False)
        except Exception as e:
            check(f"{scen.__name__} (异常 {type(e).__name__}: {e})", False)
    print(f"\n==== layer 1 result: {PASS} passed, {FAIL} failed ====")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
