"""Mock 设备 Adapter：一个假的虚拟设备，用来在没接真设备时验证插槽机制。

它实现 DeviceAdapter 三个方法、返回假数据，并把"设备会断线/收到乱输入"的
各种防御路径都演示出来。真设备（如 StackChan/WebSocket）照着同一契约实现即可，
桥身不动。
"""
from .base import Capability, DeviceAdapter, DeviceResult, ErrorCode

# 这台虚拟设备声明的能力清单（send_command 能用的 command）
_CAPABILITIES = [
    Capability(name="say", description="让设备说一句话",
               params={"text": "要说的内容（字符串）"}),
    Capability(name="move_head", description="转动设备的头",
               params={"yaw": "水平角度（数字）", "pitch": "俯仰角度（数字）"}),
    Capability(name="set_online", description="[测试用] 模拟设备断线/上线",
               params={"value": "true=在线，false=离线（布尔）"}),
]


class MockAdapter(DeviceAdapter):
    def __init__(self) -> None:
        # 内存里的假状态
        self._online: bool = True
        self._battery: int = 87
        self._last_command: str | None = None

    async def list_capabilities(self) -> DeviceResult:
        # 能力是静态元数据，断线也答得出，故永远 ok=True
        caps = [
            {"name": c.name, "description": c.description, "params": c.params}
            for c in _CAPABILITIES
        ]
        return DeviceResult.success(
            f"设备支持 {len(caps)} 条指令。",
            data={"capabilities": caps},
        )

    async def get_status(self) -> DeviceResult:
        if not self._online:
            return DeviceResult.failure(
                ErrorCode.OFFLINE,
                "设备当前无响应（可能断线），已停在原地。",
                retryable=True,
            )
        return DeviceResult.success(
            "设备在线。",
            data={
                "online": self._online,
                "battery": self._battery,
                "last_command": self._last_command,
            },
        )

    async def send_command(self, command: str,
                           params: dict | None = None) -> DeviceResult:
        params = params or {}

        # 测试钩子：故意抛异常，验证 server 的安全网能兜成友好信封而非 500。
        # 不是真能力，不出现在 list_capabilities 里。
        if command == "_raise":
            raise RuntimeError("simulated adapter crash (test hook)")

        # 离线：可预期的断线兜底
        if not self._online and command != "set_online":
            return DeviceResult.failure(
                ErrorCode.OFFLINE,
                "设备当前无响应（可能断线），指令没发出去。",
                retryable=True,
            )

        known = {c.name for c in _CAPABILITIES}
        if command not in known:
            return DeviceResult.failure(
                ErrorCode.UNKNOWN_COMMAND,
                f"设备不认识指令 '{command}'。已知指令：{sorted(known)}。",
                retryable=False,
            )

        # 各指令的参数防御 + 执行（都是假动作，只更新内存状态）
        if command == "say":
            text = params.get("text")
            if not isinstance(text, str) or text == "":
                return DeviceResult.failure(
                    ErrorCode.BAD_PARAMS,
                    "say 需要一个非空字符串参数 text。",
                    retryable=False,
                )
            self._last_command = "say"
            return DeviceResult.success(f"设备说了：{text}")

        if command == "move_head":
            yaw, pitch = params.get("yaw"), params.get("pitch")
            if not _is_number(yaw) or not _is_number(pitch):
                return DeviceResult.failure(
                    ErrorCode.BAD_PARAMS,
                    "move_head 需要数字参数 yaw 和 pitch。",
                    retryable=False,
                )
            self._last_command = "move_head"
            return DeviceResult.success(f"设备转头到 yaw={yaw}, pitch={pitch}。")

        if command == "set_online":
            value = params.get("value")
            if not isinstance(value, bool):
                return DeviceResult.failure(
                    ErrorCode.BAD_PARAMS,
                    "set_online 需要布尔参数 value（true/false）。",
                    retryable=False,
                )
            self._online = value
            self._last_command = "set_online"
            state = "在线" if value else "离线"
            return DeviceResult.success(f"设备已切到{state}。")

        # 理论到不了这里（known 已兜住），保底再兜一层
        return DeviceResult.failure(
            ErrorCode.UNKNOWN_COMMAND,
            f"设备不认识指令 '{command}'。",
            retryable=False,
        )


def _is_number(v) -> bool:
    """防御性判断：bool 是 int 的子类，要排除掉；字符串数字不算。"""
    return isinstance(v, (int, float)) and not isinstance(v, bool)
