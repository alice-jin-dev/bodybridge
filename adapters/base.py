"""设备 Adapter 抽象接口（契约）。

任何设备想插进 bodybridge，只需实现 DeviceAdapter 的三个方法，
并统一用 DeviceResult 信封返回。桥身只认这份契约，不认具体设备。

铁律：Adapter 的方法永不向外抛异常——做不到的事，用 DeviceResult(ok=False)
如实告知（"小狗歪头"哲学）。设备断线/乱输入，最坏也只能是一个友好的失败信封。
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class Capability:
    """一条设备能力：send_command 能用的一个 command。"""

    name: str                                    # 指令名，如 "say"
    description: str                             # 人话说明这条指令做什么
    params: dict[str, str] = field(default_factory=dict)  # 参数名 -> 简短说明


@dataclass
class DeviceResult:
    """三个方法统一返回的信封。Claude 那侧和设备那侧都只需认这一种形状。

    设备级失败一律当"数据"返回（ok=False 的正常信封），绝不当 MCP 协议错误抛，
    这样从根上绕开 isError / outputSchema 撞车（严格客户端 -32602）的坑。
    """

    ok: bool                       # 成功/失败，Claude 一眼分支
    message: str                  # 永远有，人话，可直接展示给用户
    data: dict | None = None       # 成功载荷（状态快照 / 能力清单）
    error: str | None = None       # 失败机器码：offline / internal_error / unknown_command / bad_params
    retryable: bool = False        # 失败是否值得重试；成功时无意义，默认 False

    def to_dict(self) -> dict:
        """转成干净 JSON 给 MCP 上线。成功失败都吐齐这 5 个键，形状一致。"""
        return {
            "ok": self.ok,
            "message": self.message,
            "data": self.data,
            "error": self.error,
            "retryable": self.retryable,
        }

    @classmethod
    def success(cls, message: str, data: dict | None = None) -> "DeviceResult":
        return cls(ok=True, message=message, data=data, error=None, retryable=False)

    @classmethod
    def failure(cls, error: str, message: str, *, retryable: bool,
                data: dict | None = None) -> "DeviceResult":
        """retryable 必填关键字：逼调用方每次失败都想清楚该不该重试。
        retryable=True  -> "别急，再试一次可能就好了"（如 offline）
        retryable=False -> "别重试，问题在这次请求本身，得改"（如 bad_params）
        """
        return cls(ok=False, message=message, data=data, error=error, retryable=retryable)


class DeviceAdapter(ABC):
    """设备 Adapter 契约。照着实现这三个方法，你的设备就能插进 bodybridge。"""

    @abstractmethod
    async def send_command(self, command: str,
                           params: dict | None = None) -> DeviceResult:
        """发一个明确指令给设备。

        command: 能力名（见 list_capabilities）。
        params:  该指令的参数，可为 None。
        返回:    DeviceResult；永不抛异常。
        """

    @abstractmethod
    async def get_status(self) -> DeviceResult:
        """查询设备当前状态快照。返回 DeviceResult；永不抛异常。"""

    @abstractmethod
    async def list_capabilities(self) -> DeviceResult:
        """返回设备支持哪些指令（send_command 能用哪些 command）。

        能力是"设备能做什么"的静态元数据，设备断线也答得出，故通常 ok=True。
        """
