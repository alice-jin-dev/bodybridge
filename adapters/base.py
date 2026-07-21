"""设备 Adapter 抽象接口（契约）。

任何设备想插进 bodybridge，只需实现 DeviceAdapter 的三个方法，
并统一用 DeviceResult 信封返回。桥身只认这份契约，不认具体设备。

铁律：Adapter 的方法永不向外抛异常——做不到的事，用 DeviceResult(ok=False)
如实告知（"小狗歪头"哲学）。设备断线/乱输入，最坏也只能是一个友好的失败信封。
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field


class ErrorCode:
    """设备失败的稳定机器码。

    选码口诀（拿不准时按这个走）：
      命令确定没到设备        -> OFFLINE
      到没到不知道（超时）    -> TIMEOUT
      指令本身不认识          -> UNKNOWN_COMMAND
      参数不对                -> BAD_PARAMS
      其余意外                -> 不要自己返回，让异常抛出，由 _safe 兜成 INTERNAL_ERROR
    """
    OFFLINE = "offline"
    TIMEOUT = "timeout"
    INTERNAL_ERROR = "internal_error"
    UNKNOWN_COMMAND = "unknown_command"
    BAD_PARAMS = "bad_params"


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

    retryable 只回答一个问题：这条命令是否【确定没有到达设备】。
      确定没到               -> True（目前只有 OFFLINE 属于这类）
      到没到不知道（如超时） -> False
      到了但执行失败         -> False
    依据：对齐 gRPC 官方重试提案的通用原则——只有那些表明"服务端未处理该请求"
    的状态才应被重试；INTERNAL 类错误不应重试。Adapter 作者按这条填，不要凭
    "再试一次会不会好"的直觉填。
    """

    ok: bool                       # 成功/失败，Claude 一眼分支
    message: str                  # 永远有，人话，可直接展示给用户
    data: dict | None = None       # 成功载荷（状态快照 / 能力清单）
    error: str | None = None       # 失败机器码，取值见 ErrorCode（类型保持 str，不强制第三方 import）
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
        retryable 的含义见 DeviceResult 的字段说明；错误码选哪个见 ErrorCode 的选码口诀。
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

    # --- 生命周期钩子（可选）------------------------------------------------
    # 下面两个不是 @abstractmethod：带默认空实现，不需要初始化的简单 Adapter
    # 可以完全不管它们，白继承 no-op。需要长连接的设备（如 WebSocket）才覆盖。
    # __init__ 只做廉价的内存构造（永不 I/O）；真正的连接/登录留到 setup。

    async def setup(self) -> DeviceResult:
        """桥启动时调用一次，用来建立连接、登录设备、准备资源。

        跑在桥的事件循环里（见 server.py 的 lifespan 包裹）。
        返回 DeviceResult；和三方法一样永不抛异常——连不上就 ok=False 如实告知，
        桥据此打印醒目日志但仍照常启动（桥身求薄，不被设备死活绑架）。
        默认：无需初始化，直接成功。
        """
        # 注意：这条 message 只会进 server 的 stderr 运维日志、永不发给 Claude，
        # 属"经控制台"类，故用 ASCII 英文（面向全球开发者，任何控制台不乱码）。
        return DeviceResult.success("no setup needed.")

    async def teardown(self) -> None:
        """桥关闭时调用一次，用来断开连接、释放资源、清理。

        无返回、永不抛异常：清理阶段没有"返回给谁"，抛异常又是关闭期经典 bug，
        故从签名上就摁死——只管尽力清理。默认：什么都不做。
        """
        return None
