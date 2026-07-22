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
from .base import DeviceAdapter, DeviceResult, ErrorCode

# 保留命令名：get_status / list_capabilities 复用 cmd 帧问设备(见下方两个方法)，
# 因此占用了设备命令空间里这两个名字。⚠️ 接入文档须写明"以下为当前保留命令名
# (会随版本增加)"，固件业务指令不得重定义；措辞给未来留口。
CMD_GET_STATUS = "get_status"
CMD_LIST_CAPABILITIES = "list_capabilities"


class ESP32Adapter(DeviceAdapter):
    # 本 adapter 支持设备主动持长连接，端点据此放行 /device（见 server.py）。
    supports_direct_connection = True

    def __init__(self) -> None:
        # 廉价内存构造，永不 I/O(契约)。_connection = 当前设备的 websockets 连接
        # 对象，由 /device 端点(第 4 步)经 attach/detach 塞入/清空；None = 没有设备
        # 连着。单连接"新踢旧"的切换逻辑就在下面 attach/detach 里（决策 2）。
        self._connection = None

    def attach_connection(self, connection) -> object | None:
        # 单连接"新踢旧"：先把指针指向新连接（绝无 None 空窗，也绝不同时指两条），
        # 返回旧连接交给端点关闭。单线程 asyncio 下这行赋值是原子的。
        old = self._connection
        self._connection = connection
        return old

    def detach_connection(self, connection) -> None:
        # compare-and-clear：只有"当前记录的就是这一条"才清空。被顶掉的旧连接稍后
        # 断开走到这里时，_connection 已是新连接、不是它自己 -> 不清，新连接毫发无伤。
        # 这是"旧连接的清理不会误杀刚接上的新连接"的关键（决策 2）。
        if self._connection is connection:
            self._connection = None

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

    # --- 发送 + 等待回执的唯一出口(第 6 步填实) --------------------------
    async def _send_and_wait(self, command: str,
                             params: dict | None) -> DeviceResult:
        """三个方法唯一的对设备出口。永不抛异常(契约)。

        本步只完整实现"没连接"这一路：如实返回 offline。真正的发送 + 在途表 +
        等 result 在第 6 步接线。
        """
        conn = self._connection
        if conn is None:
            # offline = 命令【确定没到】设备，故 retryable=True(五码里唯一为真的一类)。
            return DeviceResult.failure(
                ErrorCode.OFFLINE,
                "设备当前没有连接到桥，指令没发出去。",
                retryable=True,
            )
        # TODO(第 6 步)：生成 id -> 登记在途表(上限 MAX_INFLIGHT，超了回"太多了")
        #   -> ws_protocol.build_cmd_frame(id, command, params) -> conn.send 发出
        #   -> 在 deadline 内等对应 id 的 result(deadline 由 server._safe 施加)。
        return DeviceResult.failure(
            ErrorCode.INTERNAL_ERROR,
            "设备发送链路尚未接线（第 6 步实现），暂不可用。",
            retryable=False,
        )
