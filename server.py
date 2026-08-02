"""bodybridge — MCP Server 层 + 鉴权守门层（最小可跑版本）"""
import asyncio
import contextlib
import html
import os
import sys
from urllib.parse import quote as urlquote, urlsplit, urlunsplit

import uvicorn
from mcp.server.fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse
from starlette.routing import WebSocketRoute
from starlette.websockets import WebSocket
from dotenv import load_dotenv

import oauth_cimd
from adapters.base import DeviceAdapter, DeviceResult, ErrorCode
from adapters.websocket import WebSocketAdapter
from adapters.ws_protocol import parse_result_frame

# 本地开发便利：把同目录 .env 载入进程环境，让下面所有 os.environ.get 读得到。
# ⚠️ 必须早于任何一次 os.environ.get（第一处就在下面读 HOST），否则白加。
# 不传 override=True：默认「已存在的环境变量不被 .env 覆盖」，正是我们要的——
# 平台注入的变量（Zeabur Variables 等）优先，.env 只在本地兜底，线上以平台为准。
load_dotenv()

# 铁律 5/6：host 默认监听所有网卡——桥的定位就是被公网访问，且鉴权已强制
# （缺 TOKEN/PASSWORD 直接拒启），默认只听本机反而跟定位相反。用户显式设
# BODYBRIDGE_HOST 依然生效，覆盖这个默认值；这里不做"侦测到 PORT 就自动切
# 0.0.0.0"这类隐式适配——隐式回退路径易误解，跟 PUBLIC_URL 当初否掉同类
# 方案 c（自动侦测+回退）是同一个理由。
HOST = os.environ.get("BODYBRIDGE_HOST", "0.0.0.0")


def _resolve_port() -> tuple[int, str, str | None]:
    """监听端口优先级：PORT（Heroku/Railway/Render/Zeabur 等云平台注入的
    通行约定，Zeabur 官方文档："Zeabur uses environment variable PORT to
    determine which port to forward"）> BODYBRIDGE_PORT（本项目自己的变量）
    > 8000（默认）。

    坏值（非数字、超出 1-65535 合法端口范围）不会让服务拒启——跳过它，
    试下一优先级，最终兜底 8000（铁律 3）。返回 (端口, 生效来源, 警告文案
    或 None)；来源和警告都交给 __main__ 打印，让人一眼看出端口从哪来、
    沿途有没有哪个变量的坏值被跳过了（铁律 4）。
    """
    warnings: list[str] = []
    for name in ("PORT", "BODYBRIDGE_PORT"):
        raw = os.environ.get(name, "").strip()
        if not raw:
            continue
        try:
            port = int(raw)
            if not (1 <= port <= 65535):
                raise ValueError("out of range")
        except ValueError:
            safe = raw.encode("ascii", "replace").decode("ascii")
            warnings.append(
                f"[bodybridge] warning: {name}='{safe}' is not a valid port "
                "(must be an integer 1-65535); ignoring it."
            )
            continue
        return port, name, ("\n".join(warnings) if warnings else None)
    if warnings:
        warnings.append("[bodybridge] falling back to the default port 8000.")
    return 8000, "default", ("\n".join(warnings) if warnings else None)


PORT, _PORT_SOURCE, _PORT_WARNING = _resolve_port()

# 铁律 5：token 是鉴权必填项，没有安全默认值，走"明确必填提示"这条腿
TOKEN = os.environ.get("BODYBRIDGE_TOKEN", "").strip()

# 铁律 5：/oauth/authorize 的密码门禁，同样没有安全默认值，缺了直接拒启（与
# TOKEN 同一先例：接完中间件后，没密码这条 OAuth 路径就是废的，fail fast
# 比"桥能起但神秘地授权不了"诚实）。
PASSWORD = os.environ.get("BODYBRIDGE_PASSWORD", "").strip()

# 设备握手鉴权用的预置 token（第 3 层 /device 端点）。⚠️ 与 BODYBRIDGE_TOKEN 是
# 两回事：后者现在是 JWT 签名密钥（服务端秘密，绝不能给设备），这个才是设备出示
# 的凭证。缺失【不】在这里 fail-fast——当前 MockAdapter 没有 /device 端点、根本不
# 需要它；"缺 token 就拒绝设备连接"的强制放到端点里。
DEVICE_TOKEN = os.environ.get("BODYBRIDGE_DEVICE_TOKEN", "").strip()

# 可选：CIMD 抓取的 host 白名单。仅在 BODYBRIDGE_CLIENT_REGISTRATION=cimd 时
# 生效——默认空 = 通用防护（不限 host，但下面一系列 SSRF 防护照做）；设了就
# 只放行这些 host，给想锁死的用户自由。
_raw_cimd_allowlist = os.environ.get("BODYBRIDGE_CIMD_ALLOWLIST", "").strip()
CIMD_ALLOWLIST = (
    frozenset(h.strip() for h in _raw_cimd_allowlist.split(",") if h.strip())
    if _raw_cimd_allowlist else None
)


def _resolve_client_registration_mode() -> tuple[str, str | None]:
    """客户端注册模式：dcr（默认）或 cimd。

    默认 dcr：Claude 主动入站 POST 到我们，不需要我们主动出站访问 claude.ai，
    从根上避开 CIMD 那次 Cloudflare JS 挑战（403，详见 MIGRATION.md）。cimd
    仍完整保留、随时可切回（比如那个挑战以后被解除）。

    没设是正常路径，静默默认 dcr（铁律 5）；设了但既不是 dcr 也不是 cimd，
    才算用户操作出错，警告 + 回退 dcr（铁律 3：坏值不崩）。
    """
    raw = os.environ.get("BODYBRIDGE_CLIENT_REGISTRATION", "").strip().lower()
    if not raw:
        return "dcr", None
    if raw in ("dcr", "cimd"):
        return raw, None
    safe = raw.encode("ascii", "replace").decode("ascii")
    return "dcr", (
        f"[bodybridge] warning: BODYBRIDGE_CLIENT_REGISTRATION='{safe}' is not "
        "'dcr' or 'cimd'; falling back to 'dcr'."
    )


CLIENT_REGISTRATION, _CLIENT_REGISTRATION_WARNING = _resolve_client_registration_mode()


def _resolve_token_ttl_days() -> tuple[float, str | None]:
    """access token 有效期，天数。这是控制/配置层的自由项——不是必填项：
    没设是正常路径，静默用默认值 7 天，不警告（铁律 5：合理默认值）；
    设了但是坏值（非数字/负数/零）才算用户明确操作出错，警告 + 回退
    （铁律 3：坏值绝不崩服务）。"""
    raw = os.environ.get("BODYBRIDGE_TOKEN_TTL_DAYS", "").strip()
    if not raw:
        return 7.0, None
    try:
        ttl = float(raw)
        if ttl <= 0:
            raise ValueError("must be positive")
    except ValueError:
        safe = raw.encode("ascii", "replace").decode("ascii")
        return 7.0, (
            f"[bodybridge] warning: BODYBRIDGE_TOKEN_TTL_DAYS='{safe}' is invalid "
            "(must be a positive number); falling back to 7 days."
        )
    return ttl, None


TOKEN_TTL_DAYS, _TOKEN_TTL_WARNING = _resolve_token_ttl_days()


def _resolve_command_timeout_seconds() -> tuple[float, str | None]:
    """桥侧 deadline：一条设备指令最多等多少秒，超了就返回 TIMEOUT 信封、不再干等。
    合理默认值 25 秒（铁律 5）：没设是正常路径，静默用默认、不警告；设了但坏值
    （非数字/<=0）才算用户明确操作出错，警告 + 回退 25（铁律 3：坏值绝不崩服务）。"""
    raw = os.environ.get("BODYBRIDGE_COMMAND_TIMEOUT_SECONDS", "").strip()
    if not raw:
        return 25.0, None
    try:
        timeout = float(raw)
        if timeout <= 0:
            raise ValueError("must be positive")
    except ValueError:
        safe = raw.encode("ascii", "replace").decode("ascii")
        return 25.0, (
            f"[bodybridge] warning: BODYBRIDGE_COMMAND_TIMEOUT_SECONDS='{safe}' is "
            "invalid (must be a positive number); falling back to 25 seconds."
        )
    return timeout, None


COMMAND_TIMEOUT_SECONDS, _COMMAND_TIMEOUT_WARNING = _resolve_command_timeout_seconds()


def _resolve_heartbeat_seconds() -> tuple[float, str | None]:
    """心跳间隔：映射到 websockets 库的 ping_interval——库每隔这么多秒自动发一个
    协议级 ping。pong 超时（用库默认 ping_timeout，不单开旋钮）则库关连，桥在关连
    回调里立刻标 offline。合理默认 25 秒（铁律 5）：没设静默用默认、
    不警告；设了但坏值（非数字/<=0）才算用户明确操作出错，警告 + 回退 25（铁律 3：
    坏值绝不崩服务）。⚠️ 与 COMMAND_TIMEOUT_SECONDS 默认值都是 25 只是巧合，两个
    独立旋钮：这个是链路保活间隔，那个是单条命令的 deadline。"""
    raw = os.environ.get("BODYBRIDGE_HEARTBEAT_SECONDS", "").strip()
    if not raw:
        return 25.0, None
    try:
        hb = float(raw)
        if hb <= 0:
            raise ValueError("must be positive")
    except ValueError:
        safe = raw.encode("ascii", "replace").decode("ascii")
        return 25.0, (
            f"[bodybridge] warning: BODYBRIDGE_HEARTBEAT_SECONDS='{safe}' is invalid "
            "(must be a positive number); falling back to 25 seconds."
        )
    return hb, None


HEARTBEAT_SECONDS, _HEARTBEAT_WARNING = _resolve_heartbeat_seconds()


def _resolve_max_payload_bytes() -> tuple[int, str | None]:
    """设备帧载荷上限：映射到 websockets 库的 max_size（超限库以 close code 1009 关
    连，是防内存打爆的硬护盾）。默认 64 KB（命令通常几百字节）；必须可配置——桥面向
    所有可联网硬件，树莓派能吃 1 MB、ESP32 可能几 KB 就爆，不能按某一种定死。
    ⚠️ 设得【过小】（小于典型 result 回执帧大小）会导致正常回执被库以 1009 关连接、
    设备刚连上就被踢；桥不强制下限（保持"不替用户兜合理性"），但建议不低于约 4 KB，
    给 result 的 message + data 留够余量。合理默认（铁律 5）：没设静默用默认；坏值
    （非整数/<=0）警告 + 回退（铁律 3）。"""
    raw = os.environ.get("BODYBRIDGE_MAX_PAYLOAD_BYTES", "").strip()
    if not raw:
        return 65536, None
    try:
        n = int(raw)
        if n <= 0:
            raise ValueError("must be positive")
    except ValueError:
        safe = raw.encode("ascii", "replace").decode("ascii")
        return 65536, (
            f"[bodybridge] warning: BODYBRIDGE_MAX_PAYLOAD_BYTES='{safe}' is invalid "
            "(must be a positive integer); falling back to 65536 (64 KB)."
        )
    return n, None


MAX_PAYLOAD_BYTES, _MAX_PAYLOAD_WARNING = _resolve_max_payload_bytes()


def _resolve_max_inflight() -> tuple[int, str | None]:
    """在途命令表上限：同一时刻最多允许多少条命令在等设备回 result，超了拒绝（话术
    是"太多了"不是"做不到"）。正常同时在途只 1–2 条，默认 8 是个"小到能
    一眼发现异常"的数字。合理默认（铁律 5）：没设静默用默认；坏值（非整数/<=0）警告
    + 回退（铁律 3）。"""
    raw = os.environ.get("BODYBRIDGE_MAX_INFLIGHT", "").strip()
    if not raw:
        return 8, None
    try:
        n = int(raw)
        if n <= 0:
            raise ValueError("must be positive")
    except ValueError:
        safe = raw.encode("ascii", "replace").decode("ascii")
        return 8, (
            f"[bodybridge] warning: BODYBRIDGE_MAX_INFLIGHT='{safe}' is invalid "
            "(must be a positive integer); falling back to 8."
        )
    return n, None


MAX_INFLIGHT, _MAX_INFLIGHT_WARNING = _resolve_max_inflight()

# 库的 max_queue：已收到但应用还没取走的帧最多缓存几个。库默认 32；桥这侧命令往返
# 很稀疏（正常同时在途 1–2 条），调低到 16 足够，也顺带压低内存上界（websockets 内
# 存约 4 × max_size × max_queue）。做成固定常量而非环境变量：它太冷门，不值得多开一
# 个没人会调的旋钮（未知需求留白）。
DEVICE_MAX_QUEUE = 16


def _resolve_public_url() -> tuple[str, str | None]:
    """解析桥的公网基址，供 OAuth 元数据（RFC 9728/8414）用。
    返回 (基址_去尾斜杠, 警告文案_或_None)。

    铁律 3/5：显式配置优先；缺失或坏值绝不崩服务——回退到本地地址并把一句
    ASCII 警告交回给 __main__ 打印（本地控制台可能是 GBK，输出必须纯 ASCII）。
    """
    raw = os.environ.get("BODYBRIDGE_PUBLIC_URL", "").strip()
    # 0.0.0.0 是"监听所有网卡"的意思，不是可访问地址——本地回退时换成
    # 127.0.0.1，不然拼出来的 resource/issuer 连本地调试都访问不了。
    # HOST 显式设成别的值（包括别的非本地地址）时照原样拼，不做特殊处理。
    local_host = "127.0.0.1" if HOST == "0.0.0.0" else HOST
    local = f"http://{local_host}:{PORT}"
    if not raw:
        return local, (
            "[bodybridge] warning: BODYBRIDGE_PUBLIC_URL is not set; "
            f"falling back to {local} for OAuth metadata.\n"
            "  MCP clients (claude.ai among them) read that metadata to "
            "discover and validate this bridge, so any public deployment "
            "needs a real PUBLIC https base URL.\n"
            "  Running server.py refuses to start without it; this fallback "
            "only applies when the module is imported, e.g. by the check "
            "scripts under scripts/.\n"
            "  Set it: BODYBRIDGE_PUBLIC_URL=https://bridge.example.com"
        )
    normalized = raw.rstrip("/")
    if not (normalized.startswith("http://") or normalized.startswith("https://")):
        # 坏值也要说人话、暴露原因（铁律 4），但先 ASCII 化防 GBK 乱码
        safe = raw.encode("ascii", "replace").decode("ascii")
        return local, (
            f"[bodybridge] warning: BODYBRIDGE_PUBLIC_URL='{safe}' is malformed "
            "(must start with http:// or https://); "
            f"falling back to {local} for OAuth metadata.\n"
            "  Fix it: BODYBRIDGE_PUBLIC_URL=https://bridge.example.com"
        )
    if normalized != raw:
        return normalized, (
            "[bodybridge] note: trailing slash stripped from "
            f"BODYBRIDGE_PUBLIC_URL (using {normalized})."
        )
    return normalized, None


# 铁律 3/5：坏值/缺失回退本地 + 警告；/mcp 由代码拼，PUBLIC_URL 不含 /mcp、不含尾斜杠
PUBLIC_URL, _PUBLIC_URL_WARNING = _resolve_public_url()

# 用户到底有没有显式设过。回退值只对本地开发有意义——公网部署拿它当 issuer/aud
# 必然全错，且症状极其间接（桥活着、健康检查过，但 claude.ai 连不上或 token 验不
# 过），所以 __main__ 里据此拒启，与 TOKEN/PASSWORD 同一条腿。只管"没设"这一种；
# 设了但格式坏（不以 http:// 或 https:// 开头）仍走 _resolve_public_url 的回退+警告，
# 那条腿形状不变。
_PUBLIC_URL_IS_SET = bool(os.environ.get("BODYBRIDGE_PUBLIC_URL", "").strip())

mcp = FastMCP(
    "bodybridge",
    host=HOST,
    port=PORT,
    stateless_http=True,  # 无状态优先：每个请求自成一体，不依赖服务端会话
)


@mcp.tool()
def ping() -> str:
    """健康检查：确认 bodybridge 桥活着。"""
    return "pong"


# --- 设备 Adapter 插槽层（第 3 层）------------------------------------------
# 桥身只依赖抽象 DeviceAdapter，不认具体设备。换设备只改下面这一行实例化，
# 三个工具、_safe、整个桥身都不动 —— 这就是依赖倒置 + 桥身求薄。
# max_inflight 显式传 MAX_INFLIGHT（BODYBRIDGE_MAX_INFLIGHT 的解析结果，见上）：
# 不传的话 adapter 用自带默认 8、那个环境变量就白解析了。adapter 不 import
# server（避免循环依赖），所以配置只能走构造参数注入。
device: DeviceAdapter = WebSocketAdapter(max_inflight=MAX_INFLIGHT)


async def _safe(coro) -> dict:
    """安全网 + 桥侧 deadline：Adapter 万一漏抛异常或卡住不返回，都兜成友好信封，
    保证服务永不 500、永不无限期挂起。设备级失败走的是 ok=False 的正常返回
    （不是 isError），从根上避开 MCP 的 isError/outputSchema 撞车坑。"""
    try:
        result = await asyncio.wait_for(coro, timeout=COMMAND_TIMEOUT_SECONDS)
        return result.to_dict()
    except asyncio.TimeoutError:
        # ⚠️ 这个 except 必须排在 except Exception 之前：asyncio.TimeoutError 也是
        # Exception 的子类，顺序反了超时会被吃成 internal_error，TIMEOUT 码永不出现。
        # message 必须体现"不确定"——超时代表"到没到设备不知道"，写成"执行失败"是撒谎。
        return DeviceResult.failure(
            ErrorCode.TIMEOUT,
            f"The device did not reply within {COMMAND_TIMEOUT_SECONDS:g} "
            "seconds. The command may or may not have run. Check the device "
            "status before sending it again.",
            retryable=False,
        ).to_dict()
    except Exception as e:
        return DeviceResult.failure(
            ErrorCode.INTERNAL_ERROR,
            f"The device adapter raised an unexpected {type(e).__name__}, "
            "which the bridge caught. It is not known whether the command "
            "reached the device, so check the device status. Report this if "
            "it keeps happening.",
            retryable=False,
        ).to_dict()


@mcp.tool()
async def device_list_capabilities() -> dict:
    """列出设备支持的指令清单（send_command 能用哪些 command）。"""
    return await _safe(device.list_capabilities())


@mcp.tool()
async def device_get_status() -> dict:
    """查询设备当前状态。"""
    return await _safe(device.get_status())


@mcp.tool()
async def device_send_command(command: str, params: dict | None = None) -> dict:
    """向设备发送一个指令；command 见 device_list_capabilities。"""
    return await _safe(device.send_command(command, params))


# --- 生命周期接线 -----------------------------------------------------------
# setup/teardown 必须跑在服务器的事件循环里（长连接的 socket 换个 loop 就废），
# 所以挂在 ASGI app 的 lifespan 上（见 __main__ 的包裹）。桥这侧只负责：兜底
# 兜异常 + 打印说人话的日志；Adapter 那侧只负责返回信封。


async def _boot_device() -> None:
    """桥启动：调 setup。失败绝不 sys.exit——桥照常起、设备走 offline 兜底信封，
    存活不被单台设备绑架（桥身求薄 + 小狗歪头）。但日志要把真实原因暴露够清楚
    （铁律 4：说人话、暴露原因），让人一眼看出是设备离线还是配置写错。"""
    try:
        result = await device.setup()
    except Exception as e:
        # Adapter 违约漏抛（不该发生），也兜住，桥照样活
        print(
            f"[bodybridge] device setup raised, caught; bridge keeps starting "
            f"({type(e).__name__}: {e}). Device will fall back to offline -- "
            f"please investigate the exception above.",
            file=sys.stderr,
        )
        return
    if result.ok:
        print(f"[bodybridge] device setup ok: {result.message}", file=sys.stderr)
    else:
        # 醒目 + 暴露原因：error 机器码 + 人话 message 全给出来
        print(
            f"[bodybridge] device setup FAILED (error={result.error}): {result.message}\n"
            f"  Bridge still starts; device is currently unavailable -- later calls "
            f"will get an offline fallback envelope.\n"
            f"  If this looks like a bad address/credential, fix the device config "
            f"and restart the bridge.",
            file=sys.stderr,
        )


async def _shutdown_device() -> None:
    """桥关闭：调 teardown。契约保证它不抛，这里再兜一层，确保关闭流程不被搅乱。"""
    try:
        await device.teardown()
    except Exception as e:
        print(
            f"[bodybridge] device teardown raised, ignored ({type(e).__name__}: {e}).",
            file=sys.stderr,
        )


def _device_bearer_ok(auth_header) -> bool:
    """校验 /device 握手的 Authorization: Bearer <token> 是否等于 DEVICE_TOKEN。

    防御性处理各种坏输入（None/空/格式畸形/全角/二进制乱码）——一律返回 False，
    绝不抛（铁律 3）。用常量时间比较（safe_compare），token 是秘密。
    调用方保证只在 DEVICE_TOKEN 非空时才走到这里，故不会出现"空 token 匹配空 Bearer"。
    """
    if not auth_header:
        return False
    parts = auth_header.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return False
    return oauth_cimd.safe_compare(parts[1].strip(), DEVICE_TOKEN)


async def _device_endpoint(websocket: WebSocket) -> None:
    """第 3 层设备端点（/device）。设备主动连这里持 WebSocket 长连接。

    流程：三道拒绝闸 + 握手鉴权 -> accept -> attach_connection（新踢旧，关旧连接）
    -> 收帧循环（parse_result_frame + 投进在途表叫醒调用方）-> 断开时 detach
    （compare-and-clear）。

    三道闸全部 before-accept 沉默关闭（= 握手阶段 HTTP 403，不给试探者情报，
    延续现有 token 报错策略）。
    """
    # 闸 1：当前设备适配器不支持直连（如 Mock）-> 拒绝。/device 始终注册，
    #   但只有连接型 adapter（WebSocketAdapter）放行。这条日志帮运维看懂"为什么设备连不上"。
    if not device.supports_direct_connection:
        print(
            "[bodybridge] /device: refused a connection -- the active device "
            "adapter does not support direct connections.",
            file=sys.stderr,
        )
        await websocket.close(code=1008)
        return

    # 闸 2：DEVICE_TOKEN 未设 -> /device 禁用，拒绝一切连接。每次拒绝记一行
    #   服务器端日志（不含 token）。启动日志（见 __main__）仍然保留，但它只说
    #   一次、云平台日志滚动后就翻不到了；把线索留在拒绝发生的当下，部署者事后
    #   查"设备为什么连不上"才有据可查。对设备侧依旧是静默 1008，一个字不多给。
    if not DEVICE_TOKEN:
        print(
            "[bodybridge] /device: refused a connection -- "
            "BODYBRIDGE_DEVICE_TOKEN is not set, so the device endpoint "
            "is disabled.",
            file=sys.stderr,
        )
        await websocket.close(code=1008)
        return

    # 闸 3：握手鉴权。从握手请求头读 Authorization: Bearer <token>，常量
    #   时间比对 DEVICE_TOKEN。中间件对 websocket scope 天然放行，故鉴权在此自己做。
    if not _device_bearer_ok(websocket.headers.get("authorization")):
        # 认证失败必须在服务器端留痕（OWASP A09），但只记"被拒了"这个事实：
        # 不含 token 字符/长度、不回显请求头，也【不区分】缺头 / 格式错 / 值不对
        # —— 区分等于把"你差在哪一步"告诉试探者。设备侧仍是静默 1008。
        print(
            "[bodybridge] /device: refused a connection -- the Authorization "
            "header did not carry a valid device token.",
            file=sys.stderr,
        )
        await websocket.close(code=1008)
        return

    # --- 通过三道闸，正式接入 ---
    await websocket.accept()

    # 单连接"新踢旧"。attach 先把指针指向新连接（无 None 空窗）并返回被顶掉
    # 的旧连接，由这里负责关闭。关旧用语义明确的应用码 4409（"被新连接取代"，仿
    # HTTP 409 Conflict）+ reason，方便固件端日志区分"我是被顶掉的，不是网络抖"。
    old = device.attach_connection(websocket)
    if old is not None:
        try:
            await old.close(code=4409, reason="replaced by a new device connection")
        except Exception:
            pass  # 旧连接可能已在关闭中，关它失败无所谓，尽力而为，绝不抛（铁律 3）

    try:
        # 收帧循环：不停收帧，解析 -> 投进在途表叫醒调用方（见下方 deliver_result）。
        # 用低层 receive() 而非 receive_text()：亲手判 disconnect、亲手兜非文本帧，
        # 一个坏帧都不许掀翻循环（铁律 3）。
        while True:
            event = await websocket.receive()
            if event["type"] == "websocket.disconnect":
                break
            # 协议是 JSON 文本帧；二进制/无 text 的帧 -> text 为 None，parse 兜成忽略。
            outcome = parse_result_frame(event.get("text"))
            if outcome.ignore_reason is not None:
                print(f"[bodybridge] /device: ignored a frame -- {outcome.ignore_reason}",
                      file=sys.stderr)
                continue
            if outcome.debug_note is not None:
                print(f"[bodybridge] /device: {outcome.debug_note}", file=sys.stderr)
            # 按 frame_id 投进在途表，叫醒 _send_and_wait 里等这条的调用方。
            # deliver_result 契约保证同步、永不抛（纯内存 pop + set_result），这里仍兜
            # 一层 try/except：绝不让一次投递意外掀翻这条长命的收帧循环（铁律 3）——
            # 兜住就记一行日志、continue，连接照活、其它命令继续收发。命中与否的可见性
            # 由 deliver_result 自己负责（命中静默、无主时打一条带 id 的丢弃日志），
            # 正常路径不在这里刷屏。
            try:
                device.deliver_result(outcome.frame_id, outcome.result)
            except Exception as e:
                print(f"[bodybridge] /device: deliver_result raised, ignored "
                      f"({type(e).__name__}); connection stays up.", file=sys.stderr)
    finally:
        # 断开（设备主动断 / 网络断 / pong 超时被 uvicorn 关 / 被新连接踢）都汇到
        # 这里：compare-and-clear——只有 _connection 还是自己才清，立刻
        # 标 offline。被踢的旧连接走到这时 _connection 已是新连接，不会误清它。
        device.detach_connection(websocket)


# --- OAuth 元数据端点（第 2 层 · CIMD 发现）--------------------------------
# 只做"让 claude.ai 能发现我们"的最小部分：两份公开 JSON 元数据。
# 这些端点必须免鉴权（Claude 在拿到 token 之前就来拉），豁免见下面中间件白名单。
# 关键 CIMD 开关：AS 元数据声明 client_id_metadata_document_supported=true 且
# token_endpoint_auth_methods_supported 含 "none"，且【绝不】写 registration_endpoint
# ——这样 Claude 选 CIMD 而非 DCR（依据 MCP 2025-11-25 授权规范 + Anthropic 连接器文档）。
# authorize / token 端点是第 2/3 步才建，这里只在元数据里声明其地址。


def _protected_resource_metadata() -> dict:
    """RFC 9728 受保护资源元数据。resource 必须与用户在 Claude 里输入的 URL 逐字符一致。"""
    return {
        "resource": f"{PUBLIC_URL}/mcp",
        "authorization_servers": [PUBLIC_URL],
        "bearer_methods_supported": ["header"],
        "scopes_supported": ["mcp"],
    }


# 主路径：带 /mcp 后缀（Claude 优先探测这个）；根路径：兜底，返回同一份文档
@mcp.custom_route("/.well-known/oauth-protected-resource/mcp", methods=["GET"])
async def oauth_protected_resource_mcp(request: Request) -> JSONResponse:
    return JSONResponse(_protected_resource_metadata())


@mcp.custom_route("/.well-known/oauth-protected-resource", methods=["GET"])
async def oauth_protected_resource_root(request: Request) -> JSONResponse:
    return JSONResponse(_protected_resource_metadata())


@mcp.custom_route("/.well-known/oauth-authorization-server", methods=["GET"])
async def oauth_authorization_server(request: Request) -> JSONResponse:
    """RFC 8414 授权服务器元数据。dcr/cimd 两种模式二选一广播，绝不同时出现
    ——Anthropic 官方文档："Claude selects CIMD only when your authorization
    server metadata advertises both client_id_metadata_document_supported:
    true and none in token_endpoint_auth_methods_supported... If either is
    missing, Claude falls back to DCR."：两个字段都出现的话 Claude 仍会优先
    选 CIMD，开关就白设了。"""
    metadata = {
        "issuer": PUBLIC_URL,
        "authorization_endpoint": f"{PUBLIC_URL}/oauth/authorize",
        "token_endpoint": f"{PUBLIC_URL}/oauth/token",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],  # 两种模式都是公开客户端
        "scopes_supported": ["mcp"],
        # RFC 9207：与 _redirect_with 注入 iss 必须同进同退——声明了却不发，
        # 遵规范的客户端会拒掉授权响应，认证直接中断。
        "authorization_response_iss_parameter_supported": True,
    }
    if CLIENT_REGISTRATION == "dcr":
        metadata["registration_endpoint"] = f"{PUBLIC_URL}/oauth/register"
    else:
        metadata["client_id_metadata_document_supported"] = True
    return JSONResponse(metadata)


# --- OAuth 动态客户端注册（第 2 层 · DCR，RFC 7591）--------------------------
# 无状态：不落表，client_id 本身自包含签名（见 oauth_cimd.issue_client_id 的
# 出处说明——RFC 7591 附录 A.5.2 / OIDC DCR 1.0 §8.2）。免鉴权（白名单里）；
# cimd 模式下这个端点仍然存在、可访问，只是元数据没广播它，遵规范的客户端
# 不会主动去调，不需要额外代码禁用。
_DCR_HEADERS = {"Cache-Control": "no-store", "Pragma": "no-cache"}


@mcp.custom_route("/oauth/register", methods=["POST"])
async def oauth_register(request: Request) -> JSONResponse:
    try:
        body = await request.json()
    except Exception:
        body = None

    result = oauth_cimd.validate_registration_request(body)
    if not result.ok:
        return JSONResponse(
            {"error": result.error, "error_description": result.error_description},
            status_code=400, headers=_DCR_HEADERS,
        )

    client_id, issued_at, size_error = oauth_cimd.issue_client_id(
        TOKEN, redirect_uris=result.redirect_uris, client_name=result.client_name,
    )
    if client_id is None:
        return JSONResponse(
            {"error": "invalid_client_metadata", "error_description": size_error},
            status_code=400, headers=_DCR_HEADERS,
        )

    return JSONResponse(
        {
            "client_id": client_id,
            "client_id_issued_at": issued_at,
            "redirect_uris": result.redirect_uris,
            "client_name": result.client_name,
            # 硬编码回，不看客户端说了什么——我们结构上只支持公开客户端。
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
        },
        status_code=201, headers=_DCR_HEADERS,
    )


# --- OAuth 授权端点（第 2 层 · CIMD 校验 + PKCE）----------------------------
# CIMD 校验、SSRF 防护的实现全在 oauth_cimd.py（可独立单测）。这里只负责：
# 参数校验编排、渲染极简密码页、发放签名授权码。
#
# 参数校验分两段，这是防开放重定向的根本（RFC 6749 §4.1.2.1）：
#   前 4 项（client_id / CIMD fetch / client_id 自证 / redirect_uri 精确匹配）
#   任何一项失败 —— 直接错误页，绝不重定向（此时 redirect_uri 还不可信）。
#   之后（response_type / code_challenge / code_challenge_method）失败 ——
#   可以带 error= 重定向回去（redirect_uri 此时已确认可信）。
#
# 授权码：签名+短时效自包含（无状态），但"一次性"靠一个极小的、自我过期的
# jti 已用集合（见 oauth_cimd.redeem_authorization_code 的取舍说明）。

_AUTH_CODE_TTL_SECONDS = 90
_used_code_jtis: dict[str, float] = {}

_AUTHORIZE_HEADERS = {"X-Frame-Options": "DENY", "Cache-Control": "no-store"}

# 密码页和错误页共用同一套样式，只写一份——两处各写一套将来必然漂开。
# 全部内联、零外部资源：这两个页面在拿到 token 前就要显示，任何 CDN 字体/
# 外链 CSS/外链图片都等于把授权入口的可用性交给第三方。
_PAGE_CSS = """:root{color-scheme:light dark;
      --ink:#1E3D33;--bg:#FFFDF9;--line:#D8D4CB;--err:#B00020}
@media(prefers-color-scheme:dark){
  :root{--ink:#8FC3AC;--bg:#0D1117;--line:#2A3138;--err:#FF6B6B}}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:flex;align-items:center;
     justify-content:center;padding:1.5rem;background:var(--bg);
     color:var(--ink);
     font-family:ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
main{width:100%;max-width:22rem;text-align:center}
.lockup{width:100%;max-width:11rem;height:auto;margin:0 auto}
p{font-size:.9rem;opacity:.75;margin:1.25rem 0 1.5rem;line-height:1.5}
input[type=password]{width:100%;min-height:44px;padding:0 .9rem;
     font-size:1rem;color:var(--ink);background:transparent;
     border:1px solid var(--line);border-radius:8px}
input[type=password]:focus{outline:2px solid var(--ink);outline-offset:-1px}
button{width:100%;min-height:44px;margin-top:.75rem;font-size:1rem;
     color:var(--bg);background:var(--ink);border:0;border-radius:8px;
     cursor:pointer}
.err{color:var(--err);font-size:.85rem;margin:0 0 .5rem}
h1{font-size:1.05rem;font-weight:500;margin:.75rem 0 0}"""

# Inlined from assets/lockup-inline.svg. Keep both in sync.
_LOCKUP_SVG = '''<svg class="lockup" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 542.3 95" version="1.1" fill="none" role="img" aria-labelledby="bbil-title">
  <title id="bbil-title">bodybridge</title>
  <mask id="bbil-channel" maskUnits="userSpaceOnUse" x="0" y="0" width="64" height="64">
    <rect x="0" y="0" width="64" height="64" fill="#fff"/>
    <path d="M8 36 H57" stroke="#000" stroke-width="5.4" fill="none"/>
  </mask>
  <clipPath id="bbil-shell">
    <path d="M11 33.3 V30 A9 9 0 0 1 28.22 26.34 A13 13 0 1 1 54 24 V33.3 Z"/>
  </clipPath>
  <clipPath id="bbil-win">
    <rect x="0" y="0" width="22" height="33.3"/>
    <rect x="22" y="0" width="42" height="29.3"/>
  </clipPath>
  <g transform="translate(-7,0)">
    <path d="m 34.5,73.9 q -7.2,0 -12,-3.4 -4.8,-3.5 -6.3,-9.7 l 1,-0.2 V 73 H 7.3 V 1 h 10.4 v 32.7 l -1.1,-0.3 q 1.7,-5.8 6.6,-9.1 5,-3.3 12,-3.3 6.9,0 11.9,3.3 5.1,3.3 7.8,9.2 2.8,5.9 2.8,13.8 0,8 -2.9,14 -2.9,6 -8.1,9.3 -5.2,3.3 -12.2,3.3 z m -2.2,-8.6 q 6.8,0 10.8,-4.8 4,-4.8 4,-13.2 0,-8.3 -4,-12.9 -4,-4.7 -10.9,-4.7 -6.8,0 -10.9,4.8 -4,4.7 -4,13.1 0,8.2 4,13 4.1,4.7 11,4.7 z M 89.133492,74 q -7.8,0 -13.7,-3.4 -5.9,-3.5 -9.2,-9.5 -3.3,-6.1 -3.3,-13.8 0,-7.8 3.3,-13.7 3.4,-5.9 9.2,-9.2 5.9,-3.4 13.7,-3.4 7.9,0 13.799998,3.4 5.9,3.3 9.1,9.2 3.3,5.9 3.3,13.7 0,7.7 -3.3,13.8 -3.2,6 -9.1,9.5 Q 97.033492,74 89.133492,74 Z m 0,-8.5 q 4.7,0 8.1,-2.3 3.499998,-2.3 5.499998,-6.4 2,-4.1 2,-9.6 0,-8.2 -4.4,-12.9 -4.299998,-4.8 -11.199998,-4.8 -6.8,0 -11.2,4.8 -4.3,4.8 -4.3,12.9 0,5.5 1.9,9.6 2,4.1 5.5,6.4 3.6,2.3 8.1,2.3 z M 161.16686,73 V 61.3 l 1,0.3 q -1.6,5.7 -6.6,9.1 -5,3.3 -12,3.3 -6.9,0 -12.1,-3.3 -5.1,-3.3 -8,-9.2 -2.8,-5.9 -2.8,-13.8 0,-8 2.9,-14 2.9,-6 8.1,-9.3 5.2,-3.3 12.2,-3.3 7.3,0 12,3.5 4.8,3.4 6.3,9.6 l -1.4,0.2 V 1 h 10.3 v 72 z m -15,-7.7 q 6.9,0 10.9,-4.7 4,-4.8 4,-13.2 0,-8.2 -4.1,-12.9 -4,-4.8 -10.9,-4.8 -6.8,0 -10.8,4.8 -3.9,4.7 -3.9,13.2 0,8.3 3.9,13 4,4.6 10.9,4.6 z m 41.30008,28.2 12.3,-28.1 2.1,-3.3 15.5,-40.1 h 10.8 l -30,71.5 z m 11.8,-20.5 -21.8,-51 h 11.3 l 18.5,45.9 z" fill="currentColor" aria-label="body"/>
    <g transform="translate(233.375,11) scale(1.712707)">
      <g transform="translate(-9.4,-9.4)">
        <g mask="url(#bbil-channel)">
          <g clip-path="url(#bbil-shell)"><g clip-path="url(#bbil-win)"><g transform="translate(2,2.6)">
            <path d="M11 30 A9 9 0 0 1 28.22 26.34 A13 13 0 1 1 54 24" stroke="currentColor" stroke-opacity="0.22" stroke-width="3.2" stroke-linejoin="round" stroke-linecap="round"/>
          </g></g></g>
          <path d="M11 30 A9 9 0 0 1 28.22 26.34 A13 13 0 1 1 54 24 V41 A3 3 0 0 1 51 44 H14 A3 3 0 0 1 11 41 Z" stroke="currentColor" stroke-width="3.2" stroke-linejoin="round"/>
          <path d="M11 31.7 H54" stroke="currentColor" stroke-width="3.2" stroke-linecap="round"/>
          <path d="M11 38.7 V41 A3 3 0 0 0 14 44 H51 A3 3 0 0 0 54 41 V38.7 Z" fill="currentColor"/>
        </g>
      </g>
    </g>
    <path d="M 325.80101,73 V 22 h 9.9 v 12.7 h 0.5 V 73 Z m 10.4,-26.6 -1.3,-12.1 q 1.8,-6.5 6.2,-9.9 4.4,-3.4 10.5,-3.4 2.3,0 3.2,0.4 v 9.8 q -0.5,-0.2 -1.4,-0.2 -0.9,-0.1 -2.2,-0.1 -7.5,0 -11.3,3.9 -3.7,3.9 -3.7,11.6 z M 361.23425,73 V 22 h 10.4 v 51 z m -0.5,-61 V 0.3 h 11.5 V 12 Z m 60.03316,61 V 61.3 l 1,0.3 q -1.6,5.7 -6.6,9.1 -5,3.3 -12,3.3 -6.9,0 -12.1,-3.3 -5.1,-3.3 -8,-9.2 -2.8,-5.9 -2.8,-13.8 0,-8 2.9,-14 2.9,-6 8.1,-9.3 5.2,-3.3 12.2,-3.3 7.3,0 12,3.5 4.8,3.4 6.3,9.6 l -1.4,0.2 V 1 h 10.3 v 72 z m -15,-7.7 q 6.9,0 10.9,-4.7 4,-4.8 4,-13.2 0,-8.2 -4.1,-12.9 -4,-4.8 -10.9,-4.8 -6.8,0 -10.8,4.8 -3.9,4.7 -3.9,13.2 0,8.3 3.9,13 4,4.6 10.9,4.6 z m 58.90009,29.2 q -9.6,0 -15.9,-4.4 -6.2,-4.3 -7.5,-11.5 h 9.8 q 1,3.3 4.4,5.2 3.5,1.9 9.3,1.9 7.5,0 11.2,-3.7 3.7,-3.7 3.7,-11 V 60 l 0.9,0.2 q -1.5,5.8 -6.5,9.2 -5,3.3 -12,3.3 -6.7,0 -11.8,-3.2 -5.1,-3.2 -7.9,-8.9 -2.8,-5.8 -2.8,-13.5 0,-7.8 2.9,-13.7 2.9,-5.9 8.1,-9.1 5.3,-3.2 12.3,-3.2 7.2,0 11.9,3.5 4.8,3.4 6.1,9.7 l -0.8,0.1 V 22 h 9.9 v 48.9 q 0,11 -6.8,17.3 -6.7,6.3 -18.5,6.3 z m 0.5,-30.2 q 6.7,0 10.7,-4.7 4.1,-4.7 4.1,-12.9 0,-8 -4.1,-12.6 -4,-4.6 -10.8,-4.6 -6.8,0 -10.8,4.7 -4,4.6 -4,12.8 0,8 4,12.7 4.1,4.6 10.9,4.6 z m 59.40008,9.7 q -7.7,0 -13.6,-3.4 -5.8,-3.4 -9.1,-9.4 -3.3,-6 -3.3,-13.8 0,-7.9 3.2,-13.8 3.3,-6 9.2,-9.3 5.9,-3.3 13.5,-3.3 7.4,0 12.8,3.2 5.5,3.1 8.4,8.7 3,5.6 3,13.3 0,1.2 -0.1,2.3 0,1 -0.2,2.1 h -42.8 v -7.8 h 35.5 l -2.6,3.1 q 0,-8.2 -3.7,-12.5 -3.7,-4.3 -10.3,-4.3 -7.1,0 -11.3,4.9 -4.1,4.8 -4.1,13.4 0,8.7 4.1,13.6 4.2,4.9 11.6,4.9 4.5,0 7.8,-1.8 3.3,-1.9 4.9,-5.5 h 9.8 q -2.5,7.2 -8.5,11.3 -5.9,4.1 -14.2,4.1 z" fill="currentColor" aria-label="ridge"/>
  </g>
</svg>'''


def _esc(value) -> str:
    """所有回显到 HTML 里的用户输入/远端数据，一律转义。内联拼 HTML 就是
    XSS 温床——state、client_id、client_name（来自远端 CIMD 文档，不可信）
    都必须过这一道。"""
    return html.escape(str(value), quote=True)


def _authorize_error_page(message: str, status: int = 400) -> HTMLResponse:
    """前 4 项校验失败用这个：直接报错，绝不重定向（redirect_uri 还不可信）。"""
    body = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>bodybridge - Authorization Error</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex">
<style>{_PAGE_CSS}</style></head>
<body><main>
<h1>Authorization request rejected</h1>
<p>{_esc(message)}</p>
</main></body></html>"""
    return HTMLResponse(body, status_code=status, headers=_AUTHORIZE_HEADERS)


def _authorize_form_html(*, client_id, client_name, redirect_uri, state,
                          code_challenge, code_challenge_method, resource,
                          error: str = "") -> str:
    err_html = f'<p class="err">{_esc(error)}</p>' if error else ""
    resource_field = (
        f'<input type="hidden" name="resource" value="{_esc(resource)}">'
        if resource else ""
    )
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>bodybridge - Authorize</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex">
<style>{_PAGE_CSS}</style></head>
<body><main>
{_LOCKUP_SVG}
<h1>Authorize {_esc(client_name)}</h1>
<p>This app wants to connect to your bodybridge.</p>
<form method="POST">
<input type="hidden" name="client_id" value="{_esc(client_id)}">
<input type="hidden" name="redirect_uri" value="{_esc(redirect_uri)}">
<input type="hidden" name="state" value="{_esc(state)}">
<input type="hidden" name="code_challenge" value="{_esc(code_challenge)}">
<input type="hidden" name="code_challenge_method" value="{_esc(code_challenge_method)}">
{resource_field}
{err_html}
<input type="password" name="password" placeholder="Bridge password" autocomplete="current-password" autofocus>
<button type="submit">Authorize</button>
</form>
</main></body></html>"""


def _redirect_with(redirect_uri: str, params: dict) -> RedirectResponse:
    """/oauth/authorize 的【授权响应】重定向器——成功（code）和错误（error）
    两条路都经过这里，不是通用的 URL 拼接工具。

    自动注入 iss（RFC 9207 §2：授权响应——包括错误响应——MUST 带上授权服务器
    标识，客户端据此确认响应来自哪个授权服务器）。取值直接复用 PUBLIC_URL，
    与元数据文档广播的 issuer 同源，两者永远一致。用 {**params} 新建字典注入，
    不原地改调用方传进来的 dict。

    sep 判断沿用 OB 的写法（redirect_uri 自带 query 时用 & 续接）；外加
    Cache-Control: no-store（OAuth 规范要求：带授权码/错误信息的响应不能被缓存）。
    """
    params = {**params, "iss": PUBLIC_URL}
    sep = "&" if "?" in redirect_uri else "?"
    query = "&".join(
        f"{k}={urlquote(str(v))}" for k, v in params.items() if v
    )
    location = f"{redirect_uri}{sep}{query}" if query else redirect_uri
    return RedirectResponse(location, status_code=302,
                             headers={"Cache-Control": "no-store"})


def _validate_authorize_request(params: dict):
    """校验 /oauth/authorize 的参数。GET、POST 共用同一份逻辑——POST 阶段这些
    OAuth 参数一律从 request.query_params 读（表单 action 留空，浏览器提交时
    天然带着原始查询字符串），不从表单体读、更不信任 HTML 隐藏字段，原样重新
    走一遍这里，而不是假设 GET 已经验过了（这正是绕开 OB 那个 "client_info 为
    None 时跳过 redirect_uri 校验"缺口的关键：dcr 模式下没有本地注册表可查，
    验签本身就是唯一的"注册检查"；cimd 模式下 CIMD fetch 本身就是唯一的
    "注册检查"——两种模式都不允许有跳过路径）。

    客户端身份解析按 BODYBRIDGE_CLIENT_REGISTRATION 二选一：
      dcr  -> 本地验签自签名 client_id（零网络请求），解出 redirect_uris
      cimd -> 出站 fetch 客户端声明的 CIMD 文档（见 oauth_cimd.fetch_cimd_document）
    两条分支殊途同归：要么拿到一份可信的 redirect_uris 列表，要么直接硬拒
    ——没有中间态，所以 redirect_uri 精确匹配这一步天然无条件执行。

    返回 (stage, payload)：
      "trusted_error"  -> payload 是 HTMLResponse，直接返回，不重定向
      "redirect_error"  -> payload 是 (redirect_uri, error, description)
      "ok"              -> payload 是校验通过的字典
    """
    client_id = params.get("client_id", "")

    if CLIENT_REGISTRATION == "dcr":
        claims = oauth_cimd.verify_client_id(TOKEN, client_id)
        if claims is None:
            return "trusted_error", _authorize_error_page(
                "client_id is not a valid or recognized client identifier."
            )
        redirect_uris = claims.get("redirect_uris", [])
        client_name = claims.get("client_name") or client_id
    else:
        if not client_id.startswith("https://"):
            return "trusted_error", _authorize_error_page(
                "client_id must be an https:// URL (a Client ID Metadata Document)."
            )
        if not urlsplit(client_id).path.strip("/"):
            return "trusted_error", _authorize_error_page(
                "client_id URL must contain a path component."
            )
        fetch = oauth_cimd.fetch_cimd_document(client_id, allowlist_hosts=CIMD_ALLOWLIST)
        if not fetch.ok:
            return "trusted_error", _authorize_error_page(
                f"could not verify client identity: {fetch.error}"
            )
        redirect_uris = fetch.document.get("redirect_uris", [])
        client_name = fetch.document.get("client_name") or client_id

    redirect_uri = params.get("redirect_uri", "")
    if redirect_uri not in redirect_uris:
        return "trusted_error", _authorize_error_page(
            "redirect_uri does not match any redirect_uris registered for "
            "this client."
        )

    # --- redirect_uri 从此可信，以下错误可以带 error= 重定向回去 ---
    if params.get("response_type") != "code":
        return "redirect_error", (
            redirect_uri, "unsupported_response_type",
            "only response_type=code is supported",
        )

    code_challenge = params.get("code_challenge", "")
    if not oauth_cimd.is_valid_code_challenge(code_challenge):
        return "redirect_error", (
            redirect_uri, "invalid_request",
            "code_challenge is missing or malformed (must be S256, 43-128 chars)",
        )

    if params.get("code_challenge_method") != "S256":
        return "redirect_error", (
            redirect_uri, "invalid_request",
            "code_challenge_method must be S256",
        )

    return "ok", {
        "client_id": client_id,
        "client_name": client_name,
        "redirect_uri": redirect_uri,
        "state": params.get("state", ""),
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        # resource 存在则记录（供未来 token 端点做 audience 绑定），缺失不拒绝。
        "resource": params.get("resource") or None,
    }


@mcp.custom_route("/oauth/authorize", methods=["GET", "POST"])
async def oauth_authorize(request: Request):
    if request.method == "GET":
        params = dict(request.query_params)
    else:
        # 密码页的 <form> 没写 action，浏览器提交 POST 时天然带着原始查询
        # 字符串（日志可见 POST /oauth/authorize?response_type=code&...）。
        # 所以 OAuth 参数（state/client_id/redirect_uri/code_challenge/
        # code_challenge_method/response_type/resource）一律从这里读，只有
        # password 读表单体——state 从此不再经过 HTML 隐藏字段的转义/解码
        # 往返（那条链路曾是"302 发出但 Claude 从不来换 token"的最可疑候选：
        # 转义后的值如果没被标准浏览器行为完整解码回来就会跟原值对不上，
        # Claude 校验 state 不符会静默丢弃回调，永远不会调 /oauth/token）。
        # 这样也顺带堵死了表单体里被塞入伪造 client_id/redirect_uri 的可能
        # ——一律以 query_params 为准，不认表单体里的同名字段。
        params = dict(request.query_params)
        try:
            form = await request.form()
        except Exception:
            return _authorize_error_page("could not parse form submission.")
        params["password"] = str(form.get("password", ""))

    stage, payload = _validate_authorize_request(params)

    if stage == "trusted_error":
        return payload
    if stage == "redirect_error":
        redirect_uri, error, description = payload
        return _redirect_with(redirect_uri, {
            "error": error,
            "error_description": description,
            "state": params.get("state") or None,
        })

    validated = payload  # 校验通过的字典

    if request.method == "GET":
        return HTMLResponse(_authorize_form_html(**validated),
                             headers=_AUTHORIZE_HEADERS)

    # POST：参数已经重新校验过；现在查密码。密码比对走 _password_matches，
    # 全角字符/超长/空值/二进制乱码——任何输入都归 try/except 兜底，绝不 500。
    presented_password = params.get("password", "")
    if not _password_matches(presented_password):
        return HTMLResponse(
            _authorize_form_html(
                **validated, error="Incorrect password, please try again.",
            ),
            status_code=401,
            headers=_AUTHORIZE_HEADERS,
        )

    code = oauth_cimd.issue_authorization_code(
        TOKEN,
        client_id=validated["client_id"],
        redirect_uri=validated["redirect_uri"],
        code_challenge=validated["code_challenge"],
        code_challenge_method=validated["code_challenge_method"],
        resource=validated["resource"],
        ttl_seconds=_AUTH_CODE_TTL_SECONDS,
    )
    return _redirect_with(validated["redirect_uri"], {
        "code": code,
        "state": validated["state"] or None,
    })


# --- OAuth token 端点（第 2 层 · PKCE 核对 + JWT 签发）----------------------
# 参数校验、错误码全按 RFC 6749 §5.2（token 端点错误响应固定 HTTP 400 +
# {"error", "error_description"}）+ RFC 7636（PKCE 失败专用 invalid_grant）+
# RFC 8707（resource 不匹配专用 invalid_target，不是通用 invalid_grant）。
#
# 授权码类失败（签名错/过期/已用过/client_id 不符/redirect_uri 不符/PKCE 失败）
# 统一折叠成同一句 invalid_grant + 同一句 error_description，不区分具体原因——
# 这些是私密值，细分等于给试探者情报。resource 不匹配则相反，把期望值和收到值
# 并排列出来——resource 本来就公开在元数据文档里，且几乎总是配置错误，说清楚
# 才好排查，两种策略不同是有意的。

_CODE_INVALID_ERROR = (
    "invalid_grant",
    "the authorization code is invalid, expired, already used, or does not "
    "match this request.",
)


def _token_error(error: str, description: str, status: int = 400) -> JSONResponse:
    return JSONResponse(
        {"error": error, "error_description": description},
        status_code=status,
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
    )


def _normalize_resource_url(url: str) -> str:
    """规范化一个 resource URI，供 token 端点的 audience 比对用。

    改的是"比对前先规范化"这个轴，不是"普通 != vs 常量时间比对"那个轴（后者
    保持不动：resource 是公开值，无需常量时间比对）。MCP 授权规范 / RFC 8707
    要求比对时接受【规范化形式】，而不是对用户输入原文逐字节严格比对——否则
    大小写、尾斜杠、默认端口、fragment 这些无害差异都会误判成 invalid_target。

    规则：scheme 与 host 转小写、去尾部斜杠、去 fragment、去默认端口
    （http 的 :80 / https 的 :443）；其余（path 大小写、query 等）原样不动。

    resource 是外部输入：任何解析异常一律原样返回（铁律 3：绝不崩）——规范化
    不了的怪值天然匹配不上我们干净的 expected，会被正常拒掉，安全。"""
    try:
        parts = urlsplit(url)
        scheme = parts.scheme.lower()
        host = (parts.hostname or "").lower()
        port = parts.port  # 非法端口会在这里抛 ValueError，落到下面 except
        is_default_port = (
            (scheme == "http" and port == 80)
            or (scheme == "https" and port == 443)
        )
        netloc = host
        if port is not None and not is_default_port:
            netloc = f"{host}:{port}"
        path = parts.path.rstrip("/")
        # fragment 丢弃（第 5 个位置传空串）；query 原样保留
        return urlunsplit((scheme, netloc, path, parts.query, ""))
    except Exception:
        return url


@mcp.custom_route("/oauth/token", methods=["POST"])
async def oauth_token(request: Request) -> JSONResponse:
    # Anthropic 官方文档点名要求：/token 必须真支持
    # application/x-www-form-urlencoded（不能只支持 JSON）；JSON 顺手兼容。
    content_type = request.headers.get("content-type", "")
    try:
        if "json" in content_type:
            raw_body = await request.json()
            body = raw_body if isinstance(raw_body, dict) else {}
        else:
            form = await request.form()
            body = {k: str(v) for k, v in form.items()}
    except Exception:
        return _token_error("invalid_request", "could not parse the request body.")

    if body.get("grant_type") != "authorization_code":
        return _token_error(
            "unsupported_grant_type",
            "only grant_type=authorization_code is supported.",
        )

    code = str(body.get("code") or "")
    client_id = str(body.get("client_id") or "")
    if not code or not client_id:
        return _token_error(
            "invalid_request", "code and client_id are required parameters."
        )
    redirect_uri = str(body.get("redirect_uri") or "")
    code_verifier = str(body.get("code_verifier") or "")

    # 先核销（一碰即烧，不管接下来还通不通得过）；再比 client_id/redirect_uri；
    # 最后做 PKCE。顺序是故意的：如果失败不烧码，攻击者能对同一个 code 反复猜
    # code_verifier，把 PKCE 该有的"只准一次机会"变成"无限次机会"。
    #
    # code 里存的是 client_id 的哈希（见 oauth_cimd.hash_client_id），不是原文
    # ——这里把客户端出示的 client_id 算一遍哈希再比对，效果跟直接比对完整
    # client_id 完全等价（确认"token 阶段和 authorize 阶段是同一个客户端"），
    # 只是不用在 code 里背整个 client_id 的重量。哈希是公开值的比对，不是秘密
    # 比对，普通 == 即可，不需要 safe_compare（跟 redirect_uri 比对同一分野）。
    claims = oauth_cimd.redeem_authorization_code(TOKEN, code, _used_code_jtis)
    if (
        claims is None
        or oauth_cimd.hash_client_id(client_id) != claims.get("client_id_hash")
        or redirect_uri != claims.get("redirect_uri")
        or not oauth_cimd.verify_pkce_challenge(
            code_verifier, claims.get("code_challenge", "")
        )
    ):
        return _token_error(*_CODE_INVALID_ERROR)

    # resource / audience 绑定（MCP 授权规范：token 必须绑定到指定的 resource）。
    # 严格模式：客户端（这次请求或当初 /authorize 记下的）明确带了 resource 且
    # 跟我们唯一的资源不一致 —— 直接拒，RFC 8707 §2 的专用错误码 invalid_target。
    # 缺失则不拒绝，默认绑到我们自己（单资源桥，只服务这一个 /mcp）。
    expected_resource = f"{PUBLIC_URL}/mcp"
    effective_resource = body.get("resource") or claims.get("resource")
    if effective_resource:
        expected_norm = _normalize_resource_url(expected_resource)
        effective_norm = _normalize_resource_url(effective_resource)
        if effective_norm != expected_norm:
            return _token_error(
                "invalid_target",
                f'expected resource "{expected_norm}", got "{effective_norm}"',
            )

    # sub 存 client_id 的哈希，不是原文——access_token 要在有效期内跟着每次
    # /mcp 请求重发一遍，是三层嵌套里最贵的一层，claims 该放标识不是载荷。
    # 这是一个客户端指纹：当前中间件不读取、不校验 sub（只验签名/exp/aud/iss），
    # 留着它是为了将来做审计/排障时能认出"这个 token 是哪个客户端换出来的"，
    # 不是当前安全校验链条的一部分。
    token, expires_in = oauth_cimd.issue_access_token(
        TOKEN,
        issuer=PUBLIC_URL,
        audience=expected_resource,
        subject=oauth_cimd.hash_client_id(client_id),
        ttl_seconds=TOKEN_TTL_DAYS * 86400,
    )
    return JSONResponse(
        {
            "access_token": token,
            "token_type": "Bearer",
            "expires_in": expires_in,
            "scope": "mcp",
        },
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
    )


# --- 鉴权守门层（第 2 层）---------------------------------------------------
# 纯 ASGI 中间件：请求进来时只看一眼 Authorization 头，要么当场 401、要么原样
# 放行，完全不碰响应流（避免 BaseHTTPMiddleware 掐断 streamable-http 的 SSE 长流）。
# 因为 stateless_http，每次 MCP 调用都是独立 HTTP 请求，所以这里天然做到"每个请求
# 都验"，而不是只在握手时验一次。
#
# 这里不再是"比对固定 BODYBRIDGE_TOKEN 字符串"，
# 而是验签发的 JWT——签名 + exp + aud + iss 全部显式校验（见
# oauth_cimd.verify_access_token）。BODYBRIDGE_TOKEN 的角色也变了：不再是
# 客户端直接出示的钥匙，而是服务器自己的 JWT 签名密钥，只在这里和签发处使用，
# 永不出现在客户端手里（迁移细节见 MIGRATION.md）。


def _verify_bearer_token(token: str) -> bool:
    """校验 Authorization 头里的 Bearer token 是否是我们签发的有效 JWT。"""
    return oauth_cimd.verify_access_token(
        TOKEN, token, audience=f"{PUBLIC_URL}/mcp", issuer=PUBLIC_URL,
    ) is not None


def _password_matches(presented: str) -> bool:
    """/oauth/authorize 密码门禁，同一个安全比较模式。"""
    return oauth_cimd.safe_compare(presented, PASSWORD)


def _unauthorized(message: str) -> JSONResponse:
    """401 + 说人话的错误，附 WWW-Authenticate 指路头。
    resource_metadata 指向受保护资源元数据，Claude 据此发现授权服务器、走 OAuth
    （RFC 9728 §5.1 / MCP 授权规范）。JSON 体保持人话报错不动（铁律 4）。
    形状照抄 OB（其 server.py 4875-4877），地址换成我们自己的。"""
    resource_metadata = f"{PUBLIC_URL}/.well-known/oauth-protected-resource/mcp"
    return JSONResponse(
        {"error": "unauthorized", "message": message},
        status_code=401,
        headers={"WWW-Authenticate": f'Bearer resource_metadata="{resource_metadata}"'},
    )


# OAuth 发现/授权端点必须公开（Claude 拿 token 前就要访问），这里前缀匹配放行。
# str.startswith 接受元组，任一前缀命中即公开。/oauth/* 现在还没建（404）也无妨。
_PUBLIC_PATH_PREFIXES = (
    "/.well-known/oauth-protected-resource",
    "/.well-known/oauth-authorization-server",
    "/oauth/authorize",
    "/oauth/token",
    "/oauth/register",
)


class BearerAuthMiddleware:
    def __init__(self, app, token: str):
        self.app = app
        self.token = token  # JWT 签名密钥（即 BODYBRIDGE_TOKEN），不再是共享明文钥匙

    def _reason_to_reject(self, auth_bytes) -> str | None:
        """返回一句人话说明为何拒绝；返回 None 表示放行。防御性处理各种坏输入
        ——空值、超长串、全角字符、二进制乱码、格式畸形的 JWT，一律友好拒绝，
        绝不 500（铁律 3）。"""
        if not auth_bytes:
            return ("No Authorization header was sent. Send one in the form: "
                    "Authorization: Bearer <your token>.")
        try:
            auth = auth_bytes.decode("latin-1")  # ASGI 里 header 就是 latin-1，永不抛
        except Exception:
            return ("The Authorization header could not be read as text. Send "
                    "it as plain ASCII in the form: "
                    "Authorization: Bearer <your token>.")
        parts = auth.split(" ", 1)
        if len(parts) != 2 or parts[0].lower() != "bearer":
            return ("The Authorization header is not in the expected form. It "
                    "must be: Authorization: Bearer <your token>.")
        if not _verify_bearer_token(parts[1].strip()):
            # 签名错/已过期/aud 不符/iss 不符/格式畸形——统一这一句，不细分
            # 具体原因（防信息泄露，延续 /oauth/token 的同一策略）。
            return ("This token is not valid or has expired. Complete the "
                    "OAuth flow again, starting at /oauth/authorize, to get "
                    "a new one.")
        return None

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":  # 非 HTTP（如 lifespan）直接放行
            return await self.app(scope, receive, send)
        # 公开路径白名单：只在最前面加这道跳过，下面的 token 校验逻辑一个字不动。
        if scope.get("path", "").startswith(_PUBLIC_PATH_PREFIXES):
            return await self.app(scope, receive, send)
        auth = dict(scope.get("headers", [])).get(b"authorization")
        reason = self._reason_to_reject(auth)
        if reason is not None:
            return await _unauthorized(reason)(scope, receive, send)
        await self.app(scope, receive, send)


# ---------------------------------------------------------------------------


if __name__ == "__main__":
    if not TOKEN:
        print(
            "[bodybridge] fatal: environment variable BODYBRIDGE_TOKEN is not set.\n"
            "  It is required for auth. Without it the service would be open to anyone,\n"
            "  so startup is refused.\n"
            "  Set it (PowerShell):  $env:BODYBRIDGE_TOKEN = 'your-secret'",
            file=sys.stderr,
        )
        sys.exit(1)

    if not PASSWORD:
        print(
            "[bodybridge] fatal: environment variable BODYBRIDGE_PASSWORD is not set.\n"
            "  It gates /oauth/authorize, the page CIMD clients (e.g. claude.ai) use\n"
            "  to obtain a token. Without it that flow cannot work at all, so startup\n"
            "  is refused -- failing fast beats starting up with OAuth silently broken.\n"
            "  Set it (PowerShell):  $env:BODYBRIDGE_PASSWORD = 'your-secret'",
            file=sys.stderr,
        )
        sys.exit(1)

    if not _PUBLIC_URL_IS_SET:
        print(
            "[bodybridge] fatal: environment variable BODYBRIDGE_PUBLIC_URL is not set.\n"
            "  It is the bridge's public base URL: every OAuth metadata field, and the\n"
            "  iss and aud of every token, is derived from it. Without it MCP\n"
            "  clients (claude.ai among them) cannot discover or validate this\n"
            "  bridge, so startup is refused.\n"
            "  Set it (PowerShell, no trailing slash):\n"
            "    $env:BODYBRIDGE_PUBLIC_URL = 'https://your-bridge.example.com'",
            file=sys.stderr,
        )
        sys.exit(1)

    if _PUBLIC_URL_WARNING:  # 铁律 5：PUBLIC_URL 坏值不拒启，但要醒目提示
        print(_PUBLIC_URL_WARNING, file=sys.stderr)

    if _TOKEN_TTL_WARNING:  # 铁律 3/5：TTL 坏值不拒启，但要醒目提示
        print(_TOKEN_TTL_WARNING, file=sys.stderr)

    if _COMMAND_TIMEOUT_WARNING:  # 铁律 3/5：deadline 坏值不拒启，回退 25，但要提示
        print(_COMMAND_TIMEOUT_WARNING, file=sys.stderr)

    if _PORT_WARNING:  # 铁律 3/5：端口坏值不拒启，跳过它、试下一优先级，但要提示
        print(_PORT_WARNING, file=sys.stderr)

    if _CLIENT_REGISTRATION_WARNING:  # 铁律 3/5：模式坏值不拒启，回退 dcr，但要提示
        print(_CLIENT_REGISTRATION_WARNING, file=sys.stderr)

    if _HEARTBEAT_WARNING:  # 铁律 3/5：心跳间隔坏值不拒启，回退 25，但要提示
        print(_HEARTBEAT_WARNING, file=sys.stderr)

    if _MAX_PAYLOAD_WARNING:  # 铁律 3/5：载荷上限坏值不拒启，回退 64KB，但要提示
        print(_MAX_PAYLOAD_WARNING, file=sys.stderr)

    if _MAX_INFLIGHT_WARNING:  # 铁律 3/5：在途上限坏值不拒启，回退 8，但要提示
        print(_MAX_INFLIGHT_WARNING, file=sys.stderr)

    # 设备适配器支持直连、但 DEVICE_TOKEN 没设 -> /device 实际被禁用，醒目
    # 提示 + 指路怎么启用。仅在"本该能用却因缺 token 用不了"时提示；Mock 这类不支持
    # 直连的适配器不需要 DEVICE_TOKEN，不提示（免得误导）。
    if device.supports_direct_connection and not DEVICE_TOKEN:
        print(
            "[bodybridge] warning: /device is disabled because "
            "BODYBRIDGE_DEVICE_TOKEN is not set.\n"
            "  The device layer is active but no device can connect until you set it.\n"
            "  Set it (PowerShell):  $env:BODYBRIDGE_DEVICE_TOKEN = 'your-device-secret'",
            file=sys.stderr,
        )

    # 无条件打印：实际监听地址 + 端口来自哪个变量，排障第一眼就看得到（铁律 4）。
    print(f"[bodybridge] starting on {HOST}:{PORT} (port source: {_PORT_SOURCE})",
          file=sys.stderr)
    print(f"[bodybridge] client registration mode: {CLIENT_REGISTRATION}",
          file=sys.stderr)

    app = mcp.streamable_http_app()

    # 第 3 层设备端点：始终注册；放不放行由 _device_endpoint 内部判断（当前设备是否
    # 支持直连、DEVICE_TOKEN 是否设、Bearer 是否通过）。挂在 app.router 上、早于
    # uvicorn.run。用 routes.append 显式挂（等价于 app.router.add_websocket_route，
    # 这里选更直白的形式，一眼看出挂的是一条 WebSocketRoute）。
    app.router.routes.append(WebSocketRoute("/device", _device_endpoint))

    # 包裹（而非替换）SDK 写死的 lifespan：在它前后插入 setup/teardown。
    # 这样两件事都跑在 uvicorn 的事件循环里，且 SDK 一行没动（桥身求薄）。
    _inner_lifespan = app.router.lifespan_context

    @contextlib.asynccontextmanager
    async def lifespan(app):
        await _boot_device()              # 早于第一个请求
        try:
            async with _inner_lifespan(app):   # SDK 原有 lifespan 照常
                yield
        finally:
            await _shutdown_device()      # 进程退出前兜底清理

    app.router.lifespan_context = lifespan

    app.add_middleware(BearerAuthMiddleware, token=TOKEN)
    uvicorn.run(
        app, host=HOST, port=PORT,
        # 第 3 层 /device 的 WebSocket 参数（读入的配置在这里被消费）。
        # 显式 ws="websockets-sansio"：这个实现会认 ws_ping_interval 并真的自动发
        # 服务端 ping（keepalive），pong 超时则关连 -> 端点收到 disconnect 事件 ->
        # finally 里 detach 立刻标 offline。不用弃用的 ws="websockets"（会打弃用警告、
        # 且未来 uvicorn 会让那个名字悄悄改指向 sansio，等于把易变名字写死，违背铁律 6）。
        ws="websockets-sansio",
        ws_ping_interval=HEARTBEAT_SECONDS,   # 心跳：每 N 秒自动发协议级 ping
        ws_max_size=MAX_PAYLOAD_BYTES,        # 载荷硬护盾，超限以 close 1009 关连
        # ⚠️ sansio 实现忽略 ws_max_queue，退回库默认队列上限；我们靠收帧循环持续
        # drain 保证队列不堆积，这个上界只是冗余的内存兜底，失效不影响正确性。
        ws_max_queue=DEVICE_MAX_QUEUE,
        # ws_ping_timeout 不传：用 uvicorn 默认（20s）——决策 Q2 定的"不单开这个旋钮"。
    )
