"""bodybridge — MCP Server 层 + 鉴权守门层（最小可跑版本）"""
import contextlib
import hmac
import os
import sys

import uvicorn
from mcp.server.fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import JSONResponse

from adapters.base import DeviceAdapter, DeviceResult
from adapters.mock import MockAdapter

# 铁律 5/6：host/port 可配置，带合理默认值
HOST = os.environ.get("BODYBRIDGE_HOST", "127.0.0.1")
PORT = int(os.environ.get("BODYBRIDGE_PORT", "8000"))

# 铁律 5：token 是鉴权必填项，没有安全默认值，走"明确必填提示"这条腿
TOKEN = os.environ.get("BODYBRIDGE_TOKEN", "").strip()


def _resolve_public_url() -> tuple[str, str | None]:
    """解析桥的公网基址，供 OAuth 元数据（RFC 9728/8414）用。
    返回 (基址_去尾斜杠, 警告文案_或_None)。

    铁律 3/5：显式配置优先；缺失或坏值绝不崩服务——回退到本地地址并把一句
    ASCII 警告交回给 __main__ 打印（本地控制台可能是 GBK，输出必须纯 ASCII）。
    """
    raw = os.environ.get("BODYBRIDGE_PUBLIC_URL", "").strip()
    local = f"http://{HOST}:{PORT}"
    if not raw:
        return local, (
            "[bodybridge] warning: BODYBRIDGE_PUBLIC_URL is not set; "
            f"falling back to {local} for OAuth metadata.\n"
            "  CIMD discovery from claude.ai needs a PUBLIC https base URL.\n"
            "  Set it for real deployment: "
            "BODYBRIDGE_PUBLIC_URL=https://bridge.example.com"
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
# 桥身只依赖抽象 DeviceAdapter，不认具体设备。换真设备只改下面这一行实例化，
# 三个工具、_safe、整个桥身都不动 —— 这就是依赖倒置 + 桥身求薄。
device: DeviceAdapter = MockAdapter()


async def _safe(coro) -> dict:
    """安全网：Adapter 万一漏抛异常，也兜成友好信封，保证服务永不 500。
    设备级失败走的是 ok=False 的正常返回（不是 isError），从根上避开
    MCP 的 isError/outputSchema 撞车坑。"""
    try:
        return (await coro).to_dict()
    except Exception as e:
        return DeviceResult.failure(
            "internal_error",
            f"设备适配器内部异常，已兜底（{type(e).__name__}）。",
            retryable=True,
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
    """RFC 8414 授权服务器元数据。"""
    return JSONResponse({
        "issuer": PUBLIC_URL,
        "authorization_endpoint": f"{PUBLIC_URL}/oauth/authorize",
        "token_endpoint": f"{PUBLIC_URL}/oauth/token",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "client_id_metadata_document_supported": True,
        "scopes_supported": ["mcp"],
        # 故意不声明 registration_endpoint：我们走 CIMD，不做 DCR。
    })


# --- 鉴权守门层（第 2 层）---------------------------------------------------
# 纯 ASGI 中间件：请求进来时只看一眼 Authorization 头，要么当场 401、要么原样
# 放行，完全不碰响应流（避免 BaseHTTPMiddleware 掐断 streamable-http 的 SSE 长流）。
# 因为 stateless_http，每次 MCP 调用都是独立 HTTP 请求，所以这里天然做到"每个请求
# 都验"，而不是只在握手时验一次。


def _token_matches(presented: str, expected: str) -> bool:
    """常量时间比对，防时序攻击。两边都 encode 成 bytes，全角等非 ASCII 字符
    只会匹配不上，绝不抛异常、绝不崩。任何意外都归为"不匹配"。"""
    try:
        return hmac.compare_digest(presented.encode("utf-8"), expected.encode("utf-8"))
    except Exception:
        return False


def _unauthorized(message: str) -> JSONResponse:
    """401 + 说人话的错误，附标准 WWW-Authenticate 头。"""
    return JSONResponse(
        {"error": "unauthorized", "message": message},
        status_code=401,
        headers={"WWW-Authenticate": "Bearer"},
    )


# OAuth 发现/授权端点必须公开（Claude 拿 token 前就要访问），这里前缀匹配放行。
# str.startswith 接受元组，任一前缀命中即公开。/oauth/* 现在还没建（404）也无妨。
_PUBLIC_PATH_PREFIXES = (
    "/.well-known/oauth-protected-resource",
    "/.well-known/oauth-authorization-server",
    "/oauth/authorize",
    "/oauth/token",
)


class BearerAuthMiddleware:
    def __init__(self, app, token: str):
        self.app = app
        self.token = token

    def _reason_to_reject(self, auth_bytes) -> str | None:
        """返回一句人话说明为何拒绝；返回 None 表示放行。防御性处理各种坏输入。"""
        if not auth_bytes:
            return "缺少 Authorization 头，请带上 'Bearer <你的 token>'"
        try:
            auth = auth_bytes.decode("latin-1")  # ASGI 里 header 就是 latin-1，永不抛
        except Exception:
            return "Authorization 头无法解析"
        parts = auth.split(" ", 1)
        if len(parts) != 2 or parts[0].lower() != "bearer":
            return "Authorization 头格式应为 'Bearer <token>'"
        if not _token_matches(parts[1].strip(), self.token):
            return "token 无效，请确认与服务端 BODYBRIDGE_TOKEN 一致"
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

    if _PUBLIC_URL_WARNING:  # 铁律 5：PUBLIC_URL 缺失/坏值不拒启，但要醒目提示
        print(_PUBLIC_URL_WARNING, file=sys.stderr)

    app = mcp.streamable_http_app()

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
    uvicorn.run(app, host=HOST, port=PORT)
