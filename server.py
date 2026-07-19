"""bodybridge — MCP Server 层 + 鉴权守门层（最小可跑版本）"""
import contextlib
import hmac
import os
import sys

import uvicorn
from mcp.server.fastmcp import FastMCP
from starlette.responses import JSONResponse

from adapters.base import DeviceAdapter, DeviceResult
from adapters.mock import MockAdapter

# 铁律 5/6：host/port 可配置，带合理默认值
HOST = os.environ.get("BODYBRIDGE_HOST", "127.0.0.1")
PORT = int(os.environ.get("BODYBRIDGE_PORT", "8000"))

# 铁律 5：token 是鉴权必填项，没有安全默认值，走"明确必填提示"这条腿
TOKEN = os.environ.get("BODYBRIDGE_TOKEN", "").strip()

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
