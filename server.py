"""bodybridge — MCP Server 层 + 鉴权守门层（最小可跑版本）"""
import contextlib
import html
import os
import sys
from urllib.parse import quote as urlquote, urlsplit

import uvicorn
from mcp.server.fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse

import oauth_cimd
from adapters.base import DeviceAdapter, DeviceResult
from adapters.mock import MockAdapter

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
# TOKEN 同一先例：第 5 步接完中间件后，没密码这条 OAuth 路径就是废的，fail fast
# 比"桥能起但神秘地授权不了"诚实）。
PASSWORD = os.environ.get("BODYBRIDGE_PASSWORD", "").strip()

# 可选：CIMD 抓取的 host 白名单。默认空 = 通用防护（不限 host，但下面一系列
# SSRF 防护照做）；设了就只放行这些 host，给想锁死的用户自由。
_raw_cimd_allowlist = os.environ.get("BODYBRIDGE_CIMD_ALLOWLIST", "").strip()
CIMD_ALLOWLIST = (
    frozenset(h.strip() for h in _raw_cimd_allowlist.split(",") if h.strip())
    if _raw_cimd_allowlist else None
)


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


def _esc(value) -> str:
    """所有回显到 HTML 里的用户输入/远端数据，一律转义。内联拼 HTML 就是
    XSS 温床——state、client_id、client_name（来自远端 CIMD 文档，不可信）
    都必须过这一道。"""
    return html.escape(str(value), quote=True)


def _authorize_error_page(message: str, status: int = 400) -> HTMLResponse:
    """前 4 项校验失败用这个：直接报错，绝不重定向（redirect_uri 还不可信）。"""
    body = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>bodybridge - Authorization Error</title></head>
<body style="font-family:sans-serif;max-width:32rem;margin:4rem auto;color:#222">
<h2>Authorization request rejected</h2>
<p>{_esc(message)}</p>
</body></html>"""
    return HTMLResponse(body, status_code=status, headers=_AUTHORIZE_HEADERS)


def _authorize_form_html(*, client_id, client_name, redirect_uri, state,
                          code_challenge, code_challenge_method, resource,
                          error: str = "") -> str:
    err_html = f'<p style="color:#b00020">{_esc(error)}</p>' if error else ""
    resource_field = (
        f'<input type="hidden" name="resource" value="{_esc(resource)}">'
        if resource else ""
    )
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>bodybridge - Authorize</title></head>
<body style="font-family:sans-serif;max-width:24rem;margin:4rem auto;color:#222">
<h2>Authorize {_esc(client_name)}</h2>
<p>This app wants to connect to your bodybridge.</p>
<form method="POST">
<input type="hidden" name="client_id" value="{_esc(client_id)}">
<input type="hidden" name="redirect_uri" value="{_esc(redirect_uri)}">
<input type="hidden" name="state" value="{_esc(state)}">
<input type="hidden" name="code_challenge" value="{_esc(code_challenge)}">
<input type="hidden" name="code_challenge_method" value="{_esc(code_challenge_method)}">
{resource_field}
<input type="password" name="password" placeholder="Bridge password" autofocus>
<button type="submit">Authorize</button>
</form>
{err_html}
</body></html>"""


def _redirect_with(redirect_uri: str, params: dict) -> RedirectResponse:
    """拼接重定向 URL；跟 OB 一样的 sep 判断写法，外加 Cache-Control: no-store
    （OAuth 规范要求：带授权码/错误信息的响应不能被缓存）。"""
    sep = "&" if "?" in redirect_uri else "?"
    query = "&".join(
        f"{k}={urlquote(str(v))}" for k, v in params.items() if v
    )
    location = f"{redirect_uri}{sep}{query}" if query else redirect_uri
    return RedirectResponse(location, status_code=302,
                             headers={"Cache-Control": "no-store"})


def _validate_authorize_request(params: dict):
    """校验 /oauth/authorize 的参数。GET、POST 共用同一份逻辑——POST 的隐藏字段
    不被信任，原样重新走一遍这里，而不是假设 GET 已经验过了（这正是绕开 OB 那个
    "client_info 为 None 时跳过 redirect_uri 校验"缺口的关键：我们没有本地注册表
    可查，CIMD fetch 本身就是唯一的"注册检查"，不允许有跳过路径）。

    返回 (stage, payload)：
      "trusted_error"  -> payload 是 HTMLResponse，直接返回，不重定向
      "redirect_error"  -> payload 是 (redirect_uri, error, description)
      "ok"              -> payload 是校验通过的字典
    """
    client_id = params.get("client_id", "")
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

    redirect_uri = params.get("redirect_uri", "")
    if redirect_uri not in fetch.document.get("redirect_uris", []):
        return "trusted_error", _authorize_error_page(
            "redirect_uri does not match any redirect_uris in the client's "
            "metadata document."
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
        "client_name": fetch.document.get("client_name", client_id),
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
        try:
            form = await request.form()
        except Exception:
            return _authorize_error_page("could not parse form submission.")
        params = {k: str(v) for k, v in form.items()}

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
    claims = oauth_cimd.redeem_authorization_code(TOKEN, code, _used_code_jtis)
    if (
        claims is None
        or client_id != claims.get("client_id")
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
    if effective_resource and effective_resource != expected_resource:
        return _token_error(
            "invalid_target",
            f'expected resource "{expected_resource}", got "{effective_resource}"',
        )

    token, expires_in = oauth_cimd.issue_access_token(
        TOKEN,
        issuer=PUBLIC_URL,
        audience=expected_resource,
        subject=client_id,
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
# 第 5 步（OAuth 改造收尾）：这里不再是"比对固定 BODYBRIDGE_TOKEN 字符串"，
# 而是验第 4 步签发的 JWT——签名 + exp + aud + iss 全部显式校验（见
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
            return "缺少 Authorization 头，请带上 'Bearer <你的 token>'"
        try:
            auth = auth_bytes.decode("latin-1")  # ASGI 里 header 就是 latin-1，永不抛
        except Exception:
            return "Authorization 头无法解析"
        parts = auth.split(" ", 1)
        if len(parts) != 2 or parts[0].lower() != "bearer":
            return "Authorization 头格式应为 'Bearer <token>'"
        if not _verify_bearer_token(parts[1].strip()):
            # 签名错/已过期/aud 不符/iss 不符/格式畸形——统一这一句，不细分
            # 具体原因（防信息泄露，延续第 4 步 /oauth/token 的同一策略）。
            return "token 无效或已过期，请重新完成 OAuth 授权（从 /oauth/authorize 开始）以获取新 token"
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

    if _PUBLIC_URL_WARNING:  # 铁律 5：PUBLIC_URL 缺失/坏值不拒启，但要醒目提示
        print(_PUBLIC_URL_WARNING, file=sys.stderr)

    if _TOKEN_TTL_WARNING:  # 铁律 3/5：TTL 坏值不拒启，但要醒目提示
        print(_TOKEN_TTL_WARNING, file=sys.stderr)

    if _PORT_WARNING:  # 铁律 3/5：端口坏值不拒启，跳过它、试下一优先级，但要提示
        print(_PORT_WARNING, file=sys.stderr)

    # 无条件打印：实际监听地址 + 端口来自哪个变量，排障第一眼就看得到（铁律 4）。
    print(f"[bodybridge] listening on {HOST}:{PORT} (port source: {_PORT_SOURCE})",
          file=sys.stderr)

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
