"""CIMD 客户端发现 + SSRF 安全抓取 + 无状态签名授权码 + PKCE 校验 + JWT 签发/验证。

这个模块只依赖标准库、httpcore 和 PyJWT（都是 mcp[cli] 的直接依赖，见
uv.lock 里 mcp 包自己声明 pyjwt[crypto]，无新增依赖）。不依赖 server.py，
方便独立单测（尤其是签名码的一次性消费逻辑、PKCE 比对、JWT claims）。

SSRF 防护的核心手法："解析一次、校验那个 IP、就连那个已校验的 IP"——
不是校验域名字符串、也不是校验后重新解析再连接（后者正是 DNS rebinding
能钻的空子：两次解析可能拿到不同结果）。校验用 Python 的 ipaddress 模块
（标准解析，不是正则/字符串匹配），躲开 GitHub 那次 webhook SSRF 事故里
"解析库和连接库对 IP 写法认知不一致"的坑。
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import socket
import time
from dataclasses import dataclass
from ipaddress import ip_address
from re import compile as _re_compile
from urllib.parse import urlsplit

import httpcore
import jwt

# CIMD draft §6.6 建议上限 5KB；这里放宽到 16KB 留余量，但仍是硬上限。
_MAX_RESPONSE_BYTES = 16 * 1024
# 连接+读取合计的宽松上限（秒）。
_FETCH_TIMEOUT_SECONDS = 4.0
_REQUIRED_FIELDS = ("client_id", "client_name", "redirect_uris")

# RFC 7636 code_challenge 语法：base64url 字符集，43-128 字符。
_CODE_CHALLENGE_RE = _re_compile(r"^[A-Za-z0-9._~-]{43,128}$")


def _read_project_version() -> str:
    """从仓库根目录的 pyproject.toml 读版本号，拼进 CIMD fetch 的 User-Agent
    ——诚实标识自己是谁，不伪装浏览器（猫鼠游戏没有尽头，对方随时能升级识别；
    诚实标识才是负责任的默认做法）。任何失败（文件不存在、格式异常、tomllib
    在这个 Python 版本上不存在等）一律回退到安全默认值，绝不因为读版本号
    这种小事崩服务（铁律 3）——User-Agent 里带个占位版本号，总比整个 fetch
    直接失败强。
    """
    default = "0.0.0"
    try:
        path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "pyproject.toml"
        )
        with open(path, "rb") as f:
            raw = f.read()
    except Exception:
        return default
    try:
        import tomllib
        version = tomllib.loads(raw.decode("utf-8")).get("project", {}).get("version")
        if isinstance(version, str) and version.strip():
            return version.strip()
    except Exception:
        pass
    try:
        import re as _re_module
        m = _re_module.search(rb'^\s*version\s*=\s*"([^"]+)"', raw, _re_module.MULTILINE)
        if m:
            return m.group(1).decode("utf-8", "replace")
    except Exception:
        pass
    return default


_PROJECT_VERSION = _read_project_version()
# CIMD fetch 用的出站 User-Agent：诚实标识 bodybridge 自己，不伪装浏览器。
_CIMD_FETCH_USER_AGENT = (
    f"bodybridge/{_PROJECT_VERSION} (+https://github.com/alice-jin-dev/bodybridge)"
).encode("ascii", "replace")


def safe_compare(a: str, b: str) -> bool:
    """常量时间比对，绝不因奇怪输入抛异常。

    铁律 3 血泪：hmac.compare_digest 两个参数都是 str 时要求全 ASCII，
    含全角等非 ASCII 字符会抛 TypeError（OB 的 _verify_any_password 正是
    栽在这——裸调用、无 try/except，一个全角密码就能把它 500 掉）。这里统一
    先编码成 utf-8 bytes 再比，外面套 try/except，任何异常一律归"不匹配"，
    绝不上抛。token 比对、密码比对、签名比对，全走这一个函数。
    """
    try:
        return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))
    except Exception:
        return False


def is_valid_code_challenge(value: str) -> bool:
    """PKCE code_challenge 的语法校验：必须是 43-128 字符的 base64url 字符集。"""
    return isinstance(value, str) and bool(_CODE_CHALLENGE_RE.fullmatch(value))


# --- SSRF 安全抓取 -----------------------------------------------------------


def _is_disallowed_ip(ip) -> bool:
    """私有/环回/链路本地/保留/组播/未指定地址一律拒绝（覆盖 IPv4 和 IPv6，
    含 ::ffff: 映射的 IPv4 地址——不解开映射就检查，会漏放行一个内网地址）。"""
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def _resolve_and_pin(hostname: str, port: int) -> tuple[str | None, str | None]:
    """解析 hostname，校验*每一个*解析结果都不是私有/内部地址（只要有一个是坏的，
    整个域名判定不可信——这正是防 DNS rebinding 的关键：不是"挑一个好的用"，
    而是"混进一个坏的就全拒"）。返回 (已校验的 IP, None) 或 (None, 拒绝原因)。
    这个 IP 会被原样用于实际连接，绝不重新解析——重新解析正是 rebinding 的缺口。
    """
    try:
        infos = socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP)
    except Exception as e:
        return None, f"DNS resolution failed for '{hostname}' ({type(e).__name__})"
    if not infos:
        return None, f"DNS resolution returned no addresses for '{hostname}'"

    candidates: list[str] = []
    for _family, _type, _proto, _canon, sockaddr in infos:
        raw_ip = sockaddr[0]
        try:
            ip = ip_address(raw_ip)
        except ValueError:
            return None, f"resolved address '{raw_ip}' is not a parseable IP"
        if _is_disallowed_ip(ip):
            return None, (
                f"resolved address '{raw_ip}' is private/loopback/link-local/"
                f"reserved -- blocked by SSRF guard"
            )
        candidates.append(raw_ip)
    return candidates[0], None


class _PinnedStream(httpcore.NetworkStream):
    """包一层原始 socket。TLS 升级（start_tls）时的 server_hostname 由调用方
    （httpcore 连接池）传入的是*原始域名*（不是我们连的 IP），所以证书校验/SNI
    完全正常——我们只决定"TCP 连去哪个 IP"，不碰"证书验哪个域名"这件事。"""

    def __init__(self, sock: socket.socket) -> None:
        self._sock = sock

    def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        self._sock.settimeout(timeout)
        return self._sock.recv(max_bytes)

    def write(self, buffer: bytes, timeout: float | None = None) -> None:
        self._sock.settimeout(timeout)
        self._sock.sendall(buffer)

    def close(self) -> None:
        self._sock.close()

    def start_tls(self, ssl_context, server_hostname=None, timeout=None):
        self._sock.settimeout(timeout)
        wrapped = ssl_context.wrap_socket(self._sock, server_hostname=server_hostname)
        return _PinnedStream(wrapped)

    def get_extra_info(self, info: str):
        return None


class _PinnedNetworkBackend(httpcore.NetworkBackend):
    """只重写 connect_tcp：忽略传入的 host（原始域名），直接拨已校验的 IP。
    子类化的是 httpcore 公开导出的 NetworkBackend/NetworkStream（不是
    httpcore._backends.sync 里的私有实现），不依赖第三方库的内部实现细节。"""

    def __init__(self, pinned_ip: str) -> None:
        self._pinned_ip = pinned_ip

    def connect_tcp(self, host, port, timeout=None, local_address=None,
                     socket_options=None):
        sock = socket.create_connection(
            (self._pinned_ip, port), timeout=timeout,
            source_address=None if local_address is None else (local_address, 0),
        )
        for option in socket_options or ():
            sock.setsockopt(*option)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        return _PinnedStream(sock)


@dataclass
class CIMDResult:
    ok: bool
    document: dict | None = None
    error: str | None = None


def fetch_cimd_document(url: str, *, allowlist_hosts=None) -> CIMDResult:
    """按 CIMD draft 校验并抓取一份客户端元数据文档。

    allowlist_hosts: 非空则只放行其中的 host（BODYBRIDGE_CIMD_ALLOWLIST）；
    None/空 = 通用防护（不限 host，但下面这些防护照做）。
    """
    parts = urlsplit(url)
    if parts.scheme != "https":
        return CIMDResult(False, error="client_id must use the https:// scheme")
    hostname = parts.hostname
    if not hostname:
        return CIMDResult(False, error="client_id URL has no host component")
    if not parts.path or parts.path == "/":
        return CIMDResult(False, error="client_id URL must contain a path component")

    if allowlist_hosts and hostname not in allowlist_hosts:
        return CIMDResult(
            False,
            error=f"host '{hostname}' is not in BODYBRIDGE_CIMD_ALLOWLIST",
        )

    port = parts.port or 443
    pinned_ip, reason = _resolve_and_pin(hostname, port)
    if pinned_ip is None:
        return CIMDResult(False, error=f"SSRF guard blocked the fetch: {reason}")

    try:
        host_header = hostname.encode("idna")
    except Exception:
        return CIMDResult(False, error="client_id host name is not a valid domain")

    body = bytearray()
    status = None
    pool = httpcore.ConnectionPool(
        network_backend=_PinnedNetworkBackend(pinned_ip),
        max_connections=1,
        retries=0,
    )
    try:
        with pool.stream(
            "GET",
            url,
            headers=[
                (b"host", host_header),
                (b"user-agent", _CIMD_FETCH_USER_AGENT),
                (b"accept", b"application/json"),
            ],
            extensions={"timeout": {
                "connect": _FETCH_TIMEOUT_SECONDS,
                "write": _FETCH_TIMEOUT_SECONDS,
                "read": _FETCH_TIMEOUT_SECONDS,
                "pool": _FETCH_TIMEOUT_SECONDS,
            }},
        ) as response:
            status = response.status
            if status == 200:
                for chunk in response.stream:
                    body.extend(chunk)
                    if len(body) > _MAX_RESPONSE_BYTES:
                        return CIMDResult(
                            False,
                            error="client metadata document exceeds the size limit",
                        )
    except Exception as e:
        return CIMDResult(False, error=f"fetch failed ({type(e).__name__}): {e}")
    finally:
        pool.close()

    if status != 200:
        return CIMDResult(
            False,
            error=f"client metadata fetch returned HTTP {status} (expected 200; "
                  f"redirects are never followed)",
        )

    try:
        doc = json.loads(bytes(body).decode("utf-8"))
    except Exception:
        return CIMDResult(False, error="client metadata response is not valid JSON")

    return validate_cimd_document(doc, url)


def validate_cimd_document(doc, url: str) -> CIMDResult:
    """纯字段校验，和网络抓取分离，方便单测"happy path"而不用真的发请求。"""
    if not isinstance(doc, dict):
        return CIMDResult(False, error="client metadata is not a JSON object")
    for field in _REQUIRED_FIELDS:
        if field not in doc:
            return CIMDResult(False, error=f"client metadata missing required field '{field}'")
    redirect_uris = doc.get("redirect_uris")
    if not isinstance(redirect_uris, list) or not redirect_uris:
        return CIMDResult(False, error="client metadata 'redirect_uris' must be a non-empty list")
    if not all(isinstance(u, str) for u in redirect_uris):
        return CIMDResult(False, error="client metadata 'redirect_uris' must be a list of strings")
    # CIMD draft §4.1：client_id 必须与拉取它的 URL 逐字符相等（简单字符串比较）。
    if doc.get("client_id") != url:
        return CIMDResult(False, error="client metadata 'client_id' does not match the fetch URL")
    return CIMDResult(True, document=doc)


# --- 无状态签名授权码 ---------------------------------------------------------


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def hash_client_id(client_id: str) -> str | None:
    """client_id 是"标识"，不是"载荷"——JWT/签名 claims 该放标识，不是数据
    容器。但我们的 client_id（尤其 dcr 模式下）本身就是自签名串，把
    redirect_uris/client_name 都编码在里面（实测 194 字符）；如果 code、
    access_token 里原样存一份完整 client_id，claims 体积会跟着 client_id
    膨胀——access_token 还要在后续 7 天里跟着每次请求重发一遍，这是最贵的
    一份。这里换成固定 43 字符的 SHA-256 base64url 摘要：不管 client_id
    本身多长，claims 体积都不再随它变化，紧凑性是 JWT 的设计前提。

    只需要"确认 token 阶段出示的 client_id 与 authorize 阶段是同一个"，
    摘要足够——不需要也不该在 code/token 里携带 client_id 的全部内容。

    任何异常一律返回 None，绝不上抛（铁律 3：client_id 在这里仍是外部输入，
    调用方比较时 None 天然不会等于任何真实哈希值，安全地导致"不匹配"）。
    """
    try:
        return _b64url_encode(hashlib.sha256(client_id.encode("utf-8")).digest())
    except Exception:
        return None


def issue_authorization_code(secret: str, *, client_id: str, redirect_uri: str,
                              code_challenge: str, code_challenge_method: str,
                              resource: str | None, ttl_seconds: float,
                              now: float | None = None) -> str:
    """签一个自包含授权码（HMAC-SHA256，不是 JWT 库——手写省掉 alg 混淆攻击面，
    反正只有我们自己签、自己验，不需要跟第三方互操作）。签的是"防篡改+限时效"，
    "有没有被兑换过"这件事签名本身答不了，见 redeem_authorization_code。

    claims 里存的是 client_id_hash（见 hash_client_id），不是 client_id 原文
    ——防止 code 体积跟着 client_id 膨胀。"""
    now = time.time() if now is None else now
    claims = {
        "client_id_hash": hash_client_id(client_id),
        "redirect_uri": redirect_uri,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "resource": resource,
        "iat": now,
        "exp": now + ttl_seconds,
        "jti": secrets.token_urlsafe(16),
    }
    payload_b64 = _b64url_encode(json.dumps(claims, separators=(",", ":")).encode("utf-8"))
    sig = hmac.new(secret.encode("utf-8"), payload_b64.encode("ascii"), hashlib.sha256).digest()
    return f"{payload_b64}.{_b64url_encode(sig)}"


def redeem_authorization_code(secret: str, code: str, used_jtis: dict,
                               *, now: float | None = None) -> dict | None:
    """验签+验时效+验一次性。used_jtis 是调用方持有的模块级 dict（jti -> 过期时间），
    这里原地增删；函数内没有 await，asyncio 协作式调度下"查+标记"这两步不会被
    别的请求插进来，天然原子。

    这是"完全无状态做不到真一次性"的折中：claims 本身无状态自包含，但重放防护
    需要这一点极小的、自我过期的状态——不是长期 session，是几十秒 TTL 的用过标记。
    任何校验失败都返回 None，绝不抛异常。
    """
    now = time.time() if now is None else now
    for jti, exp in list(used_jtis.items()):
        if exp < now:
            del used_jtis[jti]  # 过期的用过标记顺手清掉，防止无界增长

    try:
        payload_b64, sig_b64 = code.split(".", 1)
    except Exception:
        return None

    try:
        expected_sig = hmac.new(
            secret.encode("utf-8"), payload_b64.encode("ascii"), hashlib.sha256
        ).digest()
        expected_sig_b64 = _b64url_encode(expected_sig)
    except Exception:
        return None
    if not safe_compare(sig_b64, expected_sig_b64):
        return None

    try:
        claims = json.loads(_b64url_decode(payload_b64).decode("utf-8"))
    except Exception:
        return None
    if not isinstance(claims, dict):
        return None

    exp = claims.get("exp")
    jti = claims.get("jti")
    if not isinstance(exp, (int, float)) or not isinstance(jti, str) or not jti:
        return None
    if exp < now:
        return None
    if jti in used_jtis:
        return None  # 已经兑换过一次，拒绝重放

    used_jtis[jti] = exp
    return claims


# --- PKCE 校验 + JWT 签发（/oauth/token 用）---------------------------------


def verify_pkce_challenge(code_verifier: str, code_challenge: str) -> bool:
    """RFC 7636 §4.6：用 code_verifier 算出 S256 challenge
    （BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))，见 §4.2），跟存的
    code_challenge 比对。

    常量时间比较：这里比的是两个哈希摘要，不是裸密码——SHA256 的雪崩效应决定
    "逐字节猜哈希输出"这类时序攻击在实践中不可行，风险量级跟直接比密码不是
    一回事。但用 safe_compare 的代价是零，且能跟项目里"这一类比较统一走一个
    安全函数"的做法保持一致，所以照样用它，不是因为这里有实际可利用的时序漏洞。

    任何异常（含 code_verifier 含非 ASCII 字符导致 encode 失败）一律归"不匹配"，
    绝不上抛——跟 safe_compare 同一套"防崩"哲学，调用方不需要在这之前单独做
    格式校验，喂什么进来都不会崩，格式不对自然计算不出匹配的结果。
    """
    try:
        digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
        computed = _b64url_encode(digest)
    except Exception:
        return False
    return safe_compare(computed, code_challenge)


def issue_access_token(secret: str, *, issuer: str, audience: str, subject: str,
                        ttl_seconds: float, now: float | None = None) -> tuple[str, int]:
    """签发无状态 JWT access token（HS256）。返回 (token, expires_in 整数秒)。

    算法选 HS256：签发（这里）和验证（第 5 步的 MCP 中间件）是同一个进程，
    非对称签名的价值在于"验证方不必持有签名密钥"，这里用不上，只会平添密钥对
    生成/轮换/存储的复杂度（违背桥身求薄）。

    防 alg 混淆：这里签发时显式指定 algorithm="HS256"，不读取任何外部输入去
    决定算法。第 5 步验证时必须同样显式传 algorithms=["HS256"]（不是从 token
    自己的头部读 alg 来决定用什么密钥/算法校验）——这不是"建议"，是 PyJWT 2.x
    的结构性强制：不传 algorithms 参数，jwt.decode() 直接抛 DecodeError，库
    从设计上不给"偷懒读 alg 字段"的选项。这里只负责稳定地只用这一种算法签。
    """
    now = time.time() if now is None else now
    exp = now + ttl_seconds
    claims = {
        "iss": issuer,
        "aud": audience,
        "sub": subject,
        "iat": int(now),
        "exp": int(exp),
        "jti": secrets.token_urlsafe(16),
    }
    token = jwt.encode(claims, secret, algorithm="HS256")
    return token, int(ttl_seconds)


def verify_access_token(secret: str, token: str, *, audience: str,
                         issuer: str) -> dict | None:
    """验一个 issue_access_token 签发的 JWT：签名 + exp（PyJWT 默认校验，没被
    关掉）+ aud + iss，全部显式声明，绝不读 token 自称的 alg 去决定校验方式——
    algorithms=["HS256"] 是唯一允许的算法，不传这个参数 PyJWT 本身就拒绝执行
    （见 issue_access_token 的说明），从设计上堵死"偷懒读 alg 字段"这条路。

    aud 必须精确等于我们自己的资源 URI（MCP 授权规范："MCP servers MUST
    validate that access tokens were issued specifically for them as the
    intended audience" 且 "MUST NOT accept or transit any other tokens"）；
    iss 必须等于 PUBLIC_URL，跟第 1 步 AS 元数据的 issuer 一致。

    任何失败（签名错、过期、aud 不符、iss 不符、格式畸形、任何异常——包括
    调用方喂进来空值/超长串/全角字符/二进制乱码/畸形 JWT）一律返回 None，
    不区分具体原因（调用方据此统一报"token 无效"，不泄露细节是哪一种失败），
    也绝不上抛（铁律 3）。
    """
    try:
        return jwt.decode(
            token, secret, algorithms=["HS256"], audience=audience, issuer=issuer,
        )
    except Exception:
        return None


# --- 无状态动态客户端注册（DCR，RFC 7591）------------------------------------
#
# 这不是变通，是规范明确认可的模式：
#   - RFC 7591 附录 A.5.2 标题即 "Stateless Client Registration"，与 A.5.1
#     有状态注册并列，是官方承认的另一种合规实现方式。
#   - OpenID Connect DCR 1.0 §8.2「Implementation Notes on Stateless Dynamic
#     Client Registration」原文："In some deployments, it is advantageous to
#     enable Clients to obtain the information necessary to interact with
#     the Authorization Server ... without the requirement that state about
#     the Client be stored at the Authorization Server ... One means of
#     doing this is to encode necessary registration information about the
#     Client into the client_id value returned."
#   - IETF 草案 draft-bradley-oauth-stateless-client-id（作者是 RFC 7591 的
#     同一批人）：client_id 对客户端本就不透明，无状态 client_id 的获取与
#     使用方式与有状态完全相同。
#
# 走 DCR 而不是 CIMD 的原因：CIMD 要求桥主动出站访问客户端声明的 URL，受制于
# 对方 WAF/我方出口 IP 信誉（实测 claude.ai 的 CIMD 文档被 Cloudflare JS 挑战
# 拦下，403）；DCR 是客户端主动入站 POST 到我们，不需要任何出站请求，从根上
# 避开这类问题。

_MAX_REDIRECT_URIS = 10
_MAX_CLIENT_ID_LENGTH = 4000
_MAX_CLIENT_NAME_LENGTH = 200


@dataclass
class DCRValidationResult:
    ok: bool
    redirect_uris: list | None = None
    client_name: str | None = None
    error: str | None = None              # RFC 7591 §3.2.2 错误码
    error_description: str | None = None


def _is_acceptable_redirect_uri(uri) -> bool:
    """MCP 授权规范原文："All redirect URIs MUST be either localhost or use
    HTTPS"。https:// 一律放行；http:// 只放行 localhost/127.0.0.1 回环形式。
    任何异常输入（非字符串、解析失败）一律归"不合规"，绝不上抛。"""
    if not isinstance(uri, str) or not uri:
        return False
    try:
        parts = urlsplit(uri)
    except Exception:
        return False
    if parts.scheme == "https" and parts.hostname:
        return True
    if parts.scheme == "http" and parts.hostname in ("localhost", "127.0.0.1"):
        return True
    return False


def validate_registration_request(body) -> DCRValidationResult:
    """RFC 7591 §3.1 请求字段校验 + §3.2.2 错误码。

    这是 OB 的真空白——它的 /oauth/register 对 body.get("redirect_uris", [])
    不做任何检查（非空？不查。是不是列表？不查。每项是不是合法 URL？不查），
    RFC 7591 §3.2.2 明明白白给了 invalid_redirect_uri / invalid_client_metadata
    这两个专用错误码就是为了这种情况，这里把它们用足。

    body 是完全不可信的外部 JSON（可能不是 dict、可能是深层嵌套的怪结构、
    可能字段类型完全对不上）——整个函数用一层 try/except 兜底，任何异常都
    归为校验失败，绝不上抛（铁律 3）；register 是给实现者用的端点、不是攻击
    敏感面，error_description 可以说清楚哪里不合规（铁律 4）。
    """
    try:
        if not isinstance(body, dict):
            return DCRValidationResult(
                False, error="invalid_client_metadata",
                error_description="request body must be a JSON object",
            )

        redirect_uris = body.get("redirect_uris")
        if not isinstance(redirect_uris, list) or not redirect_uris:
            return DCRValidationResult(
                False, error="invalid_redirect_uri",
                error_description=(
                    "redirect_uris is required and must be a non-empty array"
                ),
            )
        if len(redirect_uris) > _MAX_REDIRECT_URIS:
            return DCRValidationResult(
                False, error="invalid_client_metadata",
                error_description=(
                    f"redirect_uris must not exceed {_MAX_REDIRECT_URIS} entries"
                ),
            )
        for uri in redirect_uris:
            if not _is_acceptable_redirect_uri(uri):
                return DCRValidationResult(
                    False, error="invalid_redirect_uri",
                    error_description=(
                        "each redirect_uri must be an https:// URL, or a "
                        "http://localhost / http://127.0.0.1 loopback address"
                    ),
                )

        client_name = body.get("client_name")
        if not isinstance(client_name, str) or not client_name.strip():
            client_name = "MCP Client"
        else:
            # 只是显示用，不是安全字段——超长静默截断，不因此拒绝注册。
            client_name = client_name.strip()[:_MAX_CLIENT_NAME_LENGTH]

        return DCRValidationResult(
            True, redirect_uris=redirect_uris, client_name=client_name,
        )
    except Exception:
        return DCRValidationResult(
            False, error="invalid_client_metadata",
            error_description="malformed registration request",
        )


def _derive_registration_key(secret: str) -> bytes:
    """域分离：client_id 签名用的密钥，是从 BODYBRIDGE_TOKEN 派生出的专用
    子密钥，不是直接复用签授权码/access token 的那把原始密钥。三种结构不同
    的东西（授权码 claims / access token claims / client 注册 claims）不共用
    同一把裸密钥——成本几乎为零，多一层防护，躲开"一个签名被误当另一种东西
    验证通过"的理论风险。"""
    return hmac.new(secret.encode("utf-8"), b"client-registration", hashlib.sha256).digest()


def issue_client_id(secret: str, *, redirect_uris: list, client_name: str,
                     now: float | None = None) -> tuple[str | None, int, str | None]:
    """签一个自包含不透明 client_id。RFC 7591 对 client_id 格式没有任何要求
    （不像 CIMD 强制 https:// URL），这给了自由：直接做成跟第 3 步签名授权码
    同一套手法的 HMAC 签名不透明串——不是发明新机制，是复用已有模式。

    不设过期：client_id 本身不是凭据，光有它拿不到任何东西——安全边界在
    /oauth/authorize 的密码同意页，不需要像授权码/access token 那样限时。

    返回 (client_id, issued_at, error)：
      成功 -> (不透明串, 签发时刻, None)
      编码后超出 _MAX_CLIENT_ID_LENGTH（redirect_uris 太多/太长撑爆的）
        -> (None, 签发时刻, 人话原因)，调用方据此以 invalid_client_metadata 拒绝
    """
    now = time.time() if now is None else now
    claims = {
        "redirect_uris": redirect_uris,
        "client_name": client_name,
        "iat": int(now),
    }
    key = _derive_registration_key(secret)
    payload_b64 = _b64url_encode(json.dumps(claims, separators=(",", ":")).encode("utf-8"))
    sig_b64 = _b64url_encode(
        hmac.new(key, payload_b64.encode("ascii"), hashlib.sha256).digest()
    )
    client_id = f"{payload_b64}.{sig_b64}"
    if len(client_id) > _MAX_CLIENT_ID_LENGTH:
        return None, int(now), (
            "registration is too large (encoded client_id exceeds "
            f"{_MAX_CLIENT_ID_LENGTH} characters -- too many or too long redirect_uris)"
        )
    return client_id, int(now), None


def verify_client_id(secret: str, client_id: str) -> dict | None:
    """本地验签解出 redirect_uris/client_name，零网络请求（对照 CIMD 路径，
    这是走 DCR 的核心好处：不需要主动出站访问任何客户端声明的地址）。

    任何失败（签名错、格式畸形、字段缺失或类型不对、任何异常——含空值/
    超长串/二进制乱码/深层嵌套怪结构）一律返回 None，绝不上抛（铁律 3）。

    这里没有"验不出来就跳过"的分支：调用方（/oauth/authorize）拿到 None
    必须硬拒，不能像 OB 那样在"查不到"时放过 redirect_uri 校验——因为这个
    函数根本不存在"查不到"这种中间状态，只有"验证通过、给你可信 claims"
    或"验证失败、什么都不给"两种结果。
    """
    try:
        payload_b64, sig_b64 = client_id.split(".", 1)
    except Exception:
        return None
    try:
        key = _derive_registration_key(secret)
        expected_sig = hmac.new(key, payload_b64.encode("ascii"), hashlib.sha256).digest()
        expected_sig_b64 = _b64url_encode(expected_sig)
    except Exception:
        return None
    if not safe_compare(sig_b64, expected_sig_b64):
        return None
    try:
        claims = json.loads(_b64url_decode(payload_b64).decode("utf-8"))
    except Exception:
        return None
    if not isinstance(claims, dict):
        return None
    redirect_uris = claims.get("redirect_uris")
    if not isinstance(redirect_uris, list) or not redirect_uris:
        return None
    if not all(isinstance(u, str) for u in redirect_uris):
        return None
    return claims
