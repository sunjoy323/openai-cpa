import base64
import hashlib
import json
import os
import random
import re
import secrets
import string
import time
import traceback
import uuid
import urllib.parse
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Optional, Tuple

from curl_cffi import requests

try:
    from utils.sentinel import get_token as _native_get_token, clear_cache as _native_clear_cache
except Exception:
    _native_get_token = None
    _native_clear_cache = None

from utils import config as cfg
from utils import db_manager
from utils.email_providers.mail_service import get_email_and_token, get_oai_code, mask_email
try:
    from utils.integrations.hero_sms import _try_verify_phone_via_hero_sms
except Exception:
    _try_verify_phone_via_hero_sms = None

try:
    from utils.auth_core import generate_payload as _authcore_generate_payload
except Exception:
    _authcore_generate_payload = None

AUTH_URL            = "https://auth.openai.com/oauth/authorize"
TOKEN_URL           = "https://auth.openai.com/oauth/token"
CLIENT_ID           = "app_EMoamEEZ73f0CkXaXp7hrann"
DEFAULT_REDIRECT_URI = "http://localhost:1455/auth/callback"
DEFAULT_SCOPE       = "openid email profile offline_access"

FIRST_NAMES = [
    "James", "John", "Robert", "Michael", "William", "David", "Richard",
    "Joseph", "Thomas", "Charles", "Emma", "Olivia", "Ava", "Isabella",
    "Sophia", "Mia", "Charlotte", "Amelia", "Harper", "Evelyn",
]
LAST_NAMES = [
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller",
    "Davis", "Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzalez",
    "Wilson", "Anderson", "Thomas", "Taylor", "Moore", "Jackson", "Martin",
]

def _ssl_verify() -> bool:
    flag = os.getenv("OPENAI_SSL_VERIFY", "1").strip().lower()
    return flag not in {"0", "false", "no", "off"}

def _skip_net_check() -> bool:
    flag = os.getenv("SKIP_NET_CHECK", "0").strip().lower()
    return flag in {"1", "true", "yes", "on"}

def _b64url_no_pad(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

def _sha256_b64url_no_pad(s: str) -> str:
    return _b64url_no_pad(hashlib.sha256(s.encode("ascii")).digest())

def _random_state(nbytes: int = 16) -> str:
    return secrets.token_urlsafe(nbytes)

def _pkce_verifier() -> str:
    return secrets.token_urlsafe(64)


def _parse_callback_url(callback_url: str) -> Dict[str, Any]:
    candidate = callback_url.strip()
    if not candidate:
        return {"code": "", "state": "", "error": "", "error_description": ""}
    if "://" not in candidate:
        if candidate.startswith("?"):
            candidate = f"http://localhost{candidate}"
        elif any(ch in candidate for ch in "/?#") or ":" in candidate:
            candidate = f"http://{candidate}"
        elif "=" in candidate:
            candidate = f"http://localhost/?{candidate}"
    parsed   = urllib.parse.urlparse(candidate)
    query    = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    fragment = urllib.parse.parse_qs(parsed.fragment, keep_blank_values=True)
    for key, values in fragment.items():
        if key not in query or not query[key] or not (query[key][0] or "").strip():
            query[key] = values

    def get1(k: str) -> str:
        v = query.get(k, [""])
        return (v[0] or "").strip()

    code  = get1("code")
    state = get1("state")
    error = get1("error")
    error_description = get1("error_description")
    if code and not state and "#" in code:
        code, state = code.split("#", 1)
    if not error and error_description:
        error, error_description = error_description, ""
    return {"code": code, "state": state, "error": error,
            "error_description": error_description}


def _jwt_claims_no_verify(id_token: str) -> Dict[str, Any]:
    if not id_token or id_token.count(".") < 2:
        return {}
    payload_b64 = id_token.split(".")[1]
    pad = "=" * ((4 - (len(payload_b64) % 4)) % 4)
    try:
        return json.loads(
            base64.urlsafe_b64decode((payload_b64 + pad).encode("ascii")).decode("utf-8")
        )
    except Exception:
        return {}


def _decode_jwt_segment(seg: str) -> Dict[str, Any]:
    raw = (seg or "").strip()
    if not raw:
        return {}
    pad = "=" * ((4 - (len(raw) % 4)) % 4)
    try:
        return json.loads(
            base64.urlsafe_b64decode((raw + pad).encode("ascii")).decode("utf-8")
        )
    except Exception:
        return {}


def _to_int(v: Any) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0

def _post_form(
    url: str,
    data: Dict[str, str],
    proxies: Any = None,
    timeout: int = 30,
    retries: int = 3,
) -> Dict[str, Any]:
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }
    last_error: Optional[Exception] = None
    for attempt in range(retries + 1):
        try:
            resp = requests.post(
                url, data=data, headers=headers,
                proxies=proxies, verify=_ssl_verify(),
                timeout=timeout, impersonate="chrome110",
            )
            if resp.status_code != 200:
                raise RuntimeError(
                    f"token exchange failed: {resp.status_code}: {resp.text}"
                )
            return resp.json()
        except Exception as exc:
            last_error = exc
            if attempt < retries:
                print(f"\n[{cfg.ts()}] [WARNING] 换取 Token 时遇到网络异常: {exc}。"
                      f"准备第 {attempt+1}/{retries} 次重试...")
                time.sleep(2 * (attempt + 1))
    raise RuntimeError(
        f"token exchange failed after {retries} retries: {last_error}"
    ) from last_error


def _post_with_retry(
    session: requests.Session,
    url: str,
    *,
    headers: Dict[str, Any],
    data: Any = None,
    json_body: Any = None,
    proxies: Any = None,
    timeout: int = 30,
    retries: int = 2,
    allow_redirects: bool = True,
) -> Any:
    last_error: Optional[Exception] = None
    for attempt in range(retries + 1):
        if getattr(cfg, 'GLOBAL_STOP', False):
            raise RuntimeError("系统已停止，强制中断网络请求")
        try:
            if json_body is not None:
                return session.post(
                    url, headers=headers, json=json_body,
                    proxies=proxies, verify=_ssl_verify(),
                    timeout=timeout, allow_redirects=allow_redirects,
                )
            return session.post(
                url, headers=headers, data=data,
                proxies=proxies, verify=_ssl_verify(),
                timeout=timeout, allow_redirects=allow_redirects,
            )
        except Exception as e:
            last_error = e
            if attempt >= retries:
                break
            time.sleep(2 * (attempt + 1))
    if last_error:
        raise last_error
    raise RuntimeError("Request failed without exception")


def _short_text(value: Any, limit: int = 300) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    if not text:
        return ""
    return text if len(text) <= limit else f"{text[:limit]}..."


def _response_debug_summary(resp: Any) -> str:
    if resp is None:
        return "response=<none>"

    status = getattr(resp, "status_code", "unknown")
    headers = getattr(resp, "headers", {}) or {}
    content_type = _short_text(headers.get("content-type", ""))
    location = _short_text(headers.get("location", ""))

    payload = ""
    try:
        data = resp.json()
        if isinstance(data, dict):
            interesting = {
                key: data.get(key) for key in (
                    "error", "error_description", "message", "detail",
                    "code", "type", "reason", "continue_url"
                ) if data.get(key)
            }
            page = data.get("page") or {}
            if isinstance(page, dict) and page.get("type"):
                interesting["page_type"] = page.get("type")
            payload = json.dumps(interesting or data, ensure_ascii=False)
        else:
            payload = json.dumps(data, ensure_ascii=False)
    except Exception:
        payload = getattr(resp, "text", "")

    payload = _short_text(payload, 500)
    parts = [f"HTTP {status}"]
    if content_type:
        parts.append(f"content-type={content_type}")
    if location:
        parts.append(f"location={location}")
    if payload:
        parts.append(f"body={payload}")
    return ", ".join(parts)


def _response_error_fields(resp: Any) -> Dict[str, Any]:
    if resp is None:
        return {}
    try:
        data = resp.json()
    except Exception:
        return {}

    if isinstance(data, dict):
        err = data.get("error")
        if isinstance(err, dict):
            result = dict(err)
            if (data.get("page") or {}).get("type"):
                result["page_type"] = (data.get("page") or {}).get("type")
            return result
        return data
    return {}


def _json_dict(resp: Any) -> Dict[str, Any]:
    if resp is None:
        return {}
    try:
        data = resp.json()
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def _registration_failure_hint(stage: str, status_code: Any) -> str:
    try:
        code = int(status_code)
    except Exception:
        code = None

    if code == 400:
        return f"{stage} 可能是请求参数、会话状态或页面流程字段不符合预期，不一定是域名问题。"
    if code == 401:
        return f"{stage} 可能是认证状态失效，检查挑战链路、Cookie 和会话连续性。"
    if code == 403:
        return f"{stage} 更像是风控拦截，域名、代理、指纹或行为轨迹都可能触发。"
    if code == 409:
        return f"{stage} 可能是账号状态冲突或流程重复提交。"
    if code == 422:
        return f"{stage} 可能是资料页字段校验未通过。"
    if code == 429:
        return f"{stage} 可能是频率限制或风控限流。"
    if code and code >= 500:
        return f"{stage} 可能是服务端异常，未必和域名有关。"
    return f"{stage} 失败，域名只是可能原因之一，还可能是风控、资料校验或会话链路异常。"


def _log_registration_http_failure(stage: str, resp: Any) -> None:
    summary = _response_debug_summary(resp)
    status = getattr(resp, "status_code", "unknown")
    err_fields = _response_error_fields(resp)
    err_code = str(err_fields.get("code") or "").strip().lower()
    hint = _registration_failure_hint(stage, status)
    if err_code == "registration_disallowed":
        hint = (
            f"{stage} 被服务端明确拒绝，错误码=registration_disallowed。"
            f"这通常更像注册策略拦截，常见原因是邮箱域名信誉、代理/IP 风险、"
            f"批量行为痕迹或账号环境命中风控，而不是单纯代码参数格式问题。"
        )
    print(f"[{cfg.ts()}] [ERROR] {stage}失败: {summary}")
    print(f"[{cfg.ts()}] [ERROR] {hint}")


def _record_redirect_trace(
    trace: Optional[list],
    stage: str,
    url: str,
    resp: Any = None,
    note: str = "",
) -> None:
    if trace is None:
        return
    parts = [f"stage={stage}", f"url={_short_text(url, 240)}"]
    if resp is not None:
        parts.append(_response_debug_summary(resp))
    if note:
        parts.append(f"note={_short_text(note, 240)}")
    trace.append(" | ".join(parts))


def _log_oauth_chain_failure(
    stage: str,
    *,
    current_url: str = "",
    next_url: str = "",
    resp: Any = None,
    trace: Optional[list] = None,
    note: str = "",
) -> None:
    print(f"[{cfg.ts()}] [ERROR] OAuth 授权链路失败，阶段={stage}")
    if current_url:
        print(f"[{cfg.ts()}] [ERROR] OAuth 当前 URL: {_short_text(current_url, 500)}")
    if next_url:
        print(f"[{cfg.ts()}] [ERROR] OAuth 下一跳 URL: {_short_text(next_url, 500)}")
    if note:
        print(f"[{cfg.ts()}] [ERROR] OAuth 说明: {_short_text(note, 500)}")
    if resp is not None:
        print(f"[{cfg.ts()}] [ERROR] OAuth 原始响应: {_response_debug_summary(resp)}")
    if trace:
        for idx, item in enumerate(trace[-8:], 1):
            print(f"[{cfg.ts()}] [DEBUG] OAuth 跳转轨迹[{idx}]: {item}")


def _record_manual_login_required(
    email: str,
    password: str,
    *,
    stage: str,
    current_url: str = "",
    note: str = "",
    email_jwt: str = "",
) -> None:
    if not email or not password:
        return
    if db_manager.save_manual_review_account(
        email=email,
        password=password,
        stage=stage,
        current_url=current_url,
        note=note,
        email_jwt=email_jwt,
    ):
        print(
            f"[{cfg.ts()}] [WARNING] 已记录到人工登录待处理列表: {mask_email(email)} "
            f"(stage={stage}, file=data/manual_review_accounts.json)"
        )


def _compact_json(payload: Any) -> str:
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))

def _oai_headers(did: str, extra: dict = None) -> dict:
    h = {
        "accept": "application/json",
        "user-agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/110.0.0.0 Safari/537.36"
        ),
        "sec-ch-ua": '"Google Chrome";v="110", "Chromium";v="110", "Not_A Brand";v="24"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "oai-device-id": did,
    }
    if extra:
        h.update(extra)
    return h


def _get_sentinel_token(
    session: requests.Session,
    flow: str,
    proxies: Any = None,
) -> str:
    """获取 OpenAI token；失败返回空串而不抛异常。"""
    did = session.cookies.get("oai-did")
    if not did:
        return ""
    try:
        res = session.post(
            "https://sentinel.openai.com/backend-api/sentinel/req",
            headers={
                "Origin":       "https://sentinel.openai.com",
                "Referer":      "https://sentinel.openai.com/backend-api/sentinel/frame.html?sv=20260219f9f6",
                "Content-Type": "text/plain;charset=UTF-8",
            },
            data=json.dumps({"p": "", "id": did, "flow": flow}),
            proxies=proxies, verify=_ssl_verify(), timeout=15,
        )
        token = str((res.json() or {}).get("token") or "").strip()
        if not token:
            return ""
        return json.dumps(
            {"p": "", "t": "", "c": token, "id": did, "flow": flow},
            ensure_ascii=False, separators=(",", ":"),
        )
    except Exception:
        return ""


def _clear_sentinel_cache() -> None:
    if _native_clear_cache is None:
        return
    try:
        _native_clear_cache()
    except Exception as exc:
        print(f"[{cfg.ts()}] [WARNING] 清理 sentinel 缓存失败，将继续使用当前会话缓存: {exc}")


def _challenge_token(
    session: requests.Session,
    flow: str,
    proxies: Any = None,
    *,
    use: bool = False,
    ctx: Optional[dict] = None,
) -> str:
    did = session.cookies.get("oai-did") or ""
    if _authcore_generate_payload is not None and did:
        try:
            proxy_url = ""
            if isinstance(proxies, dict):
                proxy_url = str(proxies.get("https") or proxies.get("http") or "").strip()
            else:
                proxy_url = str(proxies or "").strip()
            payload_kwargs = dict(
                did=did,
                flow=flow,
                proxy=proxy_url,
                user_agent=session.headers.get("User-Agent"),
                impersonate="chrome110",
            )
            if ctx is not None:
                payload_kwargs["ctx"] = ctx
            try:
                token = _authcore_generate_payload(**payload_kwargs)
            except TypeError:
                payload_kwargs.pop("ctx", None)
                token = _authcore_generate_payload(**payload_kwargs)
            token = str(token or "").strip()
            if token:
                return token
        except Exception as exc:
            print(f"[{cfg.ts()}] [WARNING] auth_core 取 token 失败，flow={flow}: {exc}")
    if _native_get_token is not None:
        try:
            token = _native_get_token(session, flow, proxies, use=use)
            token = str(token or "").strip()
            if token:
                return token
        except TypeError:
            try:
                token = _native_get_token(session, flow, proxies)
                token = str(token or "").strip()
                if token:
                    return token
            except Exception as exc:
                print(f"[{cfg.ts()}] [WARNING] 原生 sentinel 取 token 失败，flow={flow}: {exc}")
        except Exception as exc:
            print(f"[{cfg.ts()}] [WARNING] 原生 sentinel 取 token 失败，flow={flow}: {exc}")
    return _get_sentinel_token(session, flow, proxies)

def _follow_redirect_chain_local(
    session: requests.Session,
    start_url: str,
    proxies: Any = None,
    max_redirects: int = 12,
    trace: Optional[list] = None,
    stage: str = "",
) -> Tuple[Any, str]:
    """手动跟随 30x 重定向；若 Location 含 code+state 则直接返回。"""
    current_url = start_url
    response    = None
    if not current_url:
        _record_redirect_trace(trace, stage or "redirect_start", current_url, note="empty start_url")
        return None, current_url
    for idx in range(max_redirects):
        try:
            response = session.get(
                current_url,
                allow_redirects=False,
                proxies=proxies,
                verify=_ssl_verify(),
                timeout=15,
            )
            _record_redirect_trace(trace, stage or f"redirect_{idx+1}", current_url, response)
            if response.status_code not in (301, 302, 303, 307, 308):
                return response, current_url
            loc = response.headers.get("Location", "")
            if not loc:
                _record_redirect_trace(
                    trace,
                    stage or f"redirect_{idx+1}",
                    current_url,
                    response,
                    note="redirect response missing Location header",
                )
                return response, current_url
            current_url = urllib.parse.urljoin(current_url, loc)
            if "code=" in current_url and "state=" in current_url:
                _record_redirect_trace(
                    trace,
                    stage or f"redirect_{idx+1}",
                    current_url,
                    note="authorization callback detected",
                )
                return None, current_url
        except Exception as e:
            _record_redirect_trace(
                trace,
                stage or f"redirect_{idx+1}",
                current_url,
                note=f"exception={e}",
            )
            return None, current_url
    _record_redirect_trace(trace, stage or "redirect_end", current_url, response, note="max_redirects reached")
    return response, current_url


def _extract_next_url(data: Dict[str, Any]) -> str:
    """从 API 响应中解析下一跳 URL"""
    continue_url = str(data.get("continue_url") or "").strip()
    if continue_url:
        return continue_url
    page_type = str((data.get("page") or {}).get("type") or "").strip()
    mapping = {
        "email_otp_verification":              "https://auth.openai.com/email-verification",
        "sign_in_with_chatgpt_codex_consent":  "https://auth.openai.com/sign-in-with-chatgpt/codex/consent",
        "workspace":                           "https://auth.openai.com/workspace",
        "add_phone":                           "https://auth.openai.com/add-phone",
        "phone_verification":                  "https://auth.openai.com/add-phone",
        "phone_otp_verification":              "https://auth.openai.com/add-phone",
        "phone_number_verification":           "https://auth.openai.com/add-phone",
    }
    return mapping.get(page_type, "")

@dataclass(frozen=True)
class OAuthStart:
    auth_url:       str
    state:          str
    code_verifier:  str
    redirect_uri:   str


def generate_oauth_url(
    *,
    redirect_uri: str = DEFAULT_REDIRECT_URI,
    scope: str = DEFAULT_SCOPE,
) -> OAuthStart:
    state          = _random_state()
    code_verifier  = _pkce_verifier()
    code_challenge = _sha256_b64url_no_pad(code_verifier)
    params = {
        "client_id":                  CLIENT_ID,
        "response_type":              "code",
        "redirect_uri":               redirect_uri,
        "scope":                      scope,
        "state":                      state,
        "code_challenge":             code_challenge,
        "code_challenge_method":      "S256",
        "prompt":                     "login",
        "id_token_add_organizations": "true",
        "codex_cli_simplified_flow":  "true",
    }
    return OAuthStart(
        auth_url      = f"{AUTH_URL}?{urllib.parse.urlencode(params)}",
        state         = state,
        code_verifier = code_verifier,
        redirect_uri  = redirect_uri,
    )


def submit_callback_url(
    *,
    callback_url:   str,
    expected_state: str,
    code_verifier:  str,
    redirect_uri:   str = DEFAULT_REDIRECT_URI,
    proxies:        Any = None,
) -> str:
    """用授权码换 token，返回 JSON 字符串"""
    cb = _parse_callback_url(callback_url)
    if cb["error"]:
        raise RuntimeError(f"oauth error: {cb['error']}: {cb['error_description']}".strip())
    if not cb["code"]:
        raise ValueError("callback url missing ?code=")
    if not cb["state"]:
        raise ValueError("callback url missing ?state=")
    if cb["state"] != expected_state:
        raise ValueError("state mismatch")

    token_resp = _post_form(
        TOKEN_URL,
        {
            "grant_type":    "authorization_code",
            "client_id":     CLIENT_ID,
            "code":          cb["code"],
            "redirect_uri":  redirect_uri,
            "code_verifier": code_verifier,
        },
        proxies=proxies,
    )

    access_token  = (token_resp.get("access_token")  or "").strip()
    refresh_token = (token_resp.get("refresh_token") or "").strip()
    id_token      = (token_resp.get("id_token")      or "").strip()
    expires_in    = _to_int(token_resp.get("expires_in"))

    claims      = _jwt_claims_no_verify(id_token)
    email       = str(claims.get("email") or "").strip()
    auth_claims = claims.get("https://api.openai.com/auth") or {}
    account_id  = str(auth_claims.get("chatgpt_account_id") or "").strip()

    now          = int(time.time())
    now_rfc      = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))
    expired_rfc  = time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                  time.gmtime(now + max(expires_in, 0)))

    config_obj = {
        "id_token":      id_token,
        "access_token":  access_token,
        "refresh_token": refresh_token,
        "account_id":    account_id,
        "last_refresh":  now_rfc,
        "email":         email,
        "type":          "codex",
        "expired":       expired_rfc,
    }
    return json.dumps(config_obj, ensure_ascii=False, separators=(",", ":"))

def _generate_password(length: int = 20) -> str:
    upper    = random.choices(string.ascii_uppercase, k=2)
    lower    = random.choices(string.ascii_lowercase, k=2)
    digits   = random.choices(string.digits, k=2)
    specials = random.choices("!@#$%&*", k=2)
    pool     = string.ascii_letters + string.digits + "!@#$%&*"
    rest     = random.choices(pool, k=length - 8)
    chars    = upper + lower + digits + specials + rest
    random.shuffle(chars)
    return "".join(chars)


def generate_random_user_info() -> dict:
    name = f"{random.choice(FIRST_NAMES)} {random.choice(LAST_NAMES)}"
    year  = random.randint(datetime.now().year - 38, datetime.now().year - 22)
    month = random.randint(1, 12)
    day   = random.randint(1, 28)
    return {"name": name, "birthdate": f"{year}-{month:02d}-{day:02d}"}

def _parse_workspace_from_auth_cookie(auth_cookie: str) -> list:
    """JWT payload"""
    if not auth_cookie or "." not in auth_cookie:
        return []
    parts = auth_cookie.split(".")
    if len(parts) >= 2:
        claims = _decode_jwt_segment(parts[1])
        workspaces = claims.get("workspaces") or []
        if workspaces:
            return workspaces
    claims = _decode_jwt_segment(parts[0])
    return claims.get("workspaces") or []


def _choose_workspace_id(workspaces: list) -> str:
    for workspace in workspaces:
        if not isinstance(workspace, dict):
            continue
        workspace_id = str(workspace.get("id") or workspace.get("workspace_id") or "").strip()
        if workspace_id:
            return workspace_id
    return ""


def _select_workspace_and_submit(
    session: Any,
    oauth: OAuthStart,
    *,
    proxies: Any = None,
    referer: str = "https://auth.openai.com/sign-in-with-chatgpt/codex/consent",
    trace: Optional[list] = None,
    stage: str = "workspace_select",
) -> Optional[str]:
    auth_cookie = session.cookies.get("oai-client-auth-session") or ""
    workspaces = _parse_workspace_from_auth_cookie(auth_cookie)
    if not workspaces:
        _log_oauth_chain_failure(
            f"{stage}_missing_workspace",
            current_url=referer,
            trace=trace,
            note="授权 Cookie 里没有 workspace 信息，无法继续提交 workspace/select。",
        )
        return None

    workspace_id = _choose_workspace_id(workspaces)
    if not workspace_id:
        _log_oauth_chain_failure(
            f"{stage}_missing_workspace_id",
            current_url=referer,
            trace=trace,
            note="workspace 列表存在，但无法解析 id/workspace_id。",
        )
        return None

    print(f"[{cfg.ts()}] [INFO] 检测到可用工作空间，准备提交 workspace/select: {workspace_id}")
    did = session.cookies.get("oai-did") or ""
    select_resp = _post_with_retry(
        session,
        "https://auth.openai.com/api/accounts/workspace/select",
        headers=_oai_headers(did, {
            "Referer": referer,
            "content-type": "application/json",
        }),
        data=_compact_json({"workspace_id": workspace_id}),
        proxies=proxies,
    )
    if select_resp.status_code != 200:
        _log_registration_http_failure("Workspace 选择", select_resp)
        _log_oauth_chain_failure(
            stage,
            current_url=referer,
            resp=select_resp,
            trace=trace,
            note="workspace/select 未返回 200。",
        )
        return None

    continue_url = _extract_next_url(_json_dict(select_resp))
    if not continue_url:
        _log_oauth_chain_failure(
            f"{stage}_missing_continue_url",
            current_url=referer,
            resp=select_resp,
            trace=trace,
            note="workspace/select 成功，但响应里没有 continue_url/page_type。",
        )
        return None

    _, final_url = _follow_redirect_chain_local(
        session, continue_url, proxies, trace=trace, stage=f"{stage}_follow"
    )
    if "code=" in final_url and "state=" in final_url:
        return submit_callback_url(
            callback_url=final_url,
            expected_state=oauth.state,
            code_verifier=oauth.code_verifier,
            redirect_uri=oauth.redirect_uri,
            proxies=proxies,
        )

    _log_oauth_chain_failure(
        f"{stage}_no_callback",
        current_url=final_url,
        next_url=continue_url,
        resp=select_resp,
        trace=trace,
        note="workspace/select 之后仍未拿到 code/state。",
    )
    return None

def _oauth_retry_result(
    success: bool,
    *,
    token_json: str = "",
    status: str = "",
    stage: str = "",
    current_url: str = "",
    note: str = "",
    message: str = "",
) -> Dict[str, Any]:
    return {
        "success": success,
        "token_json": token_json,
        "status": status or ("success" if success else "retry_failed"),
        "stage": stage,
        "current_url": current_url,
        "note": note,
        "message": message or note,
    }

def _retry_oauth_login_flow(
    email: str,
    password: str,
    *,
    email_jwt: str = "",
    proxies: Any = None,
    processed_mails: Optional[set] = None,
    record_manual_on_add_phone: bool = False,
) -> Dict[str, Any]:
    processed_mails = processed_mails if processed_mails is not None else set()
    try:
        s_log = requests.Session(proxies=proxies, impersonate="chrome110")
        oauth_log = generate_oauth_url()
        oauth_trace = []
        log_ctx = {"session_id": str(uuid.uuid4())}
        now_ms = int(time.time() * 1000)
        log_ctx["time_origin"] = float(now_ms - random.randint(20000, 300000))

        resp, current_url = _follow_redirect_chain_local(
            s_log, oauth_log.auth_url, proxies, trace=oauth_trace, stage="oauth_start"
        )
        if "code=" in current_url and "state=" in current_url:
            return _oauth_retry_result(
                True,
                token_json=submit_callback_url(
                    callback_url=current_url,
                    code_verifier=oauth_log.code_verifier,
                    redirect_uri=oauth_log.redirect_uri,
                    expected_state=oauth_log.state,
                    proxies=proxies,
                ),
            )

        sentinel_log = _challenge_token(s_log, "authorize_continue", proxies, ctx=log_ctx)
        log_start_headers = _oai_headers(
            s_log.cookies.get("oai-did") or "",
            {
                "Referer": current_url,
                "content-type": "application/json",
            },
        )
        if sentinel_log:
            log_start_headers["openai-sentinel-token"] = sentinel_log
        login_start_resp = _post_with_retry(
            s_log,
            "https://auth.openai.com/api/accounts/authorize/continue",
            headers=log_start_headers,
            json_body={"username": {"value": email, "kind": "email"}},
            proxies=proxies, allow_redirects=False,
        )
        if login_start_resp.status_code != 200:
            note = "authorize/continue 未返回 200，无法进入密码页。"
            _log_registration_http_failure("OAuth 登录起始授权", login_start_resp)
            _log_oauth_chain_failure(
                "authorize_continue",
                current_url=current_url,
                resp=login_start_resp,
                trace=oauth_trace,
                note=note,
            )
            return _oauth_retry_result(
                False,
                stage="authorize_continue",
                current_url=current_url,
                note=note,
                message="OAuth 登录起始授权失败，请看日志里的原始响应。",
            )

        pwd_page_url = str(
            (_json_dict(login_start_resp) if login_start_resp.status_code == 200 else {})
            .get("continue_url") or ""
        ).strip()
        if not pwd_page_url:
            note = "authorize/continue 返回中没有 continue_url。"
            _log_oauth_chain_failure(
                "missing_password_page_url",
                current_url=current_url,
                resp=login_start_resp,
                trace=oauth_trace,
                note=note,
            )
            return _oauth_retry_result(
                False,
                stage="missing_password_page_url",
                current_url=current_url,
                note=note,
                message="没有拿到密码页地址，OAuth 流程被截断。",
            )
        resp, current_url = _follow_redirect_chain_local(
            s_log, pwd_page_url, proxies, trace=oauth_trace, stage="password_page"
        )

        sentinel_pwd = _challenge_token(s_log, "password_verify", proxies, ctx=log_ctx)
        login_pwd_headers = _oai_headers(
            s_log.cookies.get("oai-did") or "",
            {
                "Referer": current_url,
                "content-type": "application/json",
            },
        )
        if sentinel_pwd:
            login_pwd_headers["openai-sentinel-token"] = sentinel_pwd
        pwd_login_resp = _post_with_retry(
            s_log,
            "https://auth.openai.com/api/accounts/password/verify",
            headers=login_pwd_headers,
            json_body={"password": password},
            proxies=proxies,
        )
        if pwd_login_resp.status_code != 200:
            note = "password/verify 未返回 200。"
            _log_registration_http_failure("密码验证", pwd_login_resp)
            _log_oauth_chain_failure(
                "password_verify",
                current_url=current_url,
                resp=pwd_login_resp,
                trace=oauth_trace,
                note=note,
            )
            return _oauth_retry_result(
                False,
                stage="password_verify",
                current_url=current_url,
                note=note,
                message="密码验证失败，请看日志里的原始响应。",
            )

        pwd_json = _json_dict(pwd_login_resp) if pwd_login_resp.status_code == 200 else {}
        next_url = _extract_next_url(pwd_json)
        if not next_url:
            note = "password/verify 响应里没有 continue_url，也无法从 page.type 推导下一跳。"
            _log_oauth_chain_failure(
                "missing_next_url_after_password_verify",
                current_url=current_url,
                resp=pwd_login_resp,
                trace=oauth_trace,
                note=note,
            )
            return _oauth_retry_result(
                False,
                stage="missing_next_url_after_password_verify",
                current_url=current_url,
                note=note,
                message="密码通过了，但后续跳转地址丢了。",
            )
        resp, current_url = _follow_redirect_chain_local(
            s_log, next_url, proxies, trace=oauth_trace, stage="post_password_verify"
        )

        if current_url.endswith("/email-verification"):
            print(f"\n[{cfg.ts()}] [INFO] 静默登录需要验证码，主动触发发送...")
            send_otp_url = "https://auth.openai.com/api/accounts/email-otp/send"
            try:
                sentinel_log_send = _challenge_token(s_log, "authorize_continue", proxies, ctx=log_ctx)
                log_send_headers = _oai_headers(
                    s_log.cookies.get("oai-did") or "",
                    {"Referer": current_url, "content-type": "application/json"},
                )
                if sentinel_log_send:
                    log_send_headers["openai-sentinel-token"] = sentinel_log_send
                _post_with_retry(
                    s_log,
                    send_otp_url,
                    headers=log_send_headers,
                    json_body={},
                    proxies=proxies,
                    timeout=30,
                )
            except Exception as e:
                print(f"[{cfg.ts()}] [WARNING] 登录 OTP 发送请求异常: {e}")

            code2 = ""
            for resend_attempt in range(max(1, cfg.MAX_OTP_RETRIES)):
                if resend_attempt > 0:
                    print(f"\n[{cfg.ts()}] [INFO] 正在重试 {resend_attempt}/{cfg.MAX_OTP_RETRIES}...")
                    try:
                        sentinel_log_resend = _challenge_token(
                            s_log, "authorize_continue", proxies, ctx=log_ctx
                        )
                        log_resend_headers = _oai_headers(
                            s_log.cookies.get("oai-did") or "",
                            {"Referer": current_url, "content-type": "application/json"},
                        )
                        if sentinel_log_resend:
                            log_resend_headers["openai-sentinel-token"] = sentinel_log_resend
                        _post_with_retry(
                            s_log,
                            send_otp_url,
                            headers=log_resend_headers,
                            json_body={},
                            proxies=proxies,
                            timeout=15,
                        )
                        time.sleep(2)
                    except Exception as e:
                        print(f"[{cfg.ts()}] [WARNING] 重新发送请求异常: {e}")
                code2 = get_oai_code(email, jwt=email_jwt, proxies=proxies,
                                     processed_mail_ids=processed_mails)
                if code2:
                    break

            if not code2:
                note = "二次邮箱验证阶段重试后依然未收到验证码。"
                print(f"[{cfg.ts()}] [ERROR] 重新发送后依然未收到验证码，彻底放弃。")
                return _oauth_retry_result(
                    False,
                    stage="secondary_email_otp_missing",
                    current_url=current_url,
                    note=note,
                    message="二次邮箱验证码一直没收到，暂时无法拿到 token。",
                )

            sentinel_otp2 = _challenge_token(s_log, "authorize_continue", proxies, ctx=log_ctx)
            val2_headers = _oai_headers(
                s_log.cookies.get("oai-did") or "",
                {
                    "Referer": current_url,
                    "content-type": "application/json",
                },
            )
            if sentinel_otp2:
                val2_headers["openai-sentinel-token"] = sentinel_otp2
            code2_resp = _post_with_retry(
                s_log,
                "https://auth.openai.com/api/accounts/email-otp/validate",
                headers=val2_headers,
                json_body={"code": code2},
                proxies=proxies,
            )
            if code2_resp.status_code != 200:
                note = "二次邮箱验证未通过。"
                _log_registration_http_failure("二次安全验证 OTP 校验", code2_resp)
                _log_oauth_chain_failure(
                    "secondary_email_otp_validate",
                    current_url=current_url,
                    resp=code2_resp,
                    trace=oauth_trace,
                    note=note,
                )
                return _oauth_retry_result(
                    False,
                    stage="secondary_email_otp_validate",
                    current_url=current_url,
                    note=note,
                    message="二次邮箱验证码校验失败，请看日志里的回包。",
                )

            next_url = str(_json_dict(code2_resp).get("continue_url") or "").strip()
            if not next_url:
                note = "二次 OTP 校验成功，但响应里没有 continue_url。"
                _log_oauth_chain_failure(
                    "missing_next_url_after_secondary_otp",
                    current_url=current_url,
                    resp=code2_resp,
                    trace=oauth_trace,
                    note=note,
                )
                return _oauth_retry_result(
                    False,
                    stage="missing_next_url_after_secondary_otp",
                    current_url=current_url,
                    note=note,
                    message="二次 OTP 通过了，但服务端没给下一跳地址。",
                )
            resp, current_url = _follow_redirect_chain_local(
                s_log, next_url, proxies, trace=oauth_trace, stage="post_secondary_otp"
            )

        if "code=" in current_url and "state=" in current_url:
            return _oauth_retry_result(
                True,
                token_json=submit_callback_url(
                    callback_url=current_url,
                    code_verifier=oauth_log.code_verifier,
                    redirect_uri=oauth_log.redirect_uri,
                    expected_state=oauth_log.state,
                    proxies=proxies,
                ),
            )

        if current_url.endswith("/add-phone"):
            hero_sms_note = ""
            if _try_verify_phone_via_hero_sms is None:
                hero_sms_note = "当前环境未成功加载 HeroSMS 模块，无法自动尝试手机号验证。"
            else:
                print(f"[{cfg.ts()}] [INFO] OAuth 链路命中 add-phone，尝试 HeroSMS 自动补过手机号验证...")
                ok, next_url_or_reason = _try_verify_phone_via_hero_sms(
                    session=s_log,
                    proxies=proxies,
                    hint_url=current_url,
                )
                if ok:
                    hero_sms_current_url = str(next_url_or_reason or "").strip()
                    if hero_sms_current_url and hero_sms_current_url != current_url:
                        current_url = hero_sms_current_url
                    print(f"[{cfg.ts()}] [INFO] HeroSMS 手机号验证成功，当前跳转: {_short_text(current_url, 220)}")
                    if "code=" in current_url and "state=" in current_url:
                        return _oauth_retry_result(
                            True,
                            token_json=submit_callback_url(
                                callback_url=current_url,
                                code_verifier=oauth_log.code_verifier,
                                redirect_uri=oauth_log.redirect_uri,
                                expected_state=oauth_log.state,
                                proxies=proxies,
                            ),
                        )
                    if current_url.endswith("/consent") or current_url.endswith("/workspace"):
                        token_json = _select_workspace_and_submit(
                            s_log,
                            oauth_log,
                            proxies=proxies,
                            referer=current_url,
                            trace=oauth_trace,
                            stage="hero_sms_workspace_select",
                        )
                        if token_json:
                            return _oauth_retry_result(True, token_json=token_json)
                        hero_sms_note = "HeroSMS 手机验证已通过，但后续 consent/workspace 链路仍未成功拿到 token。"
                    else:
                        hero_sms_note = (
                            "HeroSMS 手机验证已通过，但当前页面仍未进入可直接提交回调的授权路径: "
                            f"{_short_text(current_url, 220)}"
                        )
                else:
                    hero_sms_note = f"HeroSMS 自动手机号验证失败: {next_url_or_reason}"
                    print(f"[{cfg.ts()}] [WARNING] {hero_sms_note}")

            note = (
                "当前授权流已命中手机号验证页。说明这个账号/会话被要求先完成手机验证，"
                "常见诱因是代理/IP 风险、账号环境命中风控，或该邮箱注册出来的账号被策略要求补充手机号。"
            )
            if hero_sms_note:
                note = f"{note} {hero_sms_note}"
            _log_oauth_chain_failure(
                "phone_verification_required",
                current_url=current_url,
                resp=resp,
                trace=oauth_trace,
                note=note,
            )
            if record_manual_on_add_phone:
                _record_manual_login_required(
                    email,
                    password,
                    stage="phone_verification_required",
                    current_url=current_url,
                    note=note,
                    email_jwt=email_jwt,
                )
            return _oauth_retry_result(
                False,
                status="manual_login_required",
                stage="phone_verification_required",
                current_url=current_url,
                note=note,
                message="仍然命中 add-phone，账号先保留在人工复核列表里。",
            )

        if current_url.endswith("/consent") or current_url.endswith("/workspace"):
            token_json = _select_workspace_and_submit(
                s_log,
                oauth_log,
                proxies=proxies,
                referer=current_url,
                trace=oauth_trace,
                stage="manual_retry_workspace_select",
            )
            if token_json:
                return _oauth_retry_result(True, token_json=token_json)
            note = "命中 consent/workspace，但仍未拿到授权回调。"
            return _oauth_retry_result(
                False,
                stage="manual_retry_workspace_select",
                current_url=current_url,
                note=note,
                message="Workspace/Consent 授权链路没走通，详细看日志。",
            )

        note = "最终既没有命中授权回调，也没有落到可处理的 consent/workspace 路径。"
        _log_oauth_chain_failure(
            "final_oauth_chain_unresolved",
            current_url=current_url,
            resp=resp,
            trace=oauth_trace,
            note=note,
        )
        return _oauth_retry_result(
            False,
            stage="final_oauth_chain_unresolved",
            current_url=current_url,
            note=note,
            message="OAuth 最终停在未知页面，详细看日志里的跳转轨迹。",
        )
    except Exception as e:
        print(f"[{cfg.ts()}] [ERROR] OAuth 重登录兜底发生严重异常: {e}")
        print(f"[{cfg.ts()}] [ERROR] 异常堆栈: {_short_text(traceback.format_exc(), 3000)}")
        return _oauth_retry_result(
            False,
            stage="retry_login_exception",
            note=str(e),
            message="重登录拿 token 过程中出现异常，请看异常堆栈。",
        )

def retry_manual_review_login(
    email: str,
    password: str,
    *,
    email_jwt: str = "",
    proxy: Optional[str] = None,
) -> Dict[str, Any]:
    processed_mails: set = set()
    print(f"[{cfg.ts()}] [INFO] [人工复核] 进入自动补拿 Token 流程: {mask_email(email)}")
    _clear_sentinel_cache()
    print(f"[{cfg.ts()}] [DEBUG] [人工复核] 已清理 sentinel 缓存，准备初始化登录会话。")
    proxy = cfg.format_docker_url(proxy)
    if proxy and proxy.startswith("socks5://"):
        proxy = proxy.replace("socks5://", "socks5h://")
    proxies = {"http": proxy, "https": proxy} if proxy else None

    print(f"[{cfg.ts()}] [INFO] 开始尝试为人工复核账号补拿 Token: {mask_email(email)}")
    if proxy:
        print(f"[{cfg.ts()}] [INFO] 本次人工复核自动登录使用代理: {proxy}")
    result = _retry_oauth_login_flow(
        email,
        password,
        email_jwt=email_jwt,
        proxies=proxies,
        processed_mails=processed_mails,
        record_manual_on_add_phone=False,
    )
    print(
        f"[{cfg.ts()}] [INFO] [人工复核] 自动补拿 Token 流程结束: "
        f"{mask_email(email)}, success={bool(result.get('success'))}, "
        f"stage={result.get('stage') or '-'}"
    )
    return result


def run(proxy: Optional[str], run_ctx: dict = None) -> tuple:
    """完整注册流程"""
    processed_mails: set = set()
    proxy = cfg.format_docker_url(proxy)
    if proxy and proxy.startswith("socks5://"):
        proxy = proxy.replace("socks5://", "socks5h://")
    proxies = {"http": proxy, "https": proxy} if proxy else None
    _clear_sentinel_cache()
    s_reg = requests.Session(proxies=proxies, impersonate="chrome110")
    s_reg.timeout = 30

    if not _skip_net_check():
        try:
            start = time.time()
            res   = s_reg.get(
                "https://cloudflare.com/cdn-cgi/trace",
                proxies=proxies, verify=_ssl_verify(), timeout=10,
            )
            elapsed = time.time() - start
            loc = (re.search(r"^loc=(.+)$", res.text, re.MULTILINE) or [None, None])[1]
            if loc in ("CN", "HK"):
                raise RuntimeError(f"当前{proxies}代理所在地不支持 OpenAI ({loc})")
            print(f"[{cfg.ts()}] [INFO] 节点测活成功！地区: {loc} | 延迟: {elapsed:.2f}s")
        except Exception as e:
            print(f"[{cfg.ts()}] [ERROR] 代理网络检查失败: {e}")
            return None, None

    email, email_jwt = get_email_and_token(proxies)
    if not email:
        return None, None

    password = _generate_password()
    print(f"[{cfg.ts()}] [INFO] 提交注册信息 (密码: {password[:4]}****)")

    oauth_reg = generate_oauth_url()

    try:
        s_reg.get(oauth_reg.auth_url, proxies=proxies, verify=_ssl_verify(), timeout=15)
        did = s_reg.cookies.get("oai-did") or ""
        if not did:
            print(f"[{cfg.ts()}] [WARNING] 未获取到 oai-did，节点环境可能被关注。")

        reg_ctx = {}

        print(f"[{cfg.ts()}] [INFO] 正在计算风控算力挑战...")
        sentinel_signup = _challenge_token(s_reg, "authorize_continue", proxies, ctx=reg_ctx)
        if sentinel_signup:
            print(f"[{cfg.ts()}] [SUCCESS] 算力挑战成功。")
        signup_headers = _oai_headers(
            did,
            {
                "Referer": "https://auth.openai.com/create-account",
                "content-type": "application/json",
            },
        )
        if sentinel_signup:
            signup_headers["openai-sentinel-token"] = sentinel_signup

        signup_resp = _post_with_retry(
            s_reg,
            "https://auth.openai.com/api/accounts/authorize/continue",
            headers=signup_headers,
            json_body={"username": {"value": email, "kind": "email"}, "screen_hint": "signup"},
            proxies=proxies,
        )

        if signup_resp.status_code == 403:
            print(f"[{cfg.ts()}] [WARNING] 注册请求触发 403 拦截，稍作等待后重试...")
            return "retry_403", None
        if signup_resp.status_code != 200:
            _log_registration_http_failure("注册环节", signup_resp)
            return None, None

        sentinel_reg = _challenge_token(
            s_reg, "username_password_create", proxies, use=True, ctx=reg_ctx
        )
        pwd_headers = _oai_headers(
            did,
            {
                "Referer": "https://auth.openai.com/create-account/password",
                "content-type": "application/json",
            },
        )
        if sentinel_reg:
            pwd_headers["openai-sentinel-token"] = sentinel_reg

        pwd_resp = _post_with_retry(
            s_reg,
            "https://auth.openai.com/api/accounts/user/register",
            headers=pwd_headers,
            json_body={"password": password, "username": email},
            proxies=proxies,
        )

        if pwd_resp.status_code != 200:
            if run_ctx is not None:
                run_ctx["pwd_blocked"] = True
            _log_registration_http_failure("密码提交环节", pwd_resp)
            return None, None

        reg_json = _json_dict(pwd_resp)
        need_otp = (
            "verify" in reg_json.get("continue_url", "")
            or "otp"  in (reg_json.get("page") or {}).get("type", "")
        )

        if need_otp:
            if cfg.EMAIL_API_MODE == "luckmail":
                try:
                    from utils.email_providers.luckmail_service import LuckMailService
                    print(f"[{cfg.ts()}] [INFO] 正在检测 LuckMail 邮箱（{mask_email(email)}）是否存活...")
                    lm_service = LuckMailService(
                        api_key=cfg.LUCKMAIL_API_KEY,
                        proxies=proxies if getattr(cfg, 'USE_PROXY_FOR_EMAIL', True) else None
                    )
                    if not lm_service.check_token_alive(email_jwt):
                        print(f"[{cfg.ts()}] [ERROR] 邮箱 已失效，放弃当前注册并重试！")
                        return None, None
                except Exception as e:
                    print(f"[{cfg.ts()}] [WARNING] LuckMail 可用性检测异常(忽略并继续): {e}")
            otp_url = str(reg_json.get("continue_url") or "").strip()
            send_otp_url = "https://auth.openai.com/api/accounts/email-otp/send"
            if otp_url:
                try:
                    otp_headers = _oai_headers(
                        did,
                        {
                            "Referer": "https://auth.openai.com/create-account/password",
                            "content-type": "application/json",
                        },
                    )
                    if sentinel_reg:
                        otp_headers["openai-sentinel-token"] = sentinel_reg
                    _post_with_retry(
                        s_reg,
                        otp_url if otp_url.startswith("http") else f"https://auth.openai.com{otp_url}",
                        headers=otp_headers,
                        json_body={},
                        proxies=proxies,
                        timeout=30,
                    )
                except Exception as e:
                    print(f"[{cfg.ts()}] [WARNING] continue_url 触发 OTP 请求异常: {e}")

            print(f"\n[{cfg.ts()}] [INFO] 正在向 {mask_email(email)} 主动请求发送验证码...")
            try:
                sentinel_send = _challenge_token(s_reg, "authorize_continue", proxies, ctx=reg_ctx)
                send_headers = _oai_headers(
                    did,
                    {
                        "Referer": "https://auth.openai.com/create-account/password",
                        "content-type": "application/json",
                    },
                )
                if sentinel_send:
                    send_headers["openai-sentinel-token"] = sentinel_send
                _post_with_retry(
                    s_reg,
                    send_otp_url,
                    headers=send_headers,
                    json_body={},
                    proxies=proxies,
                    timeout=30,
                )
            except Exception as e:
                print(f"[{cfg.ts()}] [WARNING] OTP 初始发送请求异常: {e}")

            code = ""
            for resend_attempt in range(max(1, cfg.MAX_OTP_RETRIES)):
                if resend_attempt > 0:
                    print(f"\n[{cfg.ts()}] [INFO] 正在重试 {resend_attempt}/{cfg.MAX_OTP_RETRIES}...")
                    try:
                        sentinel_resend = _challenge_token(
                            s_reg, "authorize_continue", proxies, ctx=reg_ctx
                        )
                        resend_headers = _oai_headers(
                            did,
                            {
                                "Referer": "https://auth.openai.com/create-account/password",
                                "content-type": "application/json",
                            },
                        )
                        if sentinel_resend:
                            resend_headers["openai-sentinel-token"] = sentinel_resend
                        _post_with_retry(
                            s_reg,
                            send_otp_url,
                            headers=resend_headers,
                            json_body={},
                            proxies=proxies,
                            timeout=15,
                        )
                        time.sleep(2)
                    except Exception as e:
                        print(f"[{cfg.ts()}] [WARNING] 重新发送请求异常: {e}")
                code = get_oai_code(email, jwt=email_jwt, proxies=proxies,
                                    processed_mail_ids=processed_mails)
                if code:
                    break

            if not code:
                print(f"[{cfg.ts()}] [ERROR] 重试次数上限，丢弃当前 {mask_email(email)} 邮箱。")
                return None, None

            sentinel_otp = _challenge_token(s_reg, "authorize_continue", proxies, ctx=reg_ctx)
            val_headers = _oai_headers(
                did,
                {
                    "Referer": "https://auth.openai.com/email-verification",
                    "content-type": "application/json",
                },
            )
            if sentinel_otp:
                val_headers["openai-sentinel-token"] = sentinel_otp
            code_resp = _post_with_retry(
                s_reg,
                "https://auth.openai.com/api/accounts/email-otp/validate",
                headers=val_headers,
                json_body={"code": code},
                proxies=proxies,
            )
            if code_resp.status_code != 200:
                print(f"[{cfg.ts()}] [ERROR] 验证码校验未通过: {code_resp.text}")
                return None, None

        about_you_referer = "https://auth.openai.com/about-you"
        if need_otp:
            code_resp_json = _json_dict(code_resp)
            about_you_url = _extract_next_url(code_resp_json)
            if about_you_url:
                print(
                    f"[{cfg.ts()}] [INFO] 邮箱验证码校验通过，继续推进注册资料页: "
                    f"{_short_text(about_you_url, 180)}"
                )
                _, about_you_referer = _follow_redirect_chain_local(
                    s_reg,
                    about_you_url,
                    proxies,
                    stage="signup_post_email_otp",
                )
                if "code=" in about_you_referer and "state=" in about_you_referer:
                    print(f"[{cfg.ts()}] [SUCCESS] 邮箱验证后已直接命中授权回调。")
                    return submit_callback_url(
                        callback_url=about_you_referer,
                        expected_state=oauth_reg.state,
                        code_verifier=oauth_reg.code_verifier,
                        redirect_uri=oauth_reg.redirect_uri,
                        proxies=proxies,
                    ), password

        try:
            about_you_resp = s_reg.get(
                about_you_referer,
                proxies=proxies,
                verify=_ssl_verify(),
                timeout=15,
            )
            about_you_referer = str(getattr(about_you_resp, "url", "") or about_you_referer)
            if about_you_referer.endswith("/add-phone"):
                if run_ctx is not None:
                    run_ctx["phone_verify"] = True
                note = "提交账户资料前已命中手机号验证页，无法继续自动化创建账户。"
                _log_oauth_chain_failure(
                    "signup_profile_phone_verification",
                    current_url=about_you_referer,
                    resp=about_you_resp,
                    note=note,
                )
                _record_manual_login_required(
                    email,
                    password,
                    stage="signup_profile_phone_verification",
                    current_url=about_you_referer,
                    note=note,
                    email_jwt=email_jwt,
                )
                return None, None
            if getattr(about_you_resp, "status_code", 0) not in (200, 204):
                print(f"[{cfg.ts()}] [WARNING] 注册资料页预热返回异常: {_response_debug_summary(about_you_resp)}")
        except Exception as e:
            print(f"[{cfg.ts()}] [WARNING] 注册资料页预热失败，将直接提交账户资料: {e}")

        user_info = generate_random_user_info()
        print(f"[{cfg.ts()}] [INFO] 初始化账户信息 "
              f"(昵称: {user_info['name']}, 生日: {user_info['birthdate']})...")

        sentinel_create = _challenge_token(s_reg, "create_account", proxies, use=True, ctx=reg_ctx)
        create_headers = _oai_headers(
            did,
            {
                "Referer": about_you_referer,
                "content-type": "application/json",
            },
        )
        if sentinel_create:
            create_headers["openai-sentinel-token"] = sentinel_create
        create_account_resp = _post_with_retry(
            s_reg,
            "https://auth.openai.com/api/accounts/create_account",
            headers=create_headers,
            json_body=user_info,
            proxies=proxies,
        )

        if create_account_resp.status_code != 200:
            _log_registration_http_failure("账户创建", create_account_resp)
            return None, None

        create_account_json = _json_dict(create_account_resp)

        auth_cookie = s_reg.cookies.get("oai-client-auth-session") or ""
        workspaces  = _parse_workspace_from_auth_cookie(auth_cookie)
        has_workspace = bool(workspaces)

        print(f"[{cfg.ts()}] [INFO] 基础信息建立完毕，优先沿当前注册会话提取最终凭据...")
        direct_trace = []
        direct_current_url = ""
        post_create_url = _extract_next_url(create_account_json)

        if post_create_url:
            _, direct_current_url = _follow_redirect_chain_local(
                s_reg,
                post_create_url,
                proxies,
                trace=direct_trace,
                stage="post_create_account",
            )
            if "code=" in direct_current_url and "state=" in direct_current_url:
                print(f"[{cfg.ts()}] [SUCCESS] 当前注册会话已直接命中授权回调。")
                return submit_callback_url(
                    callback_url=direct_current_url,
                    expected_state=oauth_reg.state,
                    code_verifier=oauth_reg.code_verifier,
                    redirect_uri=oauth_reg.redirect_uri,
                    proxies=proxies,
                ), password

        if has_workspace or direct_current_url.endswith("/consent") or direct_current_url.endswith("/workspace"):
            token_json = _select_workspace_and_submit(
                s_reg,
                oauth_reg,
                proxies=proxies,
                referer=direct_current_url or post_create_url or about_you_referer,
                trace=direct_trace,
                stage="direct_workspace_select",
            )
            if token_json:
                print(f"[{cfg.ts()}] [SUCCESS] 当前注册会话提取最终凭据成功。")
                return token_json, password

        if direct_current_url.endswith("/add-phone"):
            if run_ctx is not None:
                run_ctx["phone_verify"] = True
            print(
                f"[{cfg.ts()}] [WARNING] 当前注册会话已命中手机号验证页，"
                f"继续静风控重登录大概率仍会被拦截，仅作为最后兜底尝试。"
            )
        elif direct_trace:
            print(f"[{cfg.ts()}] [WARNING] 当前注册会话未直接拿到最终凭据，转入静风控重登录兜底。")
            for idx, item in enumerate(direct_trace[-5:], 1):
                print(f"[{cfg.ts()}] [DEBUG] 当前会话提凭据轨迹[{idx}]: {item}")

        wait_time = random.randint(cfg.LOGIN_DELAY_MIN, cfg.LOGIN_DELAY_MAX)
        print(f"[{cfg.ts()}] [INFO] 等待 {wait_time} 秒后执行静风控重登录兜底...")
        time.sleep(wait_time)

        print(f"[{cfg.ts()}] [INFO] 基础信息建立完毕，执行静风控重登录...")
        retry_result = _retry_oauth_login_flow(
            email,
            password,
            email_jwt=email_jwt,
            proxies=proxies,
            processed_mails=processed_mails,
            record_manual_on_add_phone=True,
        )
        if run_ctx is not None:
            retry_url = str(retry_result.get("current_url") or "")
            retry_stage = str(retry_result.get("stage") or "")
            retry_status = str(retry_result.get("status") or "")
            if (
                retry_status == "manual_login_required"
                or retry_stage == "phone_verification_required"
                or "/add-phone" in retry_url
            ):
                run_ctx["phone_verify"] = True
        if retry_result.get("success"):
            return retry_result.get("token_json"), password
        return None, None

    except Exception as e:
        print(f"[{cfg.ts()}] [ERROR] 注册主流程发生严重异常: {e}")
        print(f"[{cfg.ts()}] [ERROR] 异常堆栈: {_short_text(traceback.format_exc(), 3000)}")
        return None, None

def refresh_oauth_token(refresh_token: str, proxies: Any = None) -> Tuple[bool, dict]:
    """用 refresh_token 换取新的 access_token。"""
    if not refresh_token:
        return False, {"error": "无 refresh_token"}
    try:
        resp = requests.post(
            TOKEN_URL,
            data={
                "client_id":     CLIENT_ID,
                "grant_type":    "refresh_token",
                "refresh_token": refresh_token,
                "redirect_uri":  DEFAULT_REDIRECT_URI,
            },
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept":       "application/json",
            },
            proxies=proxies,
            verify=_ssl_verify(),
            timeout=30,
            impersonate="chrome110",
        )
        if resp.status_code == 200:
            data      = resp.json()
            now       = int(time.time())
            expires_in = _to_int(data.get("expires_in", 3600))
            return True, {
                "access_token":  data.get("access_token"),
                "refresh_token": data.get("refresh_token", refresh_token),
                "id_token":      data.get("id_token"),
                "last_refresh":  time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
                "expired":       time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                               time.gmtime(now + max(expires_in, 0))),
            }
        return False, {"error": f"HTTP {resp.status_code}"}
    except Exception as e:
        return False, {"error": str(e)}
