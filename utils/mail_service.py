import imaplib
import json
import random
import re
import socket
import string
import time
import threading
from email import message_from_string
from email.header import decode_header, make_header
from email.message import Message
from email.policy import default as email_policy
from email.utils import getaddresses, parsedate_to_datetime
from html import unescape
from typing import Any, Optional
from urllib.parse import urlparse

import socks
from curl_cffi import requests
from utils import config as cfg
from utils.ai_service import AIService
from utils.gmail_service import get_gmail_otp_via_oauth
from utils.duckmail_service import DuckMailService

def patch_global_socket():
    """在底层强制劫持所有网络请求走 SOCKS5 (智能支持 HTTP 转 SOCKS5)"""
    if getattr(cfg, 'USE_PROXY_FOR_EMAIL', False) and getattr(cfg, 'DEFAULT_PROXY', ""):
        try:
            parsed = urlparse(cfg.DEFAULT_PROXY)
            proxy_host = parsed.hostname
            proxy_port = parsed.port or (7890 if "http" in parsed.scheme else 1080)

            socks.set_default_proxy(socks.SOCKS5, proxy_host, proxy_port, rdns=True)
            socket.socket = socks.socksocket

            scheme_used = parsed.scheme.lower()
            if scheme_used in ("http", "https"):
                print(f"[{cfg.ts()}] [INFO] 已将 HTTP 代理强制升级为 SOCKS5 全局劫持 (目标: {proxy_host}:{proxy_port})")
            else:
                print(f"[{cfg.ts()}] [INFO] 已开启全局 SOCKS5 劫持 (目标: {proxy_host}:{proxy_port})")

        except Exception as e:
            print(f"[{cfg.ts()}] [ERROR] 全局代理劫持失败: {e}")



patch_global_socket()

luckmail_lock = threading.Lock()

_CM_TOKEN_CACHE: Optional[str] = None

_thread_data = threading.local()
_orig_sleep = time.sleep
LOCAL_USED_PIDS = set()
AI_NAME_POOL = []
AI_KW_POOL = []
FIRST_NAMES = [
    "james", "john", "robert", "michael", "william", "david", "richard", "joseph", "thomas", "charles",
    "christopher", "daniel", "matthew", "anthony", "mark", "donald", "steven", "paul", "andrew", "joshua"
]
LAST_NAMES = [
    "smith", "johnson", "williams", "brown", "jones", "garcia", "miller", "davis", "rodriguez", "martinez",
    "hernandez", "lopez", "gonzalez", "wilson", "anderson", "thomas", "taylor", "moore", "jackson", "martin"
]


def _safe_set_tag(lm_service, p_id, tag_id):
    """带重试机制的异步打标，防止网络波动导致打标失败变成死循环号"""
    for _ in range(3):
        try:
            if lm_service.set_email_tag(p_id, tag_id):
                return
        except Exception:
            pass
        time.sleep(2)


def clear_sticky_domain():
    """注册失败时调用"""
    if hasattr(_thread_data, 'sticky_domain'):
        _thread_data.sticky_domain = None


def set_last_email(email: str):
    _thread_data.last_attempt_email = email


def get_last_email() -> Optional[str]:
    return getattr(_thread_data, 'last_attempt_email', None)


def _smart_sleep(secs):
    for _ in range(int(secs * 10)):
        if getattr(cfg, 'GLOBAL_STOP', False):
            return
        _orig_sleep(0.1)


time.sleep = _smart_sleep


def _ssl_verify() -> bool:
    import os
    flag = os.getenv("OPENAI_SSL_VERIFY", "1").strip().lower()
    return flag not in {"0", "false", "no", "off"}


def mask_email(text: str) -> str:
    """日志脱敏：隐藏邮箱域名部分。"""
    if not cfg.ENABLE_EMAIL_MASKING or not text:
        return text
    if "@" in text:
        prefix, _ = text.split("@", 1)
        return f"{prefix}@***.***"

    domain_match = re.match(r"^([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|\d{1,3}(?:\.\d{1,3}){3})(:\d+)?$", text)
    if domain_match:
        domain_or_ip = domain_match.group(1)
        port = domain_match.group(2) or ""
        keep = min(4, max(2, len(domain_or_ip) // 3))
        prefix = domain_or_ip[:keep]
        return f"{prefix}***.***{port}"

    match = re.match(r"token_(.+)_(\d{10,})\.json", text)
    if match:
        ep, ts_ = match.group(1), match.group(2)
        return f"token_{ep[:len(ep) // 2]}***_{ts_}.json"
    if len(text) > 8 and ".json" in text:
        name_part = text.replace(".json", "")
        return f"{name_part[:len(name_part) // 2]}***.json"
    return text


def _reset_cm_token_cache() -> None:
    global _CM_TOKEN_CACHE
    _CM_TOKEN_CACHE = None


def get_cm_token(proxies=None) -> Optional[str]:
    global _CM_TOKEN_CACHE
    if _CM_TOKEN_CACHE:
        return _CM_TOKEN_CACHE
    try:
        url = f"{cfg.CM_API_URL}/api/public/genToken"
        payload = {"email": cfg.CM_ADMIN_EMAIL, "password": cfg.CM_ADMIN_PASS}
        res = requests.post(url, json=payload, proxies=proxies,
                            verify=_ssl_verify(), timeout=15)
        data = res.json()
        if data.get("code") == 200:
            _CM_TOKEN_CACHE = data["data"]["token"]
            return _CM_TOKEN_CACHE
        print(f"[{cfg.ts()}] [ERROR] CloudMail Token 生成失败: {data.get('message')}")
    except Exception as e:
        print(f"[{cfg.ts()}] [ERROR] CloudMail 接口请求异常: {e}")
    return None


def _get_ai_data_package():
    global AI_NAME_POOL, AI_KW_POOL
    ai_enabled = getattr(cfg, 'AI_ENABLE_PROFILE', False)

    if ai_enabled:
        ai = AIService()
        if len(AI_NAME_POOL) < 5: AI_NAME_POOL.extend(ai.fetch_names())
        if len(AI_KW_POOL) < 10: AI_KW_POOL.extend(ai.fetch_keywords())
        if AI_NAME_POOL:
            return AI_NAME_POOL.pop(0), True

    letters = "".join(random.choices(string.ascii_lowercase, k=5))
    digits = "".join(random.choices(string.digits, k=3))
    return f"{letters}{digits}", False


def get_email_and_token(proxies: Any = None) -> tuple:
    """兼容五种邮箱模式的地址创建，返回 (email, token_or_id)。"""
    if getattr(cfg, 'GLOBAL_STOP', False): return None, None
    _thread_data.last_attempt_email = None

    mode = cfg.EMAIL_API_MODE
    mail_proxies = proxies if cfg.USE_PROXY_FOR_EMAIL else None

    if mode == "mail_curl":
        try:
            url = f"{cfg.MC_API_BASE}/api/remail?key={cfg.MC_KEY}"
            res = requests.post(url, proxies=mail_proxies, verify=_ssl_verify(), timeout=15)
            data = res.json()
            if data.get("email") and data.get("id"):
                email = data["email"]
                mailbox_id = data["id"]
                set_last_email(email)
                print(f"[{cfg.ts()}] [INFO] mail-curl 分配邮箱: ({mask_email(email)}) (BoxID: {mailbox_id})")
                return email, mailbox_id
        except Exception as e:
            print(f"[{cfg.ts()}] [ERROR] mail-curl 获取邮箱异常: {e}")
        return None, None

    if mode == "luckmail":
        try:
            from utils.luckmail_service import LuckMailService
            lm_service = LuckMailService(
                api_key=cfg.LUCKMAIL_API_KEY,
                preferred_domain=getattr(cfg, 'LUCKMAIL_PREFERRED_DOMAIN', ""),
                proxies=mail_proxies,
                email_type=getattr(cfg, 'LUCKMAIL_EMAIL_TYPE', "ms_graph"),
                variant_mode=getattr(cfg, 'LUCKMAIL_VARIANT_MODE', "")
            )

            tag_id = getattr(cfg, 'LUCKMAIL_TAG_ID', None)
            if not tag_id:
                with luckmail_lock:
                    tag_id = getattr(cfg, 'LUCKMAIL_TAG_ID', None)
                    if not tag_id:
                        tag_id = lm_service.get_or_create_tag_id("已使用")
                        if tag_id:
                            cfg.LUCKMAIL_TAG_ID = tag_id
                            try:
                                import yaml
                                with cfg.CONFIG_FILE_LOCK:
                                    with open(cfg.CONFIG_PATH, "r", encoding="utf-8") as f:
                                        y = yaml.safe_load(f) or {}
                                    y.setdefault("luckmail", {})["tag_id"] = tag_id
                                    with open(cfg.CONFIG_PATH, "w", encoding="utf-8") as f:
                                        yaml.dump(y, f, allow_unicode=True, sort_keys=False)
                                print(f"[{cfg.ts()}] [系统] 标签 ID {tag_id} 已同步至配置文件")
                            except Exception as e:
                                print(f"[{cfg.ts()}] [WARNING] 配置文件写入失败: {e}")

            if getattr(cfg, 'LUCKMAIL_REUSE_PURCHASED', False):
                with luckmail_lock:
                    email, token, p_id = lm_service.get_random_purchased_email(tag_id=tag_id,
                                                                               local_used_pids=LOCAL_USED_PIDS)
                    if p_id:
                        LOCAL_USED_PIDS.add(p_id)

                if email and token:
                    print(f"[{cfg.ts()}] [SUCCESS] LuckMail 成功复用历史邮箱: ({mask_email(email)})")
                    if p_id and tag_id:
                        threading.Thread(target=_safe_set_tag, args=(lm_service, p_id, tag_id), daemon=True).start()
                    return email, token
                print(f"[{cfg.ts()}] [WARNING] 未找到符合条件的历史邮箱，准备购买新号...")

            email, token, p_id = lm_service.get_email_and_token(auto_tag=False)

            if email and token:
                if p_id:
                    with luckmail_lock:
                        LOCAL_USED_PIDS.add(p_id)

                print(f"[{cfg.ts()}] [INFO] LuckMail 成功购买新邮箱: ({mask_email(email)})")

                if p_id and tag_id:
                    threading.Thread(target=_safe_set_tag, args=(lm_service, p_id, tag_id), daemon=True).start()
                return email, token

        except Exception as e:
            print(f"[{cfg.ts()}] [ERROR] LuckMail 流程异常: {e}")
            return None, None

    if mode == "duckmail":
        try:
            from utils.duckmail_service import DuckMailService
            duck_use_proxy = getattr(cfg, 'DUCK_USE_PROXY', True)
            duck_proxies = proxies if duck_use_proxy else None
            ds = DuckMailService(proxies=duck_proxies)
            email, token = ds.create_email()
            if email:
                set_last_email(email)
                print(f"[{cfg.ts()}] [INFO] DuckMail ({ds.mode}) 成功创建邮箱: {mask_email(email)}")
                return email, token
            else:
                print(f"[{cfg.ts()}] [ERROR] DuckMail 获取邮箱失败")
        except Exception as e:
            print(f"[{cfg.ts()}] [ERROR] DuckMail 流程异常: {e}")
        return None, None

    if mode == "generator_email":
        try:
            from utils.generator_email_service import GeneratorEmailService
            ge_service = GeneratorEmailService(proxies=mail_proxies)
            email, token = ge_service.create_email()

            if email and token:
                set_last_email(email)
                print(f"[{cfg.ts()}] [INFO] GeneratorEmail 成功创建邮箱: ({mask_email(email)})")
                return email, token
            else:
                print(f"[{cfg.ts()}] [ERROR] GeneratorEmail 获取邮箱失败")
        except Exception as e:
            print(f"[{cfg.ts()}] [ERROR] GeneratorEmail 流程异常: {e}")
        return None, None

    if mode == "tempmail":
        try:
            from utils.tempmail_service import TempmailService
            tm_service = TempmailService(proxies=mail_proxies)
            email, token = tm_service.create_email()

            if email and token:
                set_last_email(email)
                print(f"[{cfg.ts()}] [INFO] Tempmail 成功创建邮箱: ({mask_email(email)})")
                return email, token
            else:
                print(f"[{cfg.ts()}] [ERROR] Tempmail 获取邮箱失败")
        except Exception as e:
            print(f"[{cfg.ts()}] [ERROR] Tempmail 流程异常: {e}")
        return None, None
    if mode == "tempmail_org":
        try:
            from utils.tempmail_org import TempMailOrgService
            tm_org = TempMailOrgService(proxies=mail_proxies)
            email, token = tm_org.create_email()

            if email and token:
                set_last_email(email)
                print(f"[{cfg.ts()}] [INFO] TempMail.org 成功创建邮箱: ({mask_email(email)})")
                return email, token
            else:
                print(f"[{cfg.ts()}] [ERROR] TempMail.org 获取邮箱失败")
        except Exception as e:
            print(f"[{cfg.ts()}] [ERROR] TempMail.org 流程异常: {e}")
        return None, None

    ai_switch_on = getattr(cfg, 'AI_ENABLE_PROFILE', False)
    if ai_switch_on:
        print(f"[{cfg.ts()}] [AI-状态] 已开启 AI 智能邮箱域名信息增强...")

    prefix, ai_enabled = _get_ai_data_package()

    if cfg.ENABLE_SUB_DOMAINS:
        sticky = getattr(_thread_data, 'sticky_domain', None)
        if sticky:
            selected_domain = sticky
            print(f"[{cfg.ts()}] [INFO] 多级域名模式 - 沿用上一轮成功域名: {mask_email(selected_domain)}")
        else:
            main_list = [d.strip() for d in cfg.MAIL_DOMAINS.split(",") if d.strip()]
            if not main_list:
                print(f"[{cfg.ts()}] [ERROR] 未配置主域名池，无法捏造子域！")
                return None, None

            selected_main = random.choice(main_list)
            if getattr(cfg, 'RANDOM_SUB_DOMAIN_LEVEL', False):
                level = random.randint(1, 7)
            else:
                try:
                    level = int(getattr(cfg, 'SUB_DOMAIN_LEVEL', 1))
                except:
                    level = 1

            random_parts = []
            for _ in range(level):
                if ai_enabled and AI_KW_POOL:
                    kw = AI_KW_POOL.pop(0)
                    random_parts.append(f"{kw}-{''.join(random.choices(string.ascii_lowercase + string.digits, k=4))}")
                else:
                    random_parts.append(''.join(random.choices(string.ascii_lowercase + string.digits, k=8)))

            selected_domain = ".".join(random_parts) + f".{selected_main}"
            _thread_data.sticky_domain = selected_domain
    else:
        domain_list = [d.strip() for d in cfg.MAIL_DOMAINS.split(",") if d.strip()]
        if not domain_list:
            print(f"[{cfg.ts()}] [ERROR] 域名池配置为空，无法生成邮箱！")
            return None, None
        selected_domain = random.choice(domain_list)

    email_str = f"{prefix}@{selected_domain}"
    set_last_email(email_str)

    if mode == "cloudmail":
        token = get_cm_token(mail_proxies)
        if not token:
            print(f"[{cfg.ts()}] [ERROR] 未能获取 CloudMail Token，跳过注册")
            return None, None
        try:
            res = requests.post(
                f"{cfg.CM_API_URL}/api/public/addUser",
                headers={"Authorization": token},
                json={"list": [{"email": email_str}]},
                proxies=mail_proxies, timeout=15,
            )
            if res.json().get("code") == 200:
                print(f"[{cfg.ts()}] [INFO] CloudMail 成功创建邮箱: {mask_email(email_str)}")
                return email_str, ""
            print(f"[{cfg.ts()}] [ERROR] CloudMail 邮箱创建失败: {res.text}")
        except Exception as e:
            print(f"[{cfg.ts()}] [ERROR] CloudMail 邮箱创建异常: {e}")
        return None, None

    if mode == "freemail":
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {cfg.FREEMAIL_API_TOKEN}"
        }
        for attempt in range(5):
            if getattr(cfg, 'GLOBAL_STOP', False): return None, None
            try:
                res = requests.post(f"{cfg.FREEMAIL_API_URL.rstrip('/')}/api/create",
                                    json={"email": email_str}, headers=headers,
                                    proxies=mail_proxies, verify=_ssl_verify(), timeout=15)
                res.raise_for_status()
                print(f"[{cfg.ts()}] [INFO] 成功通过 Freemail 指定创建邮箱: {mask_email(email_str)}")
                return email_str, ""
            except Exception as e:
                print(f"[{cfg.ts()}] [ERROR] Freemail 邮箱创建异常: {e}")
                time.sleep(2)
        return None, None

    if mode == "imap":
        print(f"[{cfg.ts()}] [INFO] imap成功生成临时域名邮箱: {email_str}")
        return email_str, ""

    if mode == "cloudflare_temp_email":
        headers = {"x-admin-auth": cfg.ADMIN_AUTH, "Content-Type": "application/json"}
        body = {"enablePrefix": False, "name": prefix, "domain": selected_domain}
        for attempt in range(5):
            if getattr(cfg, 'GLOBAL_STOP', False): return None, None
            try:
                res = requests.post(
                    f"{cfg.GPTMAIL_BASE}/admin/new_address",
                    headers=headers, json=body,
                    proxies=mail_proxies, verify=_ssl_verify(), timeout=15,
                )
                res.raise_for_status()
                data = res.json()
                if data and data.get("address"):
                    email = data["address"].strip()
                    jwt = data.get("jwt", "").strip()
                    set_last_email(email)
                    print(f"[{cfg.ts()}] [INFO] cloudflare_temp_email成功获取临时邮箱: {mask_email(email)}")
                    return email, jwt
                print(f"[{cfg.ts()}] [WARNING] cloudflare_temp_email邮箱申请失败 (尝试 {attempt + 1}/5): {res.text}")
                time.sleep(1)
            except Exception as e:
                print(f"[{cfg.ts()}] [ERROR] cloudflare_temp_email邮箱注册网络异常，准备重试: {e}")
                time.sleep(2)
        return None, None


def _decode_mime_header(value: str) -> str:
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return value


def _extract_body_from_message(message: Message) -> str:
    parts = []
    if message.is_multipart():
        for part in message.walk():
            if part.get_content_maintype() == "multipart":
                continue
            ct = (part.get_content_type() or "").lower()
            if ct not in ("text/plain", "text/html"):
                continue
            try:
                payload = part.get_payload(decode=True)
                charset = part.get_content_charset() or "utf-8"
                text = payload.decode(charset, errors="replace") if payload else ""
            except Exception:
                try:
                    text = part.get_content()
                except Exception:
                    text = ""
            if ct == "text/html":
                text = re.sub(r"<[^>]+>", " ", text)
            parts.append(text)
    else:
        try:
            payload = message.get_payload(decode=True)
            charset = message.get_content_charset() or "utf-8"
            body = payload.decode(charset, errors="replace") if payload else ""
        except Exception:
            try:
                body = message.get_content()
            except Exception:
                body = str(message.get_payload() or "")
        if "html" in (message.get_content_type() or "").lower():
            body = re.sub(r"<[^>]+>", " ", body)
        parts.append(body)
    return unescape("\n".join(p for p in parts if p).strip())


def _message_timestamp(message: Message) -> Optional[float]:
    raw_date = message.get("Date")
    if not raw_date:
        return None
    try:
        return parsedate_to_datetime(raw_date).timestamp()
    except Exception:
        return None


def _recipient_matches_imap_message(message: Message, email_addr: str, body: str) -> bool:
    email_lower = (email_addr or "").lower()
    if not email_lower:
        return False

    header_values = []
    for header_name in ("To", "Cc", "Delivered-To", "X-Original-To", "X-Forwarded-To"):
        for header_value in message.get_all(header_name, []):
            header_values.append(_decode_mime_header(str(header_value)))

    addresses = [addr.lower() for _, addr in getaddresses(header_values) if addr]
    if any(email_lower == addr or email_lower in addr for addr in addresses):
        return True
    if any(email_lower in value.lower() for value in header_values):
        return True
    return email_lower in (body or "").lower()


def _preview_text(value: str, limit: int = 120) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    if not text:
        return ""
    return text if len(text) <= limit else f"{text[:limit]}..."


def _extract_mail_fields(mail: dict) -> dict:
    sender = str(
        mail.get("source") or mail.get("from") or
        mail.get("from_address") or mail.get("fromAddress") or ""
    ).strip()
    subject = str(mail.get("subject") or mail.get("title") or "").strip()
    body_text = str(
        mail.get("text") or mail.get("body") or
        mail.get("content") or mail.get("html") or ""
    ).strip()
    raw = str(mail.get("raw") or "").strip()
    if raw:
        try:
            msg = message_from_string(raw, policy=email_policy)
            sender = sender or _decode_mime_header(msg.get("From", ""))
            subject = subject or _decode_mime_header(msg.get("Subject", ""))
            parsed = _extract_body_from_message(msg)
            body_text = (f"{body_text}\n{parsed}".strip() if body_text else parsed) if parsed else body_text
        except Exception:
            body_text = f"{body_text}\n{raw}".strip() if body_text else raw
    body_text = unescape(re.sub(r"<[^>]+>", " ", body_text))
    return {"sender": sender, "subject": subject, "body": body_text, "raw": raw}


OTP_CODE_PATTERN = r"(?<!\d)(\d{6})(?!\d)"


def _extract_otp_code(content: str) -> str:
    if not content:
        return ""
    patterns = [
        r"(?i)Your ChatGPT code is\s*(\d{6})",
        r"(?i)ChatGPT code is\s*(\d{6})",
        r"(?i)verification code to continue:\s*(\d{6})",
        r"(?i)Subject:.*?(\d{6})",
    ]
    for p in patterns:
        m = re.search(p, content)
        if m:
            return m.group(1)
    fallback = re.search(r"(?<!\d)(\d{6})(?!\d)", content)
    return fallback.group(1) if fallback else ""


def _create_imap_conn():
    """使用原生方式建立 IMAP 连接"""
    return imaplib.IMAP4_SSL(cfg.IMAP_SERVER, cfg.IMAP_PORT, timeout=15)


def _should_send_imap_id():
    """网易系 IMAP 服务器在 SELECT 前通常要求发送 ID 标识。"""
    host = str(cfg.IMAP_SERVER or "").lower()
    user = str(cfg.IMAP_USER or "").lower()
    netease_hosts = ("163.com", "126.com", "yeah.net", "188.com")
    netease_domains = ("@163.com", "@126.com", "@yeah.net", "@188.com")
    return any(key in host for key in netease_hosts) or user.endswith(netease_domains)


def _imap_quote(value: str) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"')


def _send_imap_id_if_needed(mail_conn):
    if not _should_send_imap_id():
        print(
            f"\n[{cfg.ts()}] [INFO] 当前 IMAP 服务器无需发送 ID 标识: "
            f"server={cfg.IMAP_SERVER}, user={mask_email(str(cfg.IMAP_USER))}"
        )
        return

    support_email = cfg.IMAP_USER if "@" in str(cfg.IMAP_USER) else "noreply@example.com"
    id_pairs = [
        ("name", "openai-cpa"),
        ("version", "1.0.0"),
        ("vendor", "openai-cpa"),
        ("support-email", support_email),
    ]
    payload = " ".join(f'"{key}" "{_imap_quote(value)}"' for key, value in id_pairs if value)
    if not payload:
        return

    try:
        command = getattr(mail_conn, "xatom", None) or getattr(mail_conn, "_simple_command", None)
        if not command:
            print(f"\n[{cfg.ts()}] [WARNING] 当前 IMAP 客户端不支持 ID 命令，跳过 163 邮箱特殊处理。")
            return
        typ, data = command("ID", f"({payload})")
        if str(typ).upper() == "OK":
            print(f"\n[{cfg.ts()}] [INFO] 已发送 IMAP ID 标识。")
        else:
            print(f"\n[{cfg.ts()}] [WARNING] IMAP ID 返回异常: {typ} {data}")
    except Exception as e:
        print(f"\n[{cfg.ts()}] [WARNING] 发送 IMAP ID 失败（忽略，继续）: {e}")


def _create_and_login_imap_conn():
    """建立并登录 IMAP 连接，必要时补发 ID 标识。"""
    print(
        f"\n[{cfg.ts()}] [INFO] 正在连接 IMAP 服务器: "
        f"{cfg.IMAP_SERVER}:{cfg.IMAP_PORT} ({mask_email(str(cfg.IMAP_USER))})"
    )
    mail_conn = _create_imap_conn()
    try:
        mail_conn.login(cfg.IMAP_USER, cfg.IMAP_PASS.replace(" ", ""))
        print(f"\n[{cfg.ts()}] [INFO] IMAP 登录成功，开始检查 ID 标识要求。")
        _send_imap_id_if_needed(mail_conn)
        return mail_conn
    except Exception:
        try:
            mail_conn.logout()
        except Exception:
            pass
        raise
def get_oai_code(
        email: str,
        jwt: str = "",
        proxies: Any = None,
        processed_mail_ids: set = None,
        pattern: str = OTP_CODE_PATTERN,
) -> str:
    """轮询各邮箱服务商收取 OpenAI 验证码，返回 6 位字符串或空串。"""
    mailbox_id = jwt
    mail_proxies = proxies if cfg.USE_PROXY_FOR_EMAIL else None
    base_url = cfg.GPTMAIL_BASE.rstrip("/")
    mode = cfg.EMAIL_API_MODE
    imap_wait_started_at = time.time()

    print(f"\n[{cfg.ts()}] [INFO] 等待接收验证码 ({mask_email(email)})...")

    if processed_mail_ids is None:
        processed_mail_ids = set()

    mail_conn = None
    if mode == "imap":
        print(
            f"\n[{cfg.ts()}] [INFO] 当前邮箱接码模式: IMAP 直连，"
            f"网易系 ID 特殊处理={'开启' if _should_send_imap_id() else '跳过'}。"
        )
        try:
            mail_conn = _create_and_login_imap_conn()
        except Exception as e:
            extra_tip = ""
            if "unsafe login" in str(e).lower() and _should_send_imap_id():
                extra_tip = "，请确认邮箱已开启 IMAP 并使用客户端授权码"
            print(f"\n[{cfg.ts()}] [ERROR] IMAP 初始登录失败: {e}{extra_tip}")
            mail_conn = None

    for attempt in range(1, 21):
        if getattr(cfg, 'GLOBAL_STOP', False): return ""
        try:
            if mode == "mail_curl":
                inbox_url = (f"{cfg.MC_API_BASE}/api/inbox"
                             f"?key={cfg.MC_KEY}&mailbox_id={mailbox_id}")
                res = requests.get(inbox_url, proxies=mail_proxies,
                                   verify=_ssl_verify(), timeout=10)
                if res.status_code == 200:
                    for mail_item in (res.json() or []):
                        m_id = mail_item.get("mail_id")
                        s_name = mail_item.get("sender_name", "").lower()
                        if m_id and m_id not in processed_mail_ids and "openai" in s_name:
                            detail_res = requests.get(
                                f"{cfg.MC_API_BASE}/api/mail"
                                f"?key={cfg.MC_KEY}&id={m_id}",
                                proxies=mail_proxies, verify=_ssl_verify(), timeout=10,
                            )
                            if detail_res.status_code == 200:
                                d = detail_res.json()
                                body = (f"{d.get('subject', '')}\n"
                                        f"{d.get('content', '')}\n"
                                        f"{d.get('html', '')}")
                                code = _extract_otp_code(body)
                                if code:
                                    processed_mail_ids.add(m_id)
                                    print(f"\n[{cfg.ts()}] [SUCCESS] mail_curl ({mask_email(email)})邮箱提取成功: {code}")
                                    return code

            elif mode == "cloudmail":
                token = get_cm_token(mail_proxies)
                if token:
                    res = requests.post(
                        f"{cfg.CM_API_URL}/api/public/emailList",
                        headers={"Authorization": token},
                        json={"toEmail": email, "timeSort": "desc", "size": 10},
                        proxies=mail_proxies, timeout=15,
                    )
                    if res.status_code == 200:
                        for m in res.json().get("data", []):
                            m_id = str(m.get("emailId"))
                            if m_id in processed_mail_ids:
                                continue
                            content = f"{m.get('subject', '')}\n{m.get('text', '')}"
                            if ("openai" in m.get("sendEmail", "").lower() or
                                    "openai" in content.lower()):
                                code = _extract_otp_code(content)
                                if code:
                                    processed_mail_ids.add(m_id)
                                    print(f"\n[{cfg.ts()}] [SUCCESS] CloudMail ({mask_email(email)})邮箱提取成功: {code}")
                                    return code
            elif mode == "duckmail":
                duck_use_proxy = getattr(cfg, 'DUCK_USE_PROXY', True)
                duck_proxies = proxies if duck_use_proxy else None
                ds = DuckMailService(proxies=duck_proxies)
                duck_run_mode = getattr(cfg, 'DUCKMAIL_MODE', 'duck_official')

                if duck_run_mode == "duck_official":
                    forward_mode = getattr(cfg, 'DUCKMAIL_FORWARD_MODE', 'Gmail_OAuth')
                    forward_email = getattr(cfg, 'DUCKMAIL_FORWARD_EMAIL', '')
                    if forward_mode == "Gmail_OAuth":
                        otp_code = get_gmail_otp_via_oauth(email, mail_proxies)
                        if otp_code:
                            print(
                                f"\n[{cfg.ts()}] [SUCCESS] Duck转发 (Gmail OAuth) ({mask_email(email)}) 提取成功: {otp_code}")
                            return otp_code

                    elif forward_mode == "cloudmail":
                        if not forward_email:
                            print(
                                f"\n[{cfg.ts()}] [ERROR] Duckmail 运行失败: 未配置转发邮箱地址({forward_email})！")
                            return ""
                        token = get_cm_token(mail_proxies)
                        if token:
                            res = requests.post(
                                f"{cfg.CM_API_URL}/api/public/emailList",
                                headers={"Authorization": token},
                                json={"toEmail": forward_email, "timeSort": "desc", "size": 10},
                                proxies=mail_proxies, timeout=15,
                            )
                            if res.status_code == 200:
                                for m in res.json().get("data", []):
                                    m_id = str(m.get("emailId"))
                                    if m_id in processed_mail_ids:
                                        continue
                                    content = f"{m.get('subject', '')}\n{m.get('text', '')}"
                                    if "openai" not in m.get("sendEmail",
                                                             "").lower() and "openai" not in content.lower():
                                        continue

                                    target_email = email.lower()
                                    if target_email not in str(m).lower() and target_email not in content.lower():
                                        continue

                                    code = _extract_otp_code(content)
                                    if code:
                                        processed_mail_ids.add(m_id)
                                        print(f"\n[{cfg.ts()}] [SUCCESS] Duck转发 (CloudMail) 提取成功: {code}")
                                        return code


                    elif forward_mode == "freemail":
                        if not forward_email:
                            print(f"\n[{cfg.ts()}] [ERROR] Duckmail 运行失败: 未配置转发邮箱地址(forward_email)！")
                            return ""
                        headers = {"Content-Type": "application/json",
                                   "Authorization": f"Bearer {cfg.FREEMAIL_API_TOKEN}"}
                        res = requests.get(f"{cfg.FREEMAIL_API_URL}/api/emails",
                                           params={"mailbox": forward_email, "limit": 20},
                                           headers=headers, proxies=mail_proxies,
                                           verify=_ssl_verify(), timeout=15)
                        if res.status_code == 200:
                            raw_data = res.json()
                            emails_list = (
                                raw_data.get("data") or raw_data.get("emails") or raw_data.get("messages") or raw_data.get(
                                    "results") or []
                                if isinstance(raw_data, dict) else raw_data
                            )
                            if not isinstance(emails_list, list): emails_list = []
                            for mail in emails_list:
                                mail_id = str(mail.get("id") or mail.get("timestamp") or mail.get("subject") or "")
                                if not mail_id or mail_id in processed_mail_ids: continue
                                subject_text = str(mail.get("subject") or mail.get("title") or "")
                                if "openai" not in subject_text.lower() and "openai" not in str(mail).lower():
                                    continue
                                try:
                                    dr = requests.get(f"{cfg.FREEMAIL_API_URL}/api/email/{mail_id}",
                                                      headers=headers, proxies=mail_proxies,
                                                      verify=_ssl_verify(), timeout=15)
                                    if dr.status_code == 200:
                                        d = dr.json()
                                        content = "\n".join(filter(None, [str(d.get("subject") or ""),
                                                                          str(d.get("content") or ""),
                                                                          str(d.get("html_content") or "")]))

                                        target_email = email.lower()
                                        if target_email not in str(d).lower() and target_email not in content.lower():
                                            continue
                                        code = _extract_otp_code(content)
                                        if not code: code = str(d.get("code") or d.get("verification_code") or "")
                                        if code:
                                            processed_mail_ids.add(mail_id)
                                            print(f"[{cfg.ts()}] [SUCCESS] Duck转发 (Freemail) 提取成功: {code}")
                                            return code
                                except Exception:
                                    pass

                    elif forward_mode == "mail_curl":
                        if not forward_email:
                            print(
                                f"\n[{cfg.ts()}] [ERROR] Duckmail 运行失败: 未配置转发邮箱地址(forward_email)！")
                            return ""
                        inbox_url = f"{cfg.MC_API_BASE}/api/inbox?key={cfg.MC_KEY}&mailbox_id={forward_email}"
                        res = requests.get(inbox_url, proxies=mail_proxies, verify=_ssl_verify(),
                                           timeout=10)
                        if res.status_code == 200:
                            for mail_item in (res.json() or []):
                                m_id = mail_item.get("mail_id")
                                s_name = mail_item.get("sender_name", "").lower()
                                if m_id and m_id not in processed_mail_ids and "openai" in s_name:
                                    detail_res = requests.get(
                                        f"{cfg.MC_API_BASE}/api/mail?key={cfg.MC_KEY}&id={m_id}",
                                        proxies=mail_proxies, verify=_ssl_verify(), timeout=10)
                                    if detail_res.status_code == 200:
                                        d = detail_res.json()
                                        body = f"{d.get('subject', '')}\n{d.get('content', '')}\n{d.get('html', '')}"
                                        target_email = email.lower()
                                        if target_email not in str(d).lower() and target_email not in body.lower():
                                            continue

                                        code = _extract_otp_code(body)
                                        if code:
                                            processed_mail_ids.add(m_id)
                                            print(f"\n[{cfg.ts()}] [SUCCESS] Duck转发 (mail_curl) 提取成功: {code}")
                                            return code
                    elif forward_mode == "cloudflare_temp_email":
                        if not forward_email:
                            print(f"[{cfg.ts()}] [ERROR] Duckmail 运行失败: 未配置转发邮箱地址(forward_email)！")
                            return ""
                        res = requests.get(
                            f"{cfg.GPTMAIL_BASE}/admin/mails",
                            params={"limit": 20, "offset": 0, "address": forward_email},
                            headers={"x-admin-auth": cfg.ADMIN_AUTH},
                            verify=_ssl_verify(), timeout=15, proxies=mail_proxies,
                        )

                        if res.status_code == 200:
                            results = res.json().get("results", [])
                            for mail in results:
                                m_id = mail.get("id")
                                if not m_id or m_id in processed_mail_ids:
                                    continue
                                parsed = _extract_mail_fields(mail)
                                sender_lower = str(parsed.get("sender", "")).lower()
                                content = f"{parsed['subject']}\n{parsed['body']}".strip()
                                if "openai" not in sender_lower and "openai" not in content.lower():
                                    continue
                                target_prefix = email.lower().split('@')[0]
                                if target_prefix not in sender_lower and target_prefix not in content.lower():

                                    continue
                                code = _extract_otp_code(content)
                                if code:
                                    processed_mail_ids.add(m_id)
                                    print(f"\n[{cfg.ts()}] [SUCCESS] Duck转发 (CF 临时邮箱) 提取成功: {code}")
                                    return code
                    else:
                        pass

                else:
                    msgs = ds.get_messages(jwt)
                    for m in msgs:
                        content = f"{m.get('subject', '')}\n{m.get('text', '')}\n{ds.strip_html(m.get('html', ''))}"
                        if "openai" in content.lower() or "chatgpt" in content.lower():
                            code = _extract_otp_code(content)
                            if code:
                                print(
                                    f"\n[{cfg.ts()}] [SUCCESS] Duck API ({mask_email(email)}) 提取成功: {code}")
                                return code
            elif mode == "generator_email":
                if not jwt:
                    print(f"\n[{cfg.ts()}] [ERROR] GeneratorEmail 缺少凭证 (surl)，无法提取验证码！")
                    return ""
                try:
                    from utils.generator_email_service import GeneratorEmailService
                    ge_service = GeneratorEmailService(proxies=mail_proxies)

                    code = ge_service.get_verification_code(jwt)
                    if code:
                        processed_mail_ids.add(jwt)
                        print(f"\n[{cfg.ts()}] [SUCCESS] GeneratorEmail ({mask_email(email)})邮箱提取成功: {code}")
                        return code
                except Exception as e:
                    pass

            elif mode == "tempmail":
                if not jwt:
                    print(f"\n[{cfg.ts()}] [ERROR] Tempmail 缺少 token，无法提取验证码！")
                    return ""
                try:
                    from utils.tempmail_service import TempmailService
                    tm_service = TempmailService(proxies=mail_proxies)
                    email_list = tm_service.get_inbox(jwt)

                    for msg in email_list:
                        msg_date = str(msg.get("date", 0))
                        if not msg_date or msg_date in processed_mail_ids:
                            continue

                        sender = str(msg.get("from", "")).lower()
                        subject = str(msg.get("subject", ""))
                        body = str(msg.get("body", ""))
                        html = str(msg.get("html") or "")

                        content = "\n".join([sender, subject, body, html])

                        safe_content = re.sub(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", " ", content)

                        if "openai" not in sender and "openai" not in content.lower():
                            continue

                        code = _extract_otp_code(safe_content)
                        if code:
                            processed_mail_ids.add(msg_date)
                            print(f"\n[{cfg.ts()}] [SUCCESS] Tempmail ({mask_email(email)})邮箱提取成功: {code}")
                            return code
                except Exception as e:
                    pass

            elif mode == "tempmail_org":
                if not jwt:
                    print(f"\n[{cfg.ts()}] [ERROR] TempMail.org 缺少 token，无法提取验证码！")
                    return ""
                try:
                    from utils.tempmail_org import TempMailOrgService
                    tm_org = TempMailOrgService(proxies=mail_proxies)
                    email_list = tm_org.get_inbox(jwt)

                    for msg in email_list:
                        msg_id = str(msg.get("_id", msg.get("id", "")))
                        if not msg_id or msg_id in processed_mail_ids:
                            continue

                        subject = str(msg.get("subject", ""))
                        code = ""
                        m = re.search(r"(?<!\d)(\d{6})(?!\d)", subject)
                        if m:
                            code = m.group(1)

                        if code:
                            processed_mail_ids.add(msg_id)
                            print(f"\n[{cfg.ts()}] [SUCCESS] TempMail.org ({mask_email(email)})邮箱提取成功: {code}")
                            return code
                except Exception as e:
                    pass

            elif mode == "Gmail_OAuth":
                otp_code = get_gmail_otp_via_oauth(email, mail_proxies)
                if otp_code:
                    print(f"\n[{cfg.ts()}] [SUCCESS] Gmail OAuth ({mask_email(email)}) 提取成功: {otp_code}")
                    return otp_code

            elif mode == "imap":
                print(
                    f"\n[{cfg.ts()}] [DEBUG] IMAP 轮询第 {attempt}/20 次，"
                    f"当前已处理邮件数={len(processed_mail_ids)}。"
                )
                if not mail_conn:
                    try:
                        mail_conn = _create_and_login_imap_conn()
                    except Exception as e:
                        if "unsafe login" in str(e).lower() and _should_send_imap_id():
                            print(f"\n[{cfg.ts()}] [ERROR] IMAP 重连失败: {e}，请确认邮箱已开启 IMAP 并使用客户端授权码。")
                        time.sleep(5)
                        continue

                folders = ["INBOX", "Junk", '"Junk Email"', "Spam",
                           '"[Gmail]/Spam"', '"垃圾邮件"']
                matched_code = False
                for folder in folders:
                    try:
                        print(f"\n[{cfg.ts()}] [DEBUG] IMAP 准备选择文件夹: {folder}")
                        mail_conn.noop()
                        status, select_data = mail_conn.select(folder, readonly=True)
                        if status != "OK":
                            if any("unsafe login" in str(item).lower() for item in (select_data or [])):
                                print(f"\n[{cfg.ts()}] [ERROR] IMAP 文件夹选择被拒绝: {select_data}")
                                mail_conn = None
                                break
                            print(f"\n[{cfg.ts()}] [DEBUG] IMAP 文件夹不可用，跳过 {folder}: {select_data}")
                            continue
                        print(f"\n[{cfg.ts()}] [DEBUG] IMAP 文件夹选择成功: {folder}")

                        status, messages = mail_conn.uid("search", None, "ALL")
                        fetch_by_uid = True
                        if status != "OK" or not messages:
                            status, messages = mail_conn.search(None, "ALL")
                            fetch_by_uid = False
                        if status != "OK" or not messages or not messages[0]:
                            print(f"\n[{cfg.ts()}] [DEBUG] IMAP 文件夹 {folder} 中未检索到邮件。")
                            continue

                        message_ids = messages[0].split()
                        scan_ids = message_ids[-50:]
                        print(
                            f"\n[{cfg.ts()}] [DEBUG] IMAP 文件夹 {folder} 检索成功，"
                            f"总邮件数={len(message_ids)}，本轮扫描最近 {len(scan_ids)} 封，"
                            f"查询方式={'UID' if fetch_by_uid else 'SEQ'}。"
                        )
                        for mail_id in reversed(scan_ids):
                            msg_key = f"{folder}:{mail_id.decode('utf-8', 'ignore') if isinstance(mail_id, bytes) else str(mail_id)}"
                            if msg_key in processed_mail_ids:
                                continue

                            if fetch_by_uid:
                                res, data = mail_conn.uid("fetch", mail_id, "(RFC822)")
                            else:
                                res, data = mail_conn.fetch(mail_id, "(RFC822)")
                            if res != "OK" or not data:
                                print(f"\n[{cfg.ts()}] [WARNING] 拉取邮件失败: {msg_key}, status={res}")
                                processed_mail_ids.add(msg_key)
                                continue

                            raw_message = None
                            for resp_part in data:
                                if isinstance(resp_part, tuple) and len(resp_part) >= 2:
                                    raw_message = resp_part[1]
                                    break
                            if not raw_message:
                                print(f"\n[{cfg.ts()}] [WARNING] 邮件原文为空，跳过: {msg_key}")
                                processed_mail_ids.add(msg_key)
                                continue

                            import email as email_lib
                            msg = email_lib.message_from_bytes(raw_message)
                            msg_ts = _message_timestamp(msg)
                            if msg_ts is not None and msg_ts < (imap_wait_started_at - 30):
                                processed_mail_ids.add(msg_key)
                                continue

                            sender = _decode_mime_header(str(msg.get("From", "")))
                            subject = _decode_mime_header(str(msg.get("Subject", "")))
                            content = _extract_body_from_message(msg)
                            full_content = f"{sender}\n{subject}\n{content}".strip()
                            print(
                                f"\n[{cfg.ts()}] [DEBUG] 正在检查邮件: {msg_key}, "
                                f"from={_preview_text(sender, 80) or '-'}, "
                                f"subject={_preview_text(subject, 100) or '-'}"
                            )

                            if "openai" not in full_content.lower():
                                print(f"\n[{cfg.ts()}] [DEBUG] 邮件不包含 openai 关键字，跳过: {msg_key}")
                                processed_mail_ids.add(msg_key)
                                continue
                            if not _recipient_matches_imap_message(msg, email, content):
                                print(
                                    f"\n[{cfg.ts()}] [DEBUG] 邮件收件人不匹配目标邮箱，跳过: {msg_key}, "
                                    f"target={mask_email(email)}"
                                )
                                processed_mail_ids.add(msg_key)
                                continue

                            code = _extract_otp_code(full_content)
                            if code:
                                processed_mail_ids.add(msg_key)
                                print(f"\n[{cfg.ts()}] [SUCCESS] 验证码: {code} (folder={folder})")
                                matched_code = True
                                try:
                                    if fetch_by_uid:
                                        mail_conn.uid("store", mail_id, "+FLAGS", r"(\Deleted)")
                                    else:
                                        mail_conn.store(mail_id, "+FLAGS", r"(\Deleted)")
                                    mail_conn.expunge()
                                except Exception:
                                    pass
                                try:
                                    mail_conn.logout()
                                except Exception:
                                    pass
                                return code
                            print(f"\n[{cfg.ts()}] [DEBUG] 邮件命中 OpenAI 但未提取到验证码: {msg_key}")
                            processed_mail_ids.add(msg_key)
                    except imaplib.IMAP4.abort:
                        print(f"\n[{cfg.ts()}] [WARNING] IMAP 连接断开，将在下次循环重连...")
                        mail_conn = None
                        break
                    except Exception as e:
                        if "Spam" in folder or "Junk" in folder or "垃圾" in folder:
                            print(f"\n[{cfg.ts()}] [DEBUG] 访问垃圾箱失败 {folder}: {e}")
                        else:
                            print(f"\n[{cfg.ts()}] [WARNING] IMAP 扫描文件夹异常 {folder}: {e}")
                if not matched_code and mail_conn is not None:
                    print(
                        f"\n[{cfg.ts()}] [DEBUG] IMAP 第 {attempt}/20 次轮询结束，"
                        f"本轮未找到验证码邮件。"
                    )

            elif mode == "freemail":
                headers = {
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {cfg.FREEMAIL_API_TOKEN}"
                }

                res = requests.get(f"{cfg.FREEMAIL_API_URL.rstrip('/')}/api/emails",
                                   params={"mailbox": email, "limit": 20},
                                   headers=headers, proxies=mail_proxies, verify=_ssl_verify(), timeout=15)
                if res.status_code == 200:
                    raw_data = res.json()
                    emails_list = (
                        raw_data.get("data") or raw_data.get("emails") or
                        raw_data.get("messages") or raw_data.get("results") or []
                        if isinstance(raw_data, dict) else raw_data
                    )
                    if not isinstance(emails_list, list):
                        emails_list = []
                    for mail in emails_list:
                        mail_id = str(mail.get("id") or mail.get("timestamp") or
                                      mail.get("subject") or "")
                        if not mail_id or mail_id in processed_mail_ids:
                            continue
                        subject_text = str(mail.get("subject") or mail.get("title") or "")
                        code = ""
                        m = re.search(r"(?<!\d)(\d{6})(?!\d)", subject_text)
                        if m:
                            code = m.group(1)
                        if not code:
                            code = str(mail.get("code") or mail.get("verification_code") or "")
                        if not code:
                            try:
                                dr = requests.get(
                                    f"{cfg.FREEMAIL_API_URL.rstrip('/')}/api/email/{mail_id}",
                                    headers=headers, proxies=mail_proxies,
                                    verify=_ssl_verify(), timeout=15,
                                )
                                if dr.status_code == 200:
                                    d = dr.json()
                                    content = "\n".join(filter(None, [
                                        str(d.get("subject") or ""),
                                        str(d.get("content") or ""),
                                        str(d.get("html_content") or ""),
                                    ]))
                                    code = _extract_otp_code(content)
                            except Exception:
                                pass
                        if code:
                            processed_mail_ids.add(mail_id)
                            print(f"[{cfg.ts()}] [SUCCESS] freemail ({mask_email(email)})邮箱提取成功: {code}")
                            return code
            elif mode == "luckmail":
                if not jwt:
                    print(f"\n[{cfg.ts()}] [ERROR] LuckMail 缺少 token，无法提取验证码！")
                    return ""
                try:
                    from utils.luckmail_service import LuckMailService
                    lm_service = LuckMailService(api_key=cfg.LUCKMAIL_API_KEY)

                    code = lm_service.get_code(jwt)
                    if code:
                        processed_mail_ids.add(jwt)
                        print(f"\n[{cfg.ts()}] [SUCCESS] LuckMail ({mask_email(email)})邮箱提取验证码成功: {code}")
                        return code
                except Exception as e:
                    pass
            else:
                if jwt:
                    res = requests.get(
                        f"{base_url}/api/mails",
                        params={"limit": 20, "offset": 0},
                        headers={
                            "Authorization": f"Bearer {jwt}",
                            "Content-Type": "application/json",
                            "Accept": "application/json",
                        },
                        proxies=mail_proxies, verify=_ssl_verify(), timeout=15,
                    )
                else:
                    res = requests.get(
                        f"{base_url}/admin/mails",
                        params={"limit": 20, "offset": 0, "address": email},
                        headers={"x-admin-auth": cfg.ADMIN_AUTH},
                        proxies=mail_proxies, verify=_ssl_verify(), timeout=15,
                    )
                if res.status_code != 200:
                    print(f"\n[{cfg.ts()}] [ERROR] ({mask_email(email)})邮箱接口请求失败 (HTTP {res.status_code}): {res.text}")
                    time.sleep(3)
                    continue
                results = res.json().get("results")
                if results:
                    for mail in results:
                        mail_id = mail.get("id")
                        if not mail_id or mail_id in processed_mail_ids:
                            continue
                        parsed = _extract_mail_fields(mail)
                        content = f"{parsed['subject']}\n{parsed['body']}".strip()
                        if ("openai" not in parsed["sender"].lower() and
                                "openai" not in content.lower()):
                            continue
                        m = re.search(pattern, content)
                        if m:
                            processed_mail_ids.add(mail_id)
                            print(f"[{cfg.ts()}] [SUCCESS] ({mask_email(email)})邮箱提取成功: {m.group(1)}")
                            return m.group(1)
                    pass
                else:
                    pass

        except Exception as e:
            if mode == "imap":
                print(f"\n[{cfg.ts()}] [ERROR] IMAP 轮询主流程异常: {e}")
            else:
                print(".", end="", flush=True)
        if attempt % 3 == 0:
            print(f"[{cfg.ts()}] [INFO] 仍在查询邮箱，暂未收到验证码 (已尝试 {attempt}/20)...")
        time.sleep(3)

    print(f"\n[{cfg.ts()}] [ERROR] ({mask_email(email)})邮箱接收验证码超时")
    return ""
