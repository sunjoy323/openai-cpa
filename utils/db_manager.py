import sqlite3
import json
import os
from datetime import datetime
from typing import Any

os.makedirs("data", exist_ok=True)
DB_PATH = "data/data.db"
MANUAL_REVIEW_EXPORT_PATH = "data/manual_review_accounts.json"

def ts() -> str:
    return datetime.now().strftime("%H:%M:%S")

def _ensure_columns(conn, table_name: str, columns: dict) -> None:
    c = conn.cursor()
    c.execute(f"PRAGMA table_info({table_name})")
    existing_columns = {row[1] for row in c.fetchall()}
    for column_name, column_def in columns.items():
        if column_name not in existing_columns:
            c.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_def}")

def init_db():
    """初始化 SQLite 数据库，创建账号存储表"""
    with sqlite3.connect(DB_PATH, timeout=10) as conn:
        c = conn.cursor()
        c.execute('PRAGMA journal_mode=WAL;')
        c.execute('PRAGMA synchronous=NORMAL;')
        c.execute('''
            CREATE TABLE IF NOT EXISTS accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE,
                password TEXT,
                token_data TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS manual_review_accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE,
                password TEXT,
                status TEXT DEFAULT 'manual_login_required',
                email_jwt TEXT,
                stage TEXT,
                current_url TEXT,
                note TEXT,
                last_attempt_at TIMESTAMP,
                last_result TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        _ensure_columns(conn, "manual_review_accounts", {
            "email_jwt": "TEXT",
            "last_attempt_at": "TIMESTAMP",
            "last_result": "TEXT",
        })
        c.execute('''
            CREATE TABLE IF NOT EXISTS system_kv (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        ''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS local_mailboxes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE,
                password TEXT,
                client_id TEXT,
                refresh_token TEXT,
                status INTEGER DEFAULT 0,
                fission_count INTEGER DEFAULT 0,
                retry_master INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        _ensure_columns(conn, "local_mailboxes", {
            "client_id": "TEXT",
            "refresh_token": "TEXT",
            "status": "INTEGER DEFAULT 0",
            "fission_count": "INTEGER DEFAULT 0",
            "retry_master": "INTEGER DEFAULT 0",
        })
        conn.commit()
    print(f"[{ts()}] [系统] 数据库模块初始化完成")


def _sync_manual_review_export(conn) -> None:
    c = conn.cursor()
    c.execute("""
        SELECT email, password, status, email_jwt, stage, current_url, note,
               last_attempt_at, last_result, created_at, updated_at
        FROM manual_review_accounts
        ORDER BY updated_at DESC, id DESC
    """)
    rows = c.fetchall()
    data = [
        {
            "email": r[0],
            "password": r[1],
            "status": r[2],
            "email_jwt": r[3],
            "stage": r[4],
            "current_url": r[5],
            "note": r[6],
            "last_attempt_at": r[7],
            "last_result": r[8],
            "created_at": r[9],
            "updated_at": r[10],
        }
        for r in rows
    ]
    with open(MANUAL_REVIEW_EXPORT_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def save_account_to_db(email: str, password: str, token_json_str: str) -> bool:
    """账号、密码和 Token 数据存入数据库"""
    try:
        with sqlite3.connect(DB_PATH, timeout=10) as conn:
            c = conn.cursor()
            c.execute('''
                INSERT OR REPLACE INTO accounts (email, password, token_data)
                VALUES (?, ?, ?)
            ''', (email, password, token_json_str))
            c.execute("DELETE FROM manual_review_accounts WHERE email = ?", (email,))
            conn.commit()
            _sync_manual_review_export(conn)
            return True
    except Exception as e:
        print(f"[{ts()}] [ERROR] 数据库保存失败: {e}")
        return False


def save_manual_review_account(
    email: str,
    password: str,
    stage: str,
    current_url: str = "",
    note: str = "",
    email_jwt: str = "",
) -> bool:
    """将命中 add-phone 的账号单独记录，后续可人工登录处理"""
    try:
        with sqlite3.connect(DB_PATH, timeout=10) as conn:
            c = conn.cursor()
            c.execute(
                '''
                INSERT INTO manual_review_accounts (
                    email, password, status, email_jwt, stage, current_url, note
                ) VALUES (?, ?, 'manual_login_required', ?, ?, ?, ?)
                ON CONFLICT(email) DO UPDATE SET
                    password = excluded.password,
                    status = 'manual_login_required',
                    email_jwt = CASE
                        WHEN excluded.email_jwt IS NOT NULL AND excluded.email_jwt != ''
                        THEN excluded.email_jwt
                        ELSE manual_review_accounts.email_jwt
                    END,
                    stage = excluded.stage,
                    current_url = excluded.current_url,
                    note = excluded.note,
                    updated_at = CURRENT_TIMESTAMP
                ''',
                (email, password, email_jwt, stage, current_url, note),
            )
            conn.commit()
            _sync_manual_review_export(conn)
            return True
    except Exception as e:
        print(f"[{ts()}] [ERROR] 保存人工登录待处理账号失败: {e}")
        return False

def get_manual_review_account(email: str) -> dict:
    """按邮箱获取单个待人工处理账号，包含内部重试所需字段"""
    try:
        with sqlite3.connect(DB_PATH, timeout=10) as conn:
            c = conn.cursor()
            c.execute(
                """
                SELECT email, password, status, email_jwt, stage, current_url, note,
                       last_attempt_at, last_result, created_at, updated_at
                FROM manual_review_accounts
                WHERE email = ?
                LIMIT 1
                """,
                (email,),
            )
            row = c.fetchone()
            if not row:
                return {}
            return {
                "email": row[0],
                "password": row[1],
                "status": row[2],
                "email_jwt": row[3],
                "stage": row[4],
                "current_url": row[5],
                "note": row[6],
                "last_attempt_at": row[7],
                "last_result": row[8],
                "created_at": row[9],
                "updated_at": row[10],
            }
    except Exception as e:
        print(f"[{ts()}] [ERROR] 读取人工登录待处理账号失败: {e}")
        return {}

def update_manual_review_account(
    email: str,
    *,
    status: str = None,
    stage: str = None,
    current_url: str = None,
    note: str = None,
    last_result: str = None,
    touch_attempt: bool = True,
) -> bool:
    """更新人工复核账号的最近处理结果"""
    if not email:
        return False
    try:
        with sqlite3.connect(DB_PATH, timeout=10) as conn:
            c = conn.cursor()
            fields = []
            values = []
            for column, value in (
                ("status", status),
                ("stage", stage),
                ("current_url", current_url),
                ("note", note),
                ("last_result", last_result),
            ):
                if value is not None:
                    fields.append(f"{column} = ?")
                    values.append(value)
            if touch_attempt:
                fields.append("last_attempt_at = CURRENT_TIMESTAMP")
            fields.append("updated_at = CURRENT_TIMESTAMP")
            values.append(email)
            c.execute(
                f"UPDATE manual_review_accounts SET {', '.join(fields)} WHERE email = ?",
                values,
            )
            conn.commit()
            _sync_manual_review_export(conn)
            return c.rowcount > 0
    except Exception as e:
        print(f"[{ts()}] [ERROR] 更新人工登录待处理账号失败: {e}")
        return False

def get_all_accounts() -> list:
    """获取所有账号列表，按最新时间倒序"""
    try:
        with sqlite3.connect(DB_PATH, timeout=10) as conn:
            c = conn.cursor()
            c.execute("SELECT email, password, created_at FROM accounts ORDER BY id DESC")
            rows = c.fetchall()
            return [{"email": r[0], "password": r[1], "created_at": r[2]} for r in rows]
    except Exception as e:
        print(f"[{ts()}] [ERROR] 获取账号列表失败: {e}")
        return []

def get_token_by_email(email: str) -> dict:
    """根据邮箱提取完整的 Token JSON 数据（用于推送）"""
    try:
        with sqlite3.connect(DB_PATH, timeout=10) as conn:
            c = conn.cursor()
            c.execute("SELECT token_data FROM accounts WHERE email = ?", (email,))
            row = c.fetchone()
            if row and row[0]:
                return json.loads(row[0])
            return None
    except Exception as e:
        print(f"[{ts()}] [ERROR] 读取 Token 失败: {e}")
        return None

def get_tokens_by_emails(emails: list) -> list:
    """根据前端传入的邮箱列表，提取 Token"""
    if not emails:
        return []
    try:
        with sqlite3.connect(DB_PATH, timeout=10) as conn:
            c = conn.cursor()
            placeholders = ','.join(['?'] * len(emails))
            c.execute(f"SELECT token_data FROM accounts WHERE email IN ({placeholders})", emails)
            rows = c.fetchall()
            
            export_list = []
            for r in rows:
                if r[0]:
                    try:
                        export_list.append(json.loads(r[0]))
                    except:
                        pass
            return export_list
    except Exception as e:
        return []
        
def delete_accounts_by_emails(emails: list) -> bool:
    """批量从数据库中删除账号"""
    if not emails:
        return True
    try:
        with sqlite3.connect(DB_PATH, timeout=10) as conn:
            c = conn.cursor()
            placeholders = ','.join(['?'] * len(emails))
            c.execute(f"DELETE FROM accounts WHERE email IN ({placeholders})", emails)
            conn.commit()
            return True
    except Exception as e:
        print(f"[{ts()}] [ERROR] 数据库批量删除账号异常: {e}")
        return False

def get_accounts_page(page: int = 1, page_size: int = 50) -> dict:
    """带分页的账号拉取功能"""
    try:
        with sqlite3.connect(DB_PATH, timeout=10) as conn:
            c = conn.cursor()
            c.execute("SELECT COUNT(1) FROM accounts")
            total = c.fetchone()[0]

            offset = (page - 1) * page_size
            c.execute("SELECT email, password, created_at FROM accounts ORDER BY id DESC LIMIT ? OFFSET ?", (page_size, offset))
            rows = c.fetchall()
            
            data = [{"email": r[0], "password": r[1], "created_at": r[2]} for r in rows]
            return {"total": total, "data": data}
    except Exception as e:
        print(f"[{ts()}] [ERROR] 分页获取账号列表失败: {e}")
        return {"total": 0, "data": []}

def get_manual_review_accounts_page(page: int = 1, page_size: int = 50) -> dict:
    """分页获取需要人工登录处理的账号"""
    try:
        with sqlite3.connect(DB_PATH, timeout=10) as conn:
            c = conn.cursor()
            c.execute("SELECT COUNT(1) FROM manual_review_accounts")
            total = c.fetchone()[0]

            offset = (page - 1) * page_size
            c.execute(
                """
                SELECT email, password, status, stage, current_url, note,
                       last_attempt_at, last_result, created_at, updated_at
                FROM manual_review_accounts
                ORDER BY updated_at DESC, id DESC
                LIMIT ? OFFSET ?
                """,
                (page_size, offset),
            )
            rows = c.fetchall()
            data = [
                {
                    "email": r[0],
                    "password": r[1],
                    "status": r[2],
                    "stage": r[3],
                    "current_url": r[4],
                    "note": r[5],
                    "last_attempt_at": r[6],
                    "last_result": r[7],
                    "created_at": r[8],
                    "updated_at": r[9],
                }
                for r in rows
            ]
            return {"total": total, "data": data}
    except Exception as e:
        print(f"[{ts()}] [ERROR] 分页获取人工登录待处理账号失败: {e}")
        return {"total": 0, "data": []}

def set_sys_kv(key: str, value: Any):
    """保存任意数据到系统表"""
    try:
        val_str = json.dumps(value, ensure_ascii=False)
        with sqlite3.connect(DB_PATH, timeout=10) as conn:
            conn.execute("INSERT OR REPLACE INTO system_kv (key, value) VALUES (?, ?)", (key, val_str))
            conn.commit()
    except Exception as e:
        print(f"[{ts()}] [ERROR] 系统配置保存失败: {e}")

def get_sys_kv(key: str, default=None):
    """从系统表读取数据"""
    try:
        with sqlite3.connect(DB_PATH, timeout=10) as conn:
            cursor = conn.execute("SELECT value FROM system_kv WHERE key = ?", (key,))
            row = cursor.fetchone()
            if row:
                return json.loads(row[0])
    except Exception:
        pass
    return default


def get_all_accounts_with_token(limit: int = 10000) -> list:
    """提取包含完整 token_data 的账号列表，供集群导出等场景使用。"""
    try:
        with sqlite3.connect(DB_PATH, timeout=10) as conn:
            c = conn.cursor()
            c.execute(
                "SELECT email, password, token_data FROM accounts ORDER BY id DESC LIMIT ?",
                (limit,),
            )
            rows = c.fetchall()
            return [{"email": r[0], "password": r[1], "token_data": r[2]} for r in rows]
    except Exception as e:
        print(f"[{ts()}] [ERROR] 提取完整账号数据失败: {e}")
        return []

def import_local_mailboxes(mailboxes_data: list) -> int:
    """导入本地微软邮箱库。"""
    count = 0
    try:
        with sqlite3.connect(DB_PATH, timeout=10) as conn:
            c = conn.cursor()
            for mb in mailboxes_data:
                try:
                    c.execute(
                        '''
                        INSERT OR IGNORE INTO local_mailboxes (
                            email, password, client_id, refresh_token, status
                        ) VALUES (?, ?, ?, ?, 0)
                        ''',
                        (
                            mb["email"],
                            mb["password"],
                            mb.get("client_id", ""),
                            mb.get("refresh_token", ""),
                        ),
                    )
                    if c.rowcount > 0:
                        count += 1
                except Exception:
                    pass
            conn.commit()
    except Exception as e:
        print(f"[{ts()}] [ERROR] 导入邮箱库失败: {e}")
    return count


def get_local_mailboxes_page(page: int = 1, page_size: int = 50) -> dict:
    try:
        with sqlite3.connect(DB_PATH, timeout=10) as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute("SELECT COUNT(1) FROM local_mailboxes")
            total = c.fetchone()[0]

            offset = (page - 1) * page_size
            c.execute(
                "SELECT * FROM local_mailboxes ORDER BY id DESC LIMIT ? OFFSET ?",
                (page_size, offset),
            )
            rows = c.fetchall()
            return {"total": total, "data": [dict(r) for r in rows]}
    except Exception as e:
        print(f"[{ts()}] [ERROR] 分页获取本地邮箱库失败: {e}")
        return {"total": 0, "data": []}


def delete_local_mailboxes(ids: list) -> bool:
    if not ids:
        return True
    try:
        with sqlite3.connect(DB_PATH, timeout=10) as conn:
            c = conn.cursor()
            placeholders = ",".join(["?"] * len(ids))
            c.execute(f"DELETE FROM local_mailboxes WHERE id IN ({placeholders})", ids)
            conn.commit()
            return True
    except Exception as e:
        print(f"[{ts()}] [ERROR] 删除本地邮箱库失败: {e}")
        return False


def get_and_lock_unused_local_mailbox() -> dict:
    """提取一个未使用的账号，并锁定为占用状态，防止并发撞车。"""
    try:
        with sqlite3.connect(DB_PATH, timeout=10) as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute("BEGIN EXCLUSIVE")
            c.execute("SELECT * FROM local_mailboxes WHERE status = 0 ORDER BY id ASC LIMIT 1")
            row = c.fetchone()
            if row:
                c.execute("UPDATE local_mailboxes SET status = 1 WHERE id = ?", (row["id"],))
                conn.commit()
                return dict(row)
            conn.commit()
            return None
    except Exception as e:
        print(f"[{ts()}] [ERROR] 提取本地邮箱失败: {e}")
        return None


def update_local_mailbox_status(email: str, status: int):
    """更新邮箱状态：1=占用 2=出凭证 3=死号。"""
    try:
        with sqlite3.connect(DB_PATH, timeout=10) as conn:
            conn.execute("UPDATE local_mailboxes SET status = ? WHERE email = ?", (status, email))
            conn.commit()
    except Exception:
        pass


def update_local_mailbox_refresh_token(email: str, new_rt: str):
    """刷新 Token 后更新数据库。"""
    try:
        with sqlite3.connect(DB_PATH, timeout=10) as conn:
            conn.execute("UPDATE local_mailboxes SET refresh_token = ? WHERE email = ?", (new_rt, email))
            conn.commit()
    except Exception:
        pass


def get_mailbox_for_pool_fission() -> dict:
    """池裂变时提取邮箱，并立即增加计数避免并发撞车。"""
    try:
        with sqlite3.connect(DB_PATH, timeout=10) as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute("BEGIN EXCLUSIVE")
            c.execute("SELECT * FROM local_mailboxes WHERE status = 0 AND retry_master = 1 LIMIT 1")
            row = c.fetchone()

            if not row:
                c.execute("SELECT * FROM local_mailboxes WHERE status = 0 ORDER BY fission_count ASC LIMIT 1")
                row = c.fetchone()

            if row:
                c.execute(
                    "UPDATE local_mailboxes SET fission_count = fission_count + 1 WHERE id = ?",
                    (row["id"],),
                )
                conn.commit()
                return dict(row)

            conn.commit()
            return None
    except Exception as e:
        print(f"[{ts()}] [DB_ERROR] 提取失败: {e}")
        return None


def update_pool_fission_result(email: str, is_blocked: bool, is_raw: bool):
    """处理邮箱库裂变结果。"""
    try:
        with sqlite3.connect(DB_PATH, timeout=10) as conn:
            if not is_blocked:
                conn.execute("UPDATE local_mailboxes SET retry_master = 0 WHERE email = ?", (email,))
            elif not is_raw:
                conn.execute("UPDATE local_mailboxes SET retry_master = 1 WHERE email = ?", (email,))
            else:
                conn.execute(
                    "UPDATE local_mailboxes SET status = 3, retry_master = 0 WHERE email = ?",
                    (email,),
                )
            conn.commit()
    except Exception as e:
        print(f"[{ts()}] [DB_ERROR] 结果更新失败: {e}")


def clear_retry_master_status(email: str):
    """清除邮箱的母号重试标记，避免多线程重复取号。"""
    try:
        with sqlite3.connect(DB_PATH, timeout=10) as conn:
            conn.execute("UPDATE local_mailboxes SET retry_master = 0 WHERE email = ?", (email,))
            conn.commit()
    except Exception as e:
        print(f"[{ts()}] [DB_ERROR] 清除 {email} 的 retry_master 状态失败: {e}")
