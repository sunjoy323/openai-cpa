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
