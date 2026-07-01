"""
智攻 (SmartAttack) v3.5 — SaaS 多租户认证模块
==============================================
用户注册/登录、JWT 认证、API Assets 管理、计划限制。

核心功能：
- 用户注册 & 登录（bcrypt 密码哈希 + JWT token）
- 三级计划：free（10 次/月）/ pro（100 次/月）/ enterprise（无限）
- API Assets：用户可保存多个待扫描的 API 端点
- 扫描配额自动检查
"""

import functools
import logging
import os
import uuid
from datetime import datetime, timezone

import bcrypt
import jwt

from flask import request, jsonify, g

logger = logging.getLogger("smart_attack.auth")

# ---------------------------------------------------------------------------
# JWT 配置
# ---------------------------------------------------------------------------
JWT_SECRET = os.getenv("JWT_SECRET", "smartattack-jwt-secret-change-in-production")
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_HOURS = int(os.getenv("JWT_EXPIRY_HOURS", "72"))

# ---------------------------------------------------------------------------
# 计划配置
# ---------------------------------------------------------------------------
PLANS = {
    "free": {
        "name": "免费版",
        "scans_per_month": 10,
        "max_endpoints": 5,
        "features": ["swagger_import", "basic_report", "single_agent"],
    },
    "pro": {
        "name": "专业版",
        "scans_per_month": 100,
        "max_endpoints": 50,
        "features": ["swagger_import", "pdf_report", "multi_agent",
                     "knowledge_base", "rules_engine", "websocket"],
    },
    "enterprise": {
        "name": "企业版",
        "scans_per_month": -1,  # 无限
        "max_endpoints": -1,     # 无限
        "features": ["swagger_import", "pdf_report", "multi_agent",
                     "knowledge_base", "rules_engine", "websocket",
                     "celery_workers", "adversarial", "ci_cd", "sso"],
    },
}


# ======================================================================
# 用户 & API Asset 数据模型
# ======================================================================


class UserStore:
    """轻量级用户存储（基于 SQLAlchemy 的 SQLite 表）。

    设计决策：不使用复杂的 ORM 关系映射，直接使用原始 SQL，
    避免与现有 SQLAlchemy 模型冲突，同时保持零额外依赖。
    """

    @staticmethod
    def _get_db():
        from models.database import engine
        return engine

    @staticmethod
    def init():
        """创建用户相关表（幂等）。"""
        engine = UserStore._get_db()
        with engine.connect() as conn:
            conn.exec_driver_sql("""
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    email TEXT UNIQUE NOT NULL,
                    username TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    plan TEXT DEFAULT 'free',
                    company TEXT DEFAULT '',
                    created_at TEXT NOT NULL,
                    last_login TEXT
                )
            """)
            conn.exec_driver_sql("""
                CREATE TABLE IF NOT EXISTS api_assets (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    url TEXT NOT NULL,
                    asset_type TEXT DEFAULT 'swagger',
                    auth_config TEXT DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    last_scanned TEXT,
                    scan_count INTEGER DEFAULT 0,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            """)
            conn.exec_driver_sql("""
                CREATE TABLE IF NOT EXISTS scan_quota (
                    user_id TEXT PRIMARY KEY,
                    plan TEXT DEFAULT 'free',
                    month TEXT NOT NULL,
                    used INTEGER DEFAULT 0,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            """)
            conn.commit()

    @staticmethod
    def create_user(email: str, username: str, password: str,
                    plan: str = "free", company: str = "") -> dict | None:
        """创建新用户。返回用户字典或 None（邮箱已存在）。"""
        engine = UserStore._get_db()
        uid = uuid.uuid4().hex[:16]
        password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        now = datetime.now(timezone.utc).isoformat()

        try:
            with engine.connect() as conn:
                conn.exec_driver_sql(
                    """INSERT INTO users (id, email, username, password_hash, plan, company, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (uid, email, username, password_hash, plan, company, now),
                )
                # 初始化本月配额
                month_key = datetime.now(timezone.utc).strftime("%Y-%m")
                conn.exec_driver_sql(
                    "INSERT INTO scan_quota (user_id, plan, month, used) VALUES (?, ?, ?, 0)",
                    (uid, plan, month_key),
                )
                conn.commit()
            return {
                "id": uid, "email": email, "username": username,
                "plan": plan, "company": company, "created_at": now,
            }
        except Exception as e:
            if "UNIQUE" in str(e):
                return None  # 邮箱重复
            logger.error("创建用户失败: %s", e)
            raise

    @staticmethod
    def authenticate(email: str, password: str) -> dict | None:
        """验证用户凭证。返回用户字典或 None。"""
        engine = UserStore._get_db()
        with engine.connect() as conn:
            result = conn.exec_driver_sql(
                "SELECT id, email, username, password_hash, plan, company FROM users WHERE email = ?",
                (email,),
            ).first()
        if not result:
            return None
        uid, email, username, pw_hash, plan, company = result
        if not bcrypt.checkpw(password.encode(), pw_hash.encode()):
            return None
        # 更新最后登录时间
        now = datetime.now(timezone.utc).isoformat()
        with engine.connect() as conn:
            conn.exec_driver_sql("UPDATE users SET last_login = ? WHERE id = ?", (now, uid))
            conn.commit()
        return {"id": uid, "email": email, "username": username,
                "plan": plan, "company": company or ""}

    @staticmethod
    def get_user(user_id: str) -> dict | None:
        engine = UserStore._get_db()
        with engine.connect() as conn:
            result = conn.exec_driver_sql(
                "SELECT id, email, username, plan, company, created_at FROM users WHERE id = ?",
                (user_id,),
            ).first()
        if not result:
            return None
        return dict(zip(["id", "email", "username", "plan", "company", "created_at"], result))

    @staticmethod
    def check_quota(user_id: str) -> dict:
        """检查用户本月扫描配额。返回 { allowed: bool, used, limit, plan }。"""
        engine = UserStore._get_db()
        month_key = datetime.now(timezone.utc).strftime("%Y-%m")
        with engine.connect() as conn:
            # 获取用户计划
            user = conn.exec_driver_sql(
                "SELECT plan FROM users WHERE id = ?", (user_id,)
            ).first()
            if not user:
                return {"allowed": False, "used": 0, "limit": 0, "plan": "free"}
            plan = user[0]

            # 获取/创建配额记录
            quota = conn.exec_driver_sql(
                "SELECT used FROM scan_quota WHERE user_id = ? AND month = ?",
                (user_id, month_key),
            ).first()
            if not quota:
                conn.exec_driver_sql(
                    "INSERT INTO scan_quota (user_id, plan, month, used) VALUES (?, ?, ?, 0)",
                    (user_id, plan, month_key),
                )
                conn.commit()
                used = 0
            else:
                used = quota[0]

        plan_config = PLANS.get(plan, PLANS["free"])
        limit = plan_config["scans_per_month"]
        allowed = limit < 0 or used < limit  # -1 = 无限
        return {"allowed": allowed, "used": used, "limit": limit, "plan": plan}

    @staticmethod
    def use_quota(user_id: str) -> bool:
        """消耗一次扫描配额。返回是否成功。"""
        engine = UserStore._get_db()
        month_key = datetime.now(timezone.utc).strftime("%Y-%m")
        with engine.connect() as conn:
            conn.exec_driver_sql(
                "UPDATE scan_quota SET used = used + 1 WHERE user_id = ? AND month = ?",
                (user_id, month_key),
            )
            conn.commit()
        return True

    # ---- API Assets ----

    @staticmethod
    def create_asset(user_id: str, name: str, url: str,
                     asset_type: str = "swagger", auth_config: dict = None) -> str:
        """创建 API Asset，返回 asset_id。"""
        engine = UserStore._get_db()
        aid = uuid.uuid4().hex[:12]
        now = datetime.now(timezone.utc).isoformat()
        auth_json = json.dumps(auth_config or {})
        with engine.connect() as conn:
            conn.exec_driver_sql(
                """INSERT INTO api_assets (id, user_id, name, url, asset_type, auth_config, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (aid, user_id, name, url, asset_type, auth_json, now),
            )
            conn.commit()
        return aid

    @staticmethod
    def list_assets(user_id: str) -> list:
        engine = UserStore._get_db()
        with engine.connect() as conn:
            rows = conn.exec_driver_sql(
                "SELECT id, name, url, asset_type, auth_config, created_at, last_scanned, scan_count FROM api_assets WHERE user_id = ? ORDER BY created_at DESC",
                (user_id,),
            ).fetchall()
        return [dict(zip(["id", "name", "url", "asset_type", "auth_config",
                          "created_at", "last_scanned", "scan_count"], row))
                for row in rows]

    @staticmethod
    def delete_asset(user_id: str, asset_id: str) -> bool:
        engine = UserStore._get_db()
        with engine.connect() as conn:
            result = conn.exec_driver_sql(
                "DELETE FROM api_assets WHERE id = ? AND user_id = ?",
                (asset_id, user_id),
            )
            conn.commit()
            return result.rowcount > 0

    @staticmethod
    def record_scan(asset_id: str):
        """记录一次扫描到 asset。"""
        engine = UserStore._get_db()
        now = datetime.now(timezone.utc).isoformat()
        with engine.connect() as conn:
            conn.exec_driver_sql(
                "UPDATE api_assets SET last_scanned = ?, scan_count = scan_count + 1 WHERE id = ?",
                (now, asset_id),
            )
            conn.commit()


# ======================================================================
# JWT Token 工具
# ======================================================================


def create_token(user: dict) -> str:
    """为用户生成 JWT access token。"""
    payload = {
        "sub": user["id"],
        "email": user["email"],
        "plan": user.get("plan", "free"),
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc).timestamp() + JWT_EXPIRY_HOURS * 3600,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_token(token: str) -> dict | None:
    """解码 JWT token。返回 payload 或 None。"""
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


# ======================================================================
# Flask 装饰器 & 中间件
# ======================================================================


def login_required(f):
    """装饰器：要求 Bearer Token 认证。"""

    @functools.wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"success": False, "error": "需要认证"}), 401

        token = auth_header[7:]
        payload = decode_token(token)
        if payload is None:
            return jsonify({"success": False, "error": "Token 无效或已过期"}), 401

        g.user_id = payload["sub"]
        g.user_email = payload.get("email", "")
        g.user_plan = payload.get("plan", "free")
        return f(*args, **kwargs)

    return decorated


def optional_login(f):
    """装饰器：可选认证（登录后获得更多功能，未登录也可使用）。"""

    @functools.wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
            payload = decode_token(token)
            if payload:
                g.user_id = payload["sub"]
                g.user_email = payload.get("email", "")
                g.user_plan = payload.get("plan", "free")
        return f(*args, **kwargs)

    return decorated


def require_plan(min_plan: str):
    """装饰器：要求最低计划等级。"""
    plan_order = {"free": 0, "pro": 1, "enterprise": 2}

    def decorator(f):
        @functools.wraps(f)
        def decorated(*args, **kwargs):
            plan = getattr(g, "user_plan", "free")
            if plan_order.get(plan, 0) < plan_order.get(min_plan, 0):
                return jsonify({
                    "success": False,
                    "error": f"此功能需要 {min_plan} 或更高计划，当前计划: {plan}",
                }), 403
            return f(*args, **kwargs)

        return decorated

    return decorator


# ======================================================================
# 模块初始化
# ======================================================================

# 注册 json 引用（在模块顶部使用）
import json

try:
    UserStore.init()
    logger.info("用户认证模块已初始化")
except Exception as e:
    logger.warning("用户表初始化失败: %s", e)
