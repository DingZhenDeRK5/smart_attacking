"""
智攻 (SmartAttack) — 数据库引擎与会话管理
==========================================
基于 SQLAlchemy 2.x，默认使用 SQLite（零配置）。
通过 DATABASE_URL 环境变量可切换到 PostgreSQL 等。
"""

import logging
import os
from contextlib import contextmanager

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

logger = logging.getLogger("smart_attack.database")

# ---------------------------------------------------------------------------
# 数据库连接配置
# ---------------------------------------------------------------------------
# 默认 SQLite 路径位于项目 storage 目录下
_default_sqlite_path = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "storage",
    "smartattack.db",
)
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{_default_sqlite_path}")

# SQLite 需要 check_same_thread=False 以支持多线程（Flask 开发服务器）
_connect_args = {}
if DATABASE_URL.startswith("sqlite"):
    _connect_args["check_same_thread"] = False

engine = create_engine(
    DATABASE_URL,
    connect_args=_connect_args,
    echo=False,  # 生产环境关闭 SQL 日志
    pool_pre_ping=True,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

logger.info("数据库引擎已初始化: %s", DATABASE_URL)


# ---------------------------------------------------------------------------
# 依赖注入风格的会话获取
# ---------------------------------------------------------------------------
@contextmanager
def get_db():
    """上下文管理器：获取数据库会话，自动提交/回滚/关闭。"""
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def init_db():
    """创建所有表（幂等操作 — 表不存在时才创建）。"""
    from .models import ScanRecord, Vulnerability, AttackPlan, ExecutionResult  # noqa: F401

    Base.metadata.create_all(bind=engine)
    logger.info("数据库表初始化完成")
