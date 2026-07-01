"""
智攻 (SmartAttack) — 数据模型包
==============================
ORM 模型、数据库引擎、LLM 提供者抽象。
"""

from .database import Base, SessionLocal, engine, get_db, init_db
from .models import ScanRecord, Vulnerability, AttackPlan, ExecutionResult

__all__ = [
    "Base",
    "SessionLocal",
    "engine",
    "get_db",
    "init_db",
    "ScanRecord",
    "Vulnerability",
    "AttackPlan",
    "ExecutionResult",
]
