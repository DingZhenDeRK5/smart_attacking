"""
智攻 (SmartAttack) — ORM 数据模型
=================================
ScanRecord → 一次完整扫描
Vulnerability → 扫描中发现的漏洞
AttackPlan → AI 生成的攻击方案
ExecutionResult → 单次攻击执行结果
"""

from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import relationship

from .database import Base


def _utcnow():
    """返回 UTC 当前时间（naive datetime，SQLite 兼容）。"""
    return datetime.now(timezone.utc).replace(tzinfo=None)


# ======================================================================
# ScanRecord — 扫描主记录
# ======================================================================
class ScanRecord(Base):
    __tablename__ = "scan_records"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String(24), unique=True, nullable=False, index=True)
    target_url = Column(String(2048), nullable=False)
    status = Column(String(20), nullable=False, default="completed")  # queued | running | completed | failed
    created_at = Column(DateTime, nullable=False, default=_utcnow)
    updated_at = Column(DateTime, nullable=False, default=_utcnow, onupdate=_utcnow)
    model_used = Column(String(128), nullable=True)

    # ---- 统计字段 ----
    stats_phase1_plan = Column(Integer, default=0)
    stats_phase1_exec = Column(Integer, default=0)
    stats_phase2_plan = Column(Integer, default=0)
    stats_phase2_exec = Column(Integer, default=0)

    # ---- 大 JSON 文本 ----
    business_analysis_json = Column(Text, nullable=True)
    security_assessment_json = Column(Text, nullable=True)
    result_analysis_json = Column(Text, nullable=True)
    error_message = Column(Text, nullable=True)

    # ---- 关系 ----
    vulnerabilities = relationship(
        "Vulnerability", back_populates="scan",
        cascade="all, delete-orphan", lazy="selectin",
    )
    attack_plans = relationship(
        "AttackPlan", back_populates="scan",
        cascade="all, delete-orphan", lazy="selectin",
    )
    execution_results = relationship(
        "ExecutionResult", back_populates="scan",
        cascade="all, delete-orphan", lazy="selectin",
    )


# ======================================================================
# Vulnerability — 发现的漏洞
# ======================================================================
class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_record_id = Column(Integer, ForeignKey("scan_records.id"), nullable=False, index=True)

    vuln_type = Column(String(64), nullable=False)          # bola, mass_assignment, info_leak 等
    owasp_category = Column(String(16), nullable=True)      # A01 ~ A10
    cvss_score = Column(Float, nullable=True)               # 0.0 ~ 10.0
    cvss_vector = Column(String(256), nullable=True)        # CVSS 向量字符串
    severity = Column(String(16), nullable=True)             # critical | high | medium | low | info
    endpoint = Column(String(1024), nullable=True)
    finding = Column(Text, nullable=True)                   # 漏洞描述
    recommendation = Column(Text, nullable=True)             # 修复建议
    confirmed = Column(Boolean, default=False)
    created_at = Column(DateTime, default=_utcnow)

    scan = relationship("ScanRecord", back_populates="vulnerabilities")


# ======================================================================
# AttackPlan — AI 生成的攻击方案
# ======================================================================
class AttackPlan(Base):
    __tablename__ = "attack_plans"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_record_id = Column(Integer, ForeignKey("scan_records.id"), nullable=False, index=True)

    phase = Column(String(8), nullable=False)                # phase1 | phase2
    round_number = Column(Integer, nullable=False)
    vuln_type = Column(String(64), nullable=True)
    reason = Column(Text, nullable=True)
    method = Column(String(10), nullable=True)               # GET | POST | PUT | DELETE | PATCH
    url_path = Column(String(1024), nullable=True)
    headers_json = Column(Text, nullable=True)
    query_params_json = Column(Text, nullable=True)
    body_json = Column(Text, nullable=True)
    expected_behavior = Column(Text, nullable=True)
    exploit_indicator = Column(Text, nullable=True)

    scan = relationship("ScanRecord", back_populates="attack_plans")


# ======================================================================
# ExecutionResult — 单次攻击执行结果
# ======================================================================
class ExecutionResult(Base):
    __tablename__ = "execution_results"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_record_id = Column(Integer, ForeignKey("scan_records.id"), nullable=False, index=True)

    phase = Column(String(8), nullable=False)                # phase1 | phase2
    round_number = Column(Integer, nullable=False)
    vuln_type = Column(String(64), nullable=True)
    method = Column(String(10), nullable=True)
    path = Column(String(1024), nullable=True)
    status_code = Column(Integer, nullable=True)
    response_preview = Column(Text, nullable=True)
    verdict = Column(String(16), nullable=True)              # hit | partial | miss
    injected_data_json = Column(Text, nullable=True)

    scan = relationship("ScanRecord", back_populates="execution_results")
