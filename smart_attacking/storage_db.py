"""
智攻 (SmartAttack) — 数据库存储层
=================================
基于 SQLAlchemy 的持久化存储，替代旧版 JSON 文件存储。
保持与 storage.py 相同的函数签名，确保 scanner.py 无缝切换。

新增功能：
- 扫描历史搜索/筛选/分页
- 扫描对比 (diff)
- 旧 JSON 文件自动迁移
"""

import json
import logging
import os
import uuid
from datetime import datetime, timezone

try:
    from cvss import estimate_cvss_for_vuln
    from models.database import SessionLocal, init_db
    from models.models import AttackPlan, ExecutionResult, ScanRecord, Vulnerability
    from owasp import get_owasp_category
except ImportError:
    from .cvss import estimate_cvss_for_vuln
    from .models.database import SessionLocal, init_db
    from .models.models import AttackPlan, ExecutionResult, ScanRecord, Vulnerability
    from .owasp import get_owasp_category

logger = logging.getLogger("smart_attack.storage_db")


# ======================================================================
# 公开 API（与旧 storage.py 完全兼容）
# ======================================================================


def save_scan(result_dict: dict) -> str:
    """保存一次完整扫描结果到数据库，返回 scan_id。

    result_dict 应为 /start_scan 返回的完整响应体（或包含 scan_id 的预创建记录）。
    """
    init_db()  # 幂等操作
    session = SessionLocal()

    try:
        scan_id = result_dict.get("scan_id") or uuid.uuid4().hex[:12]
        target_url = result_dict.get("target_url", "")
        status = result_dict.get("status", "completed")
        stats = result_dict.get("stats", {})
        model_used = stats.get("ai_model", "")

        # 检查是否已存在（异步模式下可能预创建了记录）
        existing = session.query(ScanRecord).filter_by(scan_id=scan_id).first()
        if existing:
            record = existing
            record.status = status
            record.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
        else:
            record = ScanRecord(
                scan_id=scan_id,
                target_url=target_url,
                status=status,
                model_used=model_used,
                stats_phase1_plan=stats.get("phase1_plan_count", 0),
                stats_phase1_exec=stats.get("phase1_executed", 0),
                stats_phase2_plan=stats.get("phase2_plan_count", 0),
                stats_phase2_exec=stats.get("phase2_executed", 0),
            )
            session.add(record)

        # 如果传入的是完整扫描结果，解析并持久化结构化数据
        if status == "completed":
            _parse_and_store_result(session, record, result_dict)

        session.commit()
        logger.info("扫描记录已保存到数据库: %s", scan_id)
        return scan_id

    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def list_scans(limit: int = 20, offset: int = 0,
               search: str = "", status: str = "",
               rating: str = "") -> dict:
    """列出扫描记录（支持搜索、筛选、分页）。

    Returns:
        {"scans": [...], "total": N, "limit": L, "offset": O}
    """
    init_db()
    session = SessionLocal()

    try:
        query = session.query(ScanRecord)

        if search:
            query = query.filter(ScanRecord.target_url.contains(search))
        if status:
            query = query.filter(ScanRecord.status == status)
        if rating:
            # 通过 security_assessment_json 中的 overall_rating 筛选
            query = query.filter(
                ScanRecord.security_assessment_json.like(f'%"overall_rating":"{rating}"%')
            )

        total = query.count()
        records = (
            query.order_by(ScanRecord.created_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )

        scans = []
        for r in records:
            # 从 security_assessment_json 提取 overall_rating
            overall_rating = "unknown"
            if r.security_assessment_json:
                try:
                    assessment = json.loads(r.security_assessment_json)
                    overall_rating = assessment.get("overall_rating", "unknown")
                except json.JSONDecodeError:
                    pass

            scans.append({
                "scan_id": r.scan_id,
                "created_at": r.created_at.isoformat() if r.created_at else "",
                "updated_at": r.updated_at.isoformat() if r.updated_at else "",
                "target_url": r.target_url,
                "status": r.status,
                "overall_rating": overall_rating,
                "model_used": r.model_used,
                "stats": {
                    "phase1_plan_count": r.stats_phase1_plan,
                    "phase1_executed": r.stats_phase1_exec,
                    "phase2_plan_count": r.stats_phase2_plan,
                    "phase2_executed": r.stats_phase2_exec,
                },
                "vuln_count": len(r.vulnerabilities) if r.vulnerabilities else 0,
            })

        return {"scans": scans, "total": total, "limit": limit, "offset": offset}

    finally:
        session.close()


def get_scan(scan_id: str) -> dict | None:
    """获取单次扫描的完整记录（与旧 JSON 格式兼容的返回结构）。"""
    init_db()
    session = SessionLocal()

    try:
        record = session.query(ScanRecord).filter_by(scan_id=scan_id).first()
        if record is None:
            return None

        return _reassemble_full_result(record)

    finally:
        session.close()


def get_scan_for_comparison(scan_id_a: str, scan_id_b: str) -> dict:
    """对比两次扫描结果。

    Returns:
        {
            "scan_a": {...}, "scan_b": {...},
            "comparison": {
                "rating_change": "...",
                "new_vulnerabilities": [...],
                "fixed_vulnerabilities": [...],
                "unchanged_vulnerabilities": [...],
                "stats_diff": {...}
            }
        }
    """
    scan_a = get_scan(scan_id_a)
    scan_b = get_scan(scan_id_b)

    if not scan_a or not scan_b:
        return None

    # 提取漏洞列表用于对比
    vulns_a = _extract_vuln_list(scan_a)
    vulns_b = _extract_vuln_list(scan_b)

    # 基于 vuln_type + endpoint 做匹配
    def _key(v):
        return (v.get("vuln_type", ""), v.get("endpoint", ""))

    set_a = {_key(v): v for v in vulns_a}
    set_b = {_key(v): v for v in vulns_b}

    new_vulns = [vulns_b[i] for i, v in enumerate(vulns_b) if _key(v) not in set_a]
    fixed_vulns = [vulns_a[i] for i, v in enumerate(vulns_a) if _key(v) not in set_b]
    unchanged = [vulns_b[i] for i, v in enumerate(vulns_b) if _key(v) in set_a]

    rating_a = scan_a.get("security_assessment", {}).get("overall_rating", "unknown")
    rating_b = scan_b.get("security_assessment", {}).get("overall_rating", "unknown")
    rating_change = f"{rating_a} → {rating_b}" if rating_a != rating_b else "unchanged"

    return {
        "scan_a": {"scan_id": scan_id_a, "target_url": scan_a.get("target_url", ""),
                    "created_at": scan_a.get("created_at", ""),
                    "overall_rating": rating_a},
        "scan_b": {"scan_id": scan_id_b, "target_url": scan_b.get("target_url", ""),
                    "created_at": scan_b.get("created_at", ""),
                    "overall_rating": rating_b},
        "comparison": {
            "rating_change": rating_change,
            "new_vulnerabilities": new_vulns,
            "fixed_vulnerabilities": fixed_vulns,
            "unchanged_vulnerabilities": unchanged,
            "stats_diff": {
                "scan_a_plans": scan_a.get("stats", {}).get("phase1_plan_count", 0),
                "scan_b_plans": scan_b.get("stats", {}).get("phase1_plan_count", 0),
                "scan_a_executed": scan_a.get("stats", {}).get("phase1_executed", 0),
                "scan_b_executed": scan_b.get("stats", {}).get("phase1_executed", 0),
            },
        },
    }


def update_scan_full(scan_id: str, result_dict: dict):
    """异步任务完成后更新完整扫描结果。"""
    init_db()
    session = SessionLocal()

    try:
        record = session.query(ScanRecord).filter_by(scan_id=scan_id).first()
        if not record:
            logger.error("无法更新扫描记录，不存在: %s", scan_id)
            return

        record.status = "completed"
        record.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)

        stats = result_dict.get("stats", {})
        record.stats_phase1_plan = stats.get("phase1_plan_count", 0)
        record.stats_phase1_exec = stats.get("phase1_executed", 0)
        record.stats_phase2_plan = stats.get("phase2_plan_count", 0)
        record.stats_phase2_exec = stats.get("phase2_executed", 0)
        record.model_used = stats.get("ai_model", "")

        # 清除旧的关联数据
        session.query(Vulnerability).filter_by(scan_record_id=record.id).delete()
        session.query(AttackPlan).filter_by(scan_record_id=record.id).delete()
        session.query(ExecutionResult).filter_by(scan_record_id=record.id).delete()

        _parse_and_store_result(session, record, result_dict)
        session.commit()
        logger.info("扫描记录已更新: %s", scan_id)

    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def mark_scan_failed(scan_id: str, error_message: str):
    """标记扫描失败。"""
    init_db()
    session = SessionLocal()

    try:
        record = session.query(ScanRecord).filter_by(scan_id=scan_id).first()
        if record:
            record.status = "failed"
            record.error_message = error_message
            record.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
            session.commit()
    except Exception:
        session.rollback()
    finally:
        session.close()


# ======================================================================
# 内部辅助函数
# ======================================================================


def _parse_and_store_result(session, record: ScanRecord, result_dict: dict):
    """解析扫描结果字典，填充结构化字段和关联表。"""
    data = result_dict.get("data", result_dict)

    # ---- 大 JSON 字段 ----
    business_analysis = data.get("business_analysis", {})
    security_assessment = data.get("security_assessment", {})
    result_analysis = data.get("result_analysis", {})

    record.business_analysis_json = json.dumps(business_analysis, ensure_ascii=False) if business_analysis else None
    record.security_assessment_json = json.dumps(security_assessment, ensure_ascii=False) if security_assessment else None
    record.result_analysis_json = json.dumps(result_analysis, ensure_ascii=False) if result_analysis else None

    # ---- 漏洞 ----
    _store_vulnerabilities(session, record, data)

    # ---- 攻击方案 (Phase 1) ----
    _store_attack_plans(session, record, data.get("attack_plans", []), "phase1")

    # ---- 攻击方案 (Phase 2 / follow-up) ----
    followup_plans = data.get("followup_plans", [])
    if followup_plans:
        _store_attack_plans(session, record, followup_plans, "phase2")

    # ---- 执行结果 (Phase 1) ----
    _store_execution_results(session, record, data.get("execution_results", []), "phase1")

    # ---- 执行结果 (Phase 2) ----
    followup_exec = data.get("followup_execution", [])
    if followup_exec:
        _store_execution_results(session, record, followup_exec, "phase2")


def _store_vulnerabilities(session, record: ScanRecord, data: dict):
    """从扫描结果中提取漏洞并持久化。"""
    confirmed_vulns = []
    if data.get("security_assessment", {}).get("vulnerabilities_found"):
        confirmed_vulns = data["security_assessment"]["vulnerabilities_found"]
    elif data.get("result_analysis", {}).get("confirmed_vulnerabilities"):
        confirmed_vulns = data["result_analysis"]["confirmed_vulnerabilities"]

    for v in confirmed_vulns:
        if isinstance(v, str):
            # 简单字符串 — 尝试从攻击面/执行结果中补充信息
            vuln_type = "unknown"
            finding = v
            endpoint = ""
            recommendation = ""
        elif isinstance(v, dict):
            vuln_type = v.get("vulnerability_type", v.get("type", "unknown"))
            finding = v.get("finding", v.get("description", json.dumps(v, ensure_ascii=False)))
            endpoint = v.get("endpoint", v.get("path", ""))
            recommendation = v.get("recommendation", v.get("remediation", ""))
        else:
            continue

        cat_id, cat_name, cat_name_zh = get_owasp_category(vuln_type)
        cvss_score, cvss_vector, severity = estimate_cvss_for_vuln(vuln_type)

        vuln_record = Vulnerability(
            vuln_type=vuln_type,
            owasp_category=cat_id,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            severity=severity,
            endpoint=endpoint,
            finding=finding,
            recommendation=recommendation,
            confirmed=True,
        )
        record.vulnerabilities.append(vuln_record)


def _store_attack_plans(session, record: ScanRecord, plans: list, phase: str):
    """存储攻击方案。"""
    for i, plan in enumerate(plans):
        if not isinstance(plan, dict):
            continue
        req = plan.get("request", {})
        ap = AttackPlan(
            phase=phase,
            round_number=i + 1,
            vuln_type=plan.get("vulnerability_type", "unknown"),
            reason=plan.get("reason", ""),
            method=req.get("method", "GET"),
            url_path=req.get("url_path", ""),
            headers_json=json.dumps(req.get("headers", {}), ensure_ascii=False),
            query_params_json=json.dumps(req.get("query_params"), ensure_ascii=False) if req.get("query_params") else None,
            body_json=json.dumps(req.get("body"), ensure_ascii=False) if req.get("body") else None,
            expected_behavior=str(plan.get("expected_normal_behavior", "") or ""),
            exploit_indicator=_serialize_if_dict(plan.get("exploit_indicator", "")),
        )
        record.attack_plans.append(ap)


def _store_execution_results(session, record: ScanRecord, results: list, phase: str):
    """存储攻击执行结果。"""
    for r in results:
        if not isinstance(r, dict):
            continue
        payload = r.get("payload", {})
        er = ExecutionResult(
            phase=phase,
            round_number=r.get("round", 0),
            vuln_type=r.get("vulnerability_type", "unknown"),
            method=payload.get("method", r.get("method", "GET")),
            path=payload.get("path", r.get("path", "/")),
            status_code=r.get("status_code"),
            response_preview=(r.get("response_text", "") or "")[:4000],
            verdict=_derive_verdict(r),
            injected_data_json=json.dumps(payload.get("injected_data"), ensure_ascii=False) if payload.get("injected_data") else None,
        )
        record.execution_results.append(er)


def _serialize_if_dict(value):
    """如果值是 dict/list，序列化为 JSON 字符串。"""
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    return str(value) if value else ""


def _derive_verdict(result: dict) -> str:
    """从执行结果中推导 verdict — 增强版：识别信息泄露和敏感数据暴露。

    判定逻辑：
    - hit（命中）：200 且返回了数据，或暴露了敏感信息/错误
    - partial（部分命中）：有信息泄露但未完全确认
    - miss（未命中）：无实际价值
    """
    text = (result.get("response_text", "") or "").lower()
    code = result.get("status_code", 0)
    vuln_type = result.get("vulnerability_type", "")

    if code == 0:
        return "miss"

    # 敏感关键词检测 — 出现任何一个都可能表示信息泄露或漏洞
    sensitive_keywords = [
        "password", "secret", "token", "credit", "role", "admin",
        "debug", "internal", "db_host", "db_password", "secret_key",
        "env_var", "config", "p@ssw0rd", "api_key", "private",
        "phone", "address", "ssn", "passport",
    ]

    has_sensitive = any(kw in text for kw in sensitive_keywords)

    # SQL 错误特征 — 表示注入可能成功
    sql_error_patterns = [
        "sql", "syntax error", "sqlite", "mysql", "postgresql",
        "unclosed quotation", "near", "column", "table",
    ]
    has_sql_error = any(p in text for p in sql_error_patterns)

    # 攻击 payload 中的注入字段是否出现在响应中（批量赋值成功）
    injected_data = result.get("payload", {}).get("injected_data", {})
    injection_reflected = False
    if isinstance(injected_data, dict):
        for key in ("role", "admin", "is_admin", "credit", "balance"):
            if key in text and str(injected_data.get(key, "")) in text:
                injection_reflected = True
                break

    # 成功响应（200-299）
    if 200 <= code < 300:
        # 排除了明确的拒绝信息
        if "unauthorized" in text or "not found" in text:
            return "miss"
        # 响应中包含敏感数据 → 确认命中
        if has_sensitive or injection_reflected:
            return "hit"
        # 响应体有实际内容 → 可能命中
        if len(text) > 50:
            return "hit"
        return "partial"

    # 非 200 但泄露了错误信息
    if has_sql_error or has_sensitive:
        return "partial"

    # 500 错误本身可能揭示信息
    if code >= 500:
        return "partial"

    return "miss"


def _reassemble_full_result(record: ScanRecord) -> dict:
    """从数据库记录重新组装为完整的扫描结果字典（与旧 JSON 格式兼容）。"""
    business_analysis = _safe_json(record.business_analysis_json)
    security_assessment = _safe_json(record.security_assessment_json)
    result_analysis = _safe_json(record.result_analysis_json)

    # 重组攻击方案
    attack_plans = []
    followup_plans = []
    for ap in (record.attack_plans or []):
        plan = {
            "vulnerability_type": ap.vuln_type,
            "reason": ap.reason,
            "expected_normal_behavior": ap.expected_behavior,
            "exploit_indicator": ap.exploit_indicator,
            "request": {
                "method": ap.method,
                "url_path": ap.url_path,
                "headers": _safe_json(ap.headers_json) or {},
                "query_params": _safe_json(ap.query_params_json),
                "body": _safe_json(ap.body_json),
            },
        }
        if ap.phase == "phase1":
            attack_plans.append(plan)
        else:
            followup_plans.append(plan)

    # 重组执行结果
    execution_results = []
    followup_execution = []
    for er in (record.execution_results or []):
        result = {
            "round": er.round_number,
            "vulnerability_type": er.vuln_type,
            "reason": "",
            "expected_normal": "",
            "exploit_indicator": "",
            "payload": {
                "method": er.method,
                "path": er.path,
                "vulnerability_type": er.vuln_type,
                "injected_data": _safe_json(er.injected_data_json),
            },
            "status_code": er.status_code,
            "response_text": er.response_preview,
        }
        if er.phase == "phase1":
            execution_results.append(result)
        else:
            followup_execution.append(result)

    # 重组漏洞列表进 security_assessment
    if record.vulnerabilities:
        vuln_list = []
        for v in record.vulnerabilities:
            vuln_list.append({
                "vulnerability_type": v.vuln_type,
                "owasp_category": v.owasp_category,
                "cvss_score": v.cvss_score,
                "cvss_vector": v.cvss_vector,
                "severity": v.severity,
                "endpoint": v.endpoint,
                "finding": v.finding,
                "recommendation": v.recommendation,
                "confirmed": v.confirmed,
            })
        if security_assessment:
            security_assessment["vulnerabilities_found"] = vuln_list
        if result_analysis:
            result_analysis["confirmed_vulnerabilities"] = vuln_list

    return {
        "scan_id": record.scan_id,
        "created_at": record.created_at.isoformat() if record.created_at else "",
        "updated_at": record.updated_at.isoformat() if record.updated_at else "",
        "target_url": record.target_url,
        "status": record.status,
        "model_used": record.model_used,
        "stats": {
            "phase1_plan_count": record.stats_phase1_plan,
            "phase1_executed": record.stats_phase1_exec,
            "phase2_plan_count": record.stats_phase2_plan,
            "phase2_executed": record.stats_phase2_exec,
            "ai_model": record.model_used,
        },
        "data": {
            "success": record.status == "completed",
            "target_url": record.target_url,
            "business_analysis": business_analysis,
            "attack_plans": attack_plans,
            "execution_results": execution_results,
            "result_analysis": result_analysis,
            "followup_plans": followup_plans,
            "followup_execution": followup_execution,
            "security_assessment": security_assessment,
        },
    }


def _extract_vuln_list(scan: dict) -> list:
    """从重组后的扫描结果中提取漏洞列表。"""
    assessment = scan.get("data", {}).get("security_assessment", {})
    return assessment.get("vulnerabilities_found", [])


def _safe_json(text: str | None):
    """安全解析 JSON，失败时返回 None。"""
    if not text:
        return None
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return None


# ======================================================================
# JSON → DB 迁移
# ======================================================================


def migrate_json_to_db(storage_dir: str = None) -> int:
    """将旧 JSON 文件迁移到数据库。幂等操作。

    Args:
        storage_dir: JSON 文件所在目录，默认从 config 读取

    Returns:
        迁移的扫描记录数
    """
    init_db()
    session = SessionLocal()

    try:
        # 检查是否已有数据
        existing_count = session.query(ScanRecord).count()
        if existing_count > 0:
            logger.info("数据库已有 %d 条记录，跳过迁移", existing_count)
            return 0

        # 确定 JSON 存储目录
        if storage_dir is None:
            from config import STORAGE_DIR
            storage_dir = STORAGE_DIR

        if not os.path.isdir(storage_dir):
            logger.info("JSON 存储目录不存在，跳过迁移: %s", storage_dir)
            return 0

        json_files = sorted(
            [f for f in os.listdir(storage_dir) if f.endswith(".json")]
        )
        if not json_files:
            logger.info("未找到 JSON 扫描记录，跳过迁移")
            return 0

        migrated = 0
        for filename in json_files:
            file_path = os.path.join(storage_dir, filename)
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    record = json.load(f)
            except (json.JSONDecodeError, OSError) as e:
                logger.warning("跳过损坏的文件 %s: %s", filename, e)
                continue

            try:
                scan_id = save_scan(record)
                logger.info("已迁移: %s → %s", filename, scan_id)
                migrated += 1
            except Exception as e:
                logger.error("迁移失败 %s: %s", filename, e)

        logger.info("JSON 迁移完成: %d/%d 条记录", migrated, len(json_files))
        return migrated

    finally:
        session.close()
