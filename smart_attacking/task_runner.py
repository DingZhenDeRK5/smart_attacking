"""
智攻 (SmartAttack) — 后台任务执行器
===================================
基于 threading.Thread 的异步扫描执行，无需 Celery/Redis 外部依赖。
提供任务提交、状态轮询、WebSocket 实时推送、完成通知的完整生命周期管理。

设计决策：
- 使用 daemon thread 而非 Celery，避免引入外部消息队列
- 内存字典 + threading.Lock 跟踪状态，足够课程项目使用
- 扫描逻辑与 scanner.py 保持独立，便于未来替换为 Celery
- v3.3: 新增 WebSocket 实时推送扫描进度和攻击结果
"""

import logging
import threading
import uuid
from datetime import datetime, timezone

try:
    from config import ENABLE_FOLLOWUP, MODEL
except ImportError:
    from smart_attacking.config import ENABLE_FOLLOWUP, MODEL

logger = logging.getLogger("smart_attack.task_runner")

# ---------------------------------------------------------------------------
# WebSocket 发射器（延迟导入避免循环依赖）
# ---------------------------------------------------------------------------
_socketio = None


def _get_socketio():
    """延迟获取 SocketIO 实例。"""
    global _socketio
    if _socketio is None:
        try:
            from scanner import socketio as sio
            _socketio = sio
        except ImportError:
            pass
    return _socketio


def _emit(scan_id: str, event: str, data: dict):
    """向指定 scan_id 的房间发送 WebSocket 事件。"""
    sio = _get_socketio()
    if sio:
        try:
            sio.emit(event, data, room=f"scan_{scan_id}", namespace="/ws")
        except Exception:
            pass  # WebSocket 发送失败不影响扫描流程

# ======================================================================
# 任务状态跟踪（内存）
# ======================================================================
# 格式: { scan_id: { status, phase, message, progress, started_at, updated_at } }
_task_status: dict = {}
_lock = threading.Lock()


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ======================================================================
# 公开 API
# ======================================================================


def submit_scan(target_url: str, model_provider: str = None,
                model_name: str = None, auth_config: dict = None,
                custom_base_url: str = None, user_id: str = None) -> str:
    """提交一次异步扫描，立即返回 scan_id。

    优先使用 Celery（如可用），否则降级到 threading。
    """
    scan_id = uuid.uuid4().hex[:12]

    with _lock:
        _task_status[scan_id] = {
            "status": "queued",
            "phase": "pending",
            "message": "等待执行…",
            "progress": 0,
            "started_at": _utcnow_iso(),
            "updated_at": _utcnow_iso(),
            "model_provider": model_provider,
            "model_name": model_name,
            "executor": "pending",  # 实际执行器在提交后确定
        }

    try:
        from storage_db import save_scan
        save_scan({
            "scan_id": scan_id,
            "target_url": target_url,
            "status": "queued",
            "stats": {"ai_model": model_name or MODEL},
            "user_id": user_id,
        })
    except Exception as e:
        logger.warning("预创建扫描记录失败 (非致命): %s", e)

    # 尝试 Celery，否则使用 threading
    if _try_submit_via_celery(scan_id, target_url, model_provider, model_name,
                              auth_config, custom_base_url):
        logger.info("异步扫描已提交 (Celery): %s → %s", scan_id, target_url)
    else:
        thread = threading.Thread(
            target=_run_scan,
            args=(scan_id, target_url, model_provider, model_name, auth_config, custom_base_url),
            daemon=True,
        )
        thread.start()
        logger.info("异步扫描已提交 (Threading): %s → %s", scan_id, target_url)

    return scan_id


def submit_shadow_scan(base_url: str, shadow_apis: list,
                       model_provider: str = None,
                       model_name: str = None) -> str:
    """对影子 API 列表发起异步安全扫描。"""
    scan_id = uuid.uuid4().hex[:12]

    with _lock:
        _task_status[scan_id] = {
            "status": "queued",
            "phase": "pending",
            "message": f"准备扫描 {len(shadow_apis)} 个影子 API…",
            "progress": 0,
            "started_at": _utcnow_iso(),
            "updated_at": _utcnow_iso(),
            "model_provider": model_provider,
            "model_name": model_name,
            "shadow_count": len(shadow_apis),
        }

    try:
        from storage_db import save_scan
        save_scan({
            "scan_id": scan_id,
            "target_url": f"{base_url} [影子API: {len(shadow_apis)} 个端点]",
            "status": "queued",
            "stats": {"ai_model": model_name or MODEL},
        })
    except Exception as e:
        logger.warning("预创建扫描记录失败 (非致命): %s", e)

    thread = threading.Thread(
        target=_run_shadow_scan,
        args=(scan_id, base_url, shadow_apis, model_provider, model_name),
        daemon=True,
    )
    thread.start()
    logger.info("影子 API 扫描已提交: %s → %d 个端点", scan_id, len(shadow_apis))
    return scan_id


def get_task_status(scan_id: str) -> dict | None:
    """获取异步任务状态。

    Returns:
        dict 或 None（任务不存在）
    """
    with _lock:
        return _task_status.get(scan_id)


# ======================================================================
# 后台扫描执行
# ======================================================================


def _execute_scan_logic(scan_id: str, target_url: str,
                        model_provider: str | None, model_name: str | None,
                        auth_config: dict | None = None,
                        custom_base_url: str | None = None):
    """执行完整的 5 阶段扫描流水线（纯逻辑，不含线程/Celery 封装）。

    此函数可被 threading.Thread 或 Celery Worker 调用。
    """
    from attacker import execute_dynamic_attack, fetch_remote_swagger
    from storage_db import mark_scan_failed, update_scan_full

    # 构建认证 headers
    auth_headers = _build_auth_headers(auth_config) if auth_config else {}

    try:
        # ---- Phase 1: 抓取 Swagger ----
        _update(scan_id, "running", "fetch", "正在抓取 Swagger 文档…", 5)
        swagger_data = fetch_remote_swagger(target_url, headers=auth_headers)

        # ---- Phase 2a: 规则引擎（快速，零 token 消耗） ----
        _update(scan_id, "running", "analyze",
                "规则引擎正在分析 API 端点并生成攻击载荷…", 5)
        rules_result = {"attack_plans": [], "rules_summary": {}, "total_plans": 0}
        try:
            from rules_engine import run_rules_engine
            rules_result = run_rules_engine(swagger_data)
            logger.info("[%s] 规则引擎完成: %d 组攻击方案 (%d 条规则命中)",
                        scan_id, rules_result["total_plans"],
                        len(rules_result.get("rules_summary", {})))
            _emit(scan_id, "scan_status", {
                "scan_id": scan_id, "status": "running", "phase": "analyze",
                "message": f"规则引擎完成: {rules_result['total_plans']} 组规则攻击方案",
                "progress": 10,
            })
        except Exception as e:
            logger.warning("[%s] 规则引擎失败 (非致命): %s", scan_id, e)

        # ---- Phase 2b: 多 Agent 协作分析 + AI 攻击方案生成 ----
        _update(scan_id, "running", "analyze",
                "规则引擎 + AI Agent 双引擎协作生成攻击方案…", 15)
        heuristic_result = {"attack_plans": [], "summary": {}, "total_plans": 0}
        try:
            from heuristic_engine import run_heuristic_engine
            heuristic_result = run_heuristic_engine(swagger_data)
            logger.info("[%s] Heuristic engine completed: %d plans",
                        scan_id, heuristic_result.get("total_plans", 0))
        except Exception as e:
            logger.warning("[%s] Heuristic engine failed (non-fatal): %s", scan_id, e)

        try:
            from agents import run_multi_agent_scan
            multi_result = run_multi_agent_scan(swagger_data)
            business_analysis = multi_result["business_analysis"]
            ai_attack_plans = multi_result["attack_plans"]
            agent_report = multi_result.get("agent_report", {})
            logger.info("[%s] Multi-agent analysis completed: ai_plans=%d",
                        scan_id, len(ai_attack_plans))
        except Exception as e:
            logger.warning("[%s] Multi-agent analysis failed, trying single-agent fallback: %s", scan_id, e)
            try:
                from ai_engine import analyze_and_generate_plans
                business_analysis, ai_attack_plans = analyze_and_generate_plans(
                    swagger_data,
                    provider_override=model_provider,
                    model_override=model_name,
                    base_url_override=custom_base_url,
                )
                agent_report = {"mode": "fallback_single_agent"}
            except Exception as ai_error:
                logger.warning("[%s] Single-agent fallback failed; continuing with deterministic plans: %s",
                               scan_id, ai_error)
                business_analysis = {"domain": "unknown", "analysis_mode": "deterministic_fallback"}
                ai_attack_plans = []
                agent_report = {"mode": "deterministic_fallback"}

        # ---- 合并双引擎攻击方案 ----
        rule_plans = rules_result.get("attack_plans", [])
        heuristic_plans = heuristic_result.get("attack_plans", [])
        # 去重：AI 方案与规则方案按 (method, path, vuln_type) 去重
        seen_keys = set()
        for plan in rule_plans + heuristic_plans:
            key = (plan["request"]["method"], plan["request"]["url_path"], plan["vulnerability_type"])
            seen_keys.add(key)
        deduped_ai_plans = []
        for plan in ai_attack_plans:
            key = (plan["request"]["method"], plan["request"]["url_path"], plan["vulnerability_type"])
            if key not in seen_keys:
                seen_keys.add(key)
                deduped_ai_plans.append(plan)

        # 规则方案在前（快速执行），AI 方案在后（业务逻辑深度测试）
        attack_plans = rule_plans + deduped_ai_plans
        attack_plans = rule_plans + heuristic_plans + deduped_ai_plans
        agent_report["rules_engine"] = {
            "plan_count": len(rule_plans),
            "rules_hit": list(rules_result.get("rules_summary", {}).keys()),
        }
        agent_report["heuristic_engine"] = {
            "plan_count": len(heuristic_plans),
            "summary": heuristic_result.get("summary", {}),
        }
        agent_report["dual_engine"] = True
        agent_report["total_plans"] = len(attack_plans)

        logger.info("[%s] Phase 2 双引擎完成: 规则=%d + AI=%d (去重后) → 共 %d 组攻击方案",
                    scan_id, len(rule_plans), len(deduped_ai_plans), len(attack_plans))

        if not attack_plans:
            raise RuntimeError("规则引擎和 AI 均未能生成有效攻击方案")

        # ---- Phase 3: 执行第一轮攻击 ----
        _update(scan_id, "running", "attack",
                f"正在执行 {len(attack_plans)} 组攻击…", 35)
        execution_results = execute_dynamic_attack(attack_plans, target_url, auth_headers=auth_headers)
        from result_analyzer import analyze_execution_results, merge_ai_and_local_analysis
        local_result_analysis, local_security_assessment = analyze_execution_results(execution_results)
        logger.info("[%s] Local analyzer found %d evidence-backed findings",
                    scan_id,
                    len(local_security_assessment.get("vulnerabilities_found", [])))
        logger.info("[%s] Phase 3 完成: %d 组执行结果", scan_id, len(execution_results))

        # WebSocket: 推送每一条攻击执行结果
        for idx, result in enumerate(execution_results):
            _emit(scan_id, "attack_result", {
                "index": idx + 1,
                "total": len(execution_results),
                "method": result.get("method", "GET"),
                "path": result.get("path", "/"),
                "status_code": result.get("status_code", 0),
                "vulnerability_type": result.get("vulnerability_type", ""),
                "verdict": _quick_verdict(result),
                "response_preview": (result.get("response_text", "") or "")[:300],
            })

        # ---- Phase 4: AI 结果分析 + 后续攻击 ----
        _update(scan_id, "running", "evaluate",
                "AI 正在分析攻击结果并生成后续方案…", 60)
        result_analysis = {}
        followup_plans = []
        followup_execution = []
        security_assessment = {}

        if ENABLE_FOLLOWUP:
            from ai_engine import analyze_results_and_followup
            try:
                result_analysis, followup_plans, security_assessment = (
                    analyze_results_and_followup(
                        business_analysis, execution_results, swagger_data,
                        provider_override=model_provider,
                        model_override=model_name,
                        base_url_override=custom_base_url,
                    )
                )
            except Exception as e:
                logger.warning("[%s] Phase 3 失败 (非致命): %s", scan_id, e)
                result_analysis = {
                    "error": str(e),
                    "summary": "AI 分析阶段出错，但第一轮攻击结果仍然有效",
                }

            # ---- Phase 5: 执行后续攻击 ----
            if followup_plans:
                _update(scan_id, "running", "followup",
                        f"正在执行 {len(followup_plans)} 组后续攻击…", 80)
                followup_execution = execute_dynamic_attack(followup_plans, target_url, auth_headers=auth_headers)

        # ---- Phase 5.5: 对抗式验证（交叉验证疑似漏洞）----
        result_analysis, security_assessment = merge_ai_and_local_analysis(
            result_analysis,
            security_assessment,
            local_result_analysis,
            local_security_assessment,
        )

        adversarial_report = {}
        if security_assessment and security_assessment.get("vulnerabilities_found"):
            vulns = security_assessment["vulnerabilities_found"]
            original_count = len(vulns)
            if vulns:
                _update(scan_id, "running", "evaluate",
                        f"对抗式验证: 攻击/防御 Agent 交叉验证 {len(vulns)} 个疑似漏洞…", 85)
                try:
                    from adversarial import adversarial_verify
                    adv_result = adversarial_verify(vulns)
                    # 用验证后的漏洞列表替换
                    security_assessment["vulnerabilities_found"] = adv_result["verified_vulns"]
                    security_assessment["false_positives_removed"] = len(adv_result.get("false_positives", []))
                    adversarial_report = {
                        "enabled": True,
                        "stats": adv_result["stats"],
                        "false_positives_removed": security_assessment["false_positives_removed"],
                    }
                    logger.info("[%s] 对抗验证完成: 确认=%d 降级=%d 误报过滤=%d",
                                scan_id,
                                adv_result["stats"].get("confirmed", 0),
                                adv_result["stats"].get("downgraded", 0),
                                adv_result["stats"].get("false_positive", 0))
                except Exception as e:
                    logger.warning("[%s] 对抗验证失败 (非致命): %s", scan_id, e)
                    adversarial_report = {"enabled": False, "error": str(e)}

                # ---- Phase 5.6: 二次验证（v3.6 新增）----
                verified_vulns = security_assessment.get("vulnerabilities_found", [])
                if verified_vulns:
                    _update(scan_id, "running", "evaluate",
                            f"二次验证: 验证 {len(verified_vulns)} 个漏洞…", 88)
                    try:
                        from result_analyzer import verify_vulnerabilities
                        final_vulns, verification_results = verify_vulnerabilities(
                            verified_vulns, execution_results, followup_execution
                        )
                        security_assessment["vulnerabilities_found"] = final_vulns
                        security_assessment["verification_applied"] = True
                        security_assessment["verified_count"] = len(final_vulns)
                        security_assessment["original_count"] = original_count
                        result_analysis["verified_vulnerabilities"] = final_vulns
                        result_analysis["verification_results"] = verification_results
                        logger.info("[%s] 二次验证完成: %d/%d 漏洞确认",
                                    scan_id, len(final_vulns), len(verified_vulns))
                    except Exception as e:
                        logger.warning("[%s] 二次验证失败 (非致命): %s", scan_id, e)

        # ---- 安全评分计算 ----
        result_analysis, security_assessment = merge_ai_and_local_analysis(
            result_analysis,
            security_assessment,
            local_result_analysis,
            local_security_assessment,
        )

        try:
            from scoring import calculate_score
            security_score = calculate_score({"data": {
                "security_assessment": security_assessment,
                "execution_results": execution_results,
                "stats": {"phase1_plan_count": len(attack_plans)},
            }})
            security_assessment["smartattack_score"] = security_score
        except Exception as e:
            logger.warning("[%s] 安全评分计算失败 (非致命): %s", scan_id, e)

        # ---- 汇总结果 ----
        _update(scan_id, "running", "done", "正在保存结果…", 95)

        result = {
            "scan_id": scan_id,
            "success": True,
            "target_url": target_url,
            "business_analysis": business_analysis,
            "attack_plans": attack_plans,
            "execution_results": execution_results,
            "result_analysis": result_analysis,
            "followup_plans": followup_plans,
            "followup_execution": followup_execution,
            "security_assessment": security_assessment,
            "agent_report": agent_report,
            "adversarial_report": adversarial_report,
            "stats": {
                "phase1_plan_count": len(attack_plans),
                "phase1_executed": len(execution_results),
                "phase2_plan_count": len(followup_plans),
                "phase2_executed": len(followup_execution),
                "ai_model": model_name or MODEL,
            },
        }

        update_scan_full(scan_id, result)

        # ---- 存入知识库（RAG） ----
        try:
            from knowledge_base import store_scan_knowledge
            store_scan_knowledge(result)
        except Exception as e:
            logger.warning("[%s] 知识库存储失败 (非致命): %s", scan_id, e)

        # ---- WebSocket: 推送扫描完成事件 + 漏洞摘要 ----
        hit_results = [
            r for r in execution_results
            if _quick_verdict(r) == "hit"
        ]
        vulns_found = (result.get("security_assessment", {}) or {}).get("vulnerabilities_found", [])
        _emit(scan_id, "scan_complete", {
            "scan_id": scan_id,
            "target_url": target_url,
            "total_attacks": len(execution_results),
            "hits": len(hit_results),
            "vulnerabilities_count": len(vulns_found),
            "overall_rating": (result.get("security_assessment", {}) or {}).get("overall_rating", "unknown"),
            "vulnerabilities": [
                {"type": v.get("vulnerability_type", "unknown"),
                 "severity": v.get("severity", "medium"),
                 "endpoint": v.get("endpoint", "")}
                for v in vulns_found[:10]
            ],
        })

        _update(scan_id, "completed", "done", "扫描完成", 100)
        logger.info("[%s] 扫描完成 ✅", scan_id)

    except Exception as e:
        logger.error("[%s] 扫描失败: %s", scan_id, e)
        try:
            mark_scan_failed(scan_id, str(e))
        except Exception:
            pass
        _update(scan_id, "failed", "error", str(e))


def _run_scan(scan_id: str, target_url: str,
              model_provider: str | None, model_name: str | None,
              auth_config: dict | None = None,
              custom_base_url: str | None = None):
    """Threading 封装：在后台线程中执行扫描流水线。"""
    _execute_scan_logic(scan_id, target_url, model_provider, model_name,
                        auth_config, custom_base_url)


def _execute_shadow_scan_logic(scan_id: str, base_url: str, shadow_apis: list,
                               model_provider: str | None, model_name: str | None):
    """执行影子 API 扫描逻辑（纯逻辑，不含线程/Celery 封装）。"""
    from attacker import execute_dynamic_attack
    from storage_db import mark_scan_failed, update_scan_full

    try:
        # ---- Phase 1: AI 分析影子 API ----
        _update(scan_id, "running", "analyze",
                f"AI 正在分析 {len(shadow_apis)} 个影子 API…", 15)

        from ai_engine import _run_shadow_analysis
        business_analysis, attack_plans = _run_shadow_analysis(
            base_url, shadow_apis,
            provider_override=model_provider,
            model_override=model_name,
        )

        if not attack_plans:
            raise RuntimeError("AI 未能针对影子 API 生成攻击方案")

        _update(scan_id, "running", "attack",
                f"正在攻击 {len(attack_plans)} 组影子 API 方案…", 40)
        execution_results = execute_dynamic_attack(attack_plans, base_url)

        # ---- Phase 2: 结果分析 ----
        _update(scan_id, "running", "evaluate",
                "AI 正在分析影子 API 攻击结果…", 75)

        from ai_engine import analyze_results_and_followup
        result_analysis, followup_plans, security_assessment = (
            analyze_results_and_followup(
                business_analysis, execution_results,
                str(shadow_apis),
                provider_override=model_provider,
                model_override=model_name,
            )
        )

        followup_execution = []
        if followup_plans:
            _update(scan_id, "running", "followup",
                    f"后续攻击 {len(followup_plans)} 组…", 90)
            followup_execution = execute_dynamic_attack(followup_plans, base_url)

        _update(scan_id, "running", "done", "保存结果…", 98)

        result = {
            "scan_id": scan_id,
            "success": True,
            "target_url": f"{base_url} [影子API检测]",
            "business_analysis": business_analysis,
            "attack_plans": attack_plans,
            "execution_results": execution_results,
            "result_analysis": result_analysis,
            "followup_plans": followup_plans,
            "followup_execution": followup_execution,
            "security_assessment": security_assessment,
            "shadow_apis_scanned": shadow_apis,
            "stats": {
                "phase1_plan_count": len(attack_plans),
                "phase1_executed": len(execution_results),
                "phase2_plan_count": len(followup_plans),
                "phase2_executed": len(followup_execution),
                "ai_model": model_name or MODEL,
            },
        }

        update_scan_full(scan_id, result)
        _update(scan_id, "completed", "done",
                f"影子 API 扫描完成：{len(shadow_apis)} 个端点已测试", 100)
        logger.info("[%s] 影子 API 扫描完成 ✅", scan_id)

    except Exception as e:
        logger.error("[%s] 影子 API 扫描失败: %s", scan_id, e)
        try:
            mark_scan_failed(scan_id, str(e))
        except Exception:
            pass
        _update(scan_id, "failed", "error", str(e))


def _run_shadow_scan(scan_id: str, base_url: str, shadow_apis: list,
                     model_provider: str | None, model_name: str | None):
    """Threading 封装：在后台线程中执行影子 API 扫描。"""
    _execute_shadow_scan_logic(scan_id, base_url, shadow_apis, model_provider, model_name)


# ======================================================================
# Celery 感知的任务提交
# ======================================================================


def _try_submit_via_celery(scan_id: str, target_url: str,
                           model_provider=None, model_name=None,
                           auth_config=None, custom_base_url=None) -> bool:
    """尝试通过 Celery 提交扫描任务。返回 True 表示已提交。"""
    try:
        from celery_app import submit_celery_scan
        return submit_celery_scan(
            scan_id, target_url, model_provider, model_name,
            auth_config, custom_base_url,
        )
    except Exception:
        return False


def _build_auth_headers(auth_config: dict) -> dict:
    """根据认证配置构建 HTTP Headers。"""
    headers = {}
    auth_type = auth_config.get("type", "none")
    if auth_type == "bearer":
        token = auth_config.get("token", "")
        if token:
            headers["Authorization"] = f"Bearer {token}"
    elif auth_type == "api_key":
        header_name = auth_config.get("header", "X-API-Key")
        value = auth_config.get("value", "")
        if header_name and value:
            headers[header_name] = value
    elif auth_type == "basic":
        import base64
        username = auth_config.get("username", "")
        password = auth_config.get("password", "")
        if username:
            encoded = base64.b64encode(f"{username}:{password}".encode()).decode()
            headers["Authorization"] = f"Basic {encoded}"
    return headers


def _quick_verdict(result: dict) -> str:
    """快速判断攻击结果（hit / partial / miss）。"""
    try:
        from result_analyzer import analyze_single_result
        verdict = analyze_single_result(result).get("verdict", "failed")
        if verdict == "success":
            return "hit"
        if verdict == "partial":
            return "partial"
        return "miss"
    except Exception:
        return "miss"


def _update(scan_id: str, status: str, phase: str, message: str,
            progress: int = None):
    """更新任务状态（线程安全）+ WebSocket 实时推送。"""
    with _lock:
        if scan_id in _task_status:
            _task_status[scan_id].update({
                "status": status,
                "phase": phase,
                "message": message,
                "updated_at": _utcnow_iso(),
            })
            if progress is not None:
                _task_status[scan_id]["progress"] = progress

    # WebSocket 实时推送状态更新
    _emit(scan_id, "scan_status", {
        "scan_id": scan_id,
        "status": status,
        "phase": phase,
        "message": message,
        "progress": progress,
    })
