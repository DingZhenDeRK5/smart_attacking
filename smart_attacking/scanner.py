"""
鏅烘敾 (SmartAttack) v3.5 鈥?鍚庣鍏ュ彛
==================================
鍩轰簬澶фā鍨嬬殑 API 鑷姩鍖栨笚閫忔祴璇曠郴缁熴€?妯″潡鍖栨灦鏋勶細config / parser / ai_engine / attacker / storage_db / agents / knowledge_base / rules_engine

v3.5 鏂板锛氳鍒欏紩鎿?+ AI 鍙屽紩鎿庢灦鏋勩€乄ebSocket 瀹炴椂鎺ㄩ€併€丼aaS 澶氱鎴枫€丆I/CD 闆嗘垚

鍚姩鏂瑰紡锛?    python scanner.py          锛堝湪 smart_attacking 鐩綍鍐咃級
    python -m smart_attacking.scanner   锛堝湪椤圭洰鏍圭洰褰曪級
"""

import logging
import os
import sys

# ---- 纭繚鍖呭唴妯″潡鍙互浜掔浉瀵煎叆锛堝吋瀹瑰绉嶅惎鍔ㄦ柟寮忥級 ----
_package_dir = os.path.dirname(os.path.abspath(__file__))
if _package_dir not in sys.path:
    sys.path.insert(0, _package_dir)

from flask import Flask, jsonify, make_response, request
from flask_cors import CORS
from flask_socketio import SocketIO, emit

from ai_engine import analyze_and_generate_plans, analyze_results_and_followup
from attacker import execute_dynamic_attack, fetch_remote_swagger
from config import DEBUG_MODE, ENABLE_FOLLOWUP, HOST, LLM_PROVIDER, MODEL, PORT
from storage_db import (
    get_scan,
    get_scan_for_comparison,
    list_scans,
    migrate_json_to_db,
    save_scan,
)

# ---------------------------------------------------------------------------
# 鏃ュ織
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s 鈥?%(message)s",
)
logger = logging.getLogger("smart_attack")

# ---------------------------------------------------------------------------
# Flask 搴旂敤 + WebSocket
# ---------------------------------------------------------------------------
app = Flask(__name__)
CORS(app)
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode="threading",  # 鍏煎 Windows / 绠€鍗曢儴缃?    logger=False,
    engineio_logger=False,
)


# ======================================================================
# 鍚姩鏃跺垵濮嬪寲
# ======================================================================
def _on_startup():
    """Endpoint handler."""
    from models.database import init_db

    init_db()
    try:
        count = migrate_json_to_db()
        if count > 0:
            logger.info("Migrated %d legacy JSON scan records into database", count)
    except Exception as e:
        logger.warning("JSON 杩佺Щ澶辫触锛堥潪鑷村懡锛? %s", e)


_on_startup()


def _merge_attack_plans(*plan_groups):
    """Endpoint handler."""
    merged = []
    seen = set()
    for plans in plan_groups:
        for plan in plans or []:
            if not isinstance(plan, dict) or not isinstance(plan.get("request"), dict):
                continue
            req = plan["request"]
            key = (
                req.get("method", "GET"),
                req.get("url_path", ""),
                str(req.get("query_params")),
                str(req.get("body")),
                plan.get("vulnerability_type", "unknown"),
            )
            if key in seen:
                continue
            seen.add(key)
            merged.append(plan)
    return merged


# ======================================================================
# API 绔偣
# ======================================================================


@app.route("/start_scan", methods=["POST"])
def start_scan():
    """Endpoint handler."""
    data = request.get_json(silent=True) or {}
    target_url = data.get("url")
    if not target_url:
        return jsonify({"success": False, "error": "缂哄皯蹇呰鍙傛暟 url"}), 400

    mode = data.get("mode", "async")
    auth_config = data.get("auth_config", {})
    custom_base_url = data.get("custom_base_url", "")

    # ---- 閰嶉妫€鏌ワ紙鐧诲綍鐢ㄦ埛锛?---
    user_id = None
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        try:
            from auth import decode_token, UserStore
            payload = decode_token(auth_header[7:])
            if payload:
                user_id = payload["sub"]
                quota = UserStore.check_quota(user_id)
                if not quota["allowed"]:
                    return jsonify({
                        "success": False,
                        "error": f"鏈湀鎵弿閰嶉宸茬敤灏?({quota['used']}/{quota['limit']})锛岃鍗囩骇璁″垝",
                        "quota": quota,
                    }), 429
        except Exception:
            pass  # 閰嶉妫€鏌ュけ璐ヤ笉闃绘鎵弿

    if mode == "async":
        # ---- 寮傛妯″紡锛氱珛鍗宠繑鍥?scan_id锛屽悗鍙版墽琛?----
        try:
            from task_runner import submit_scan

            scan_id = submit_scan(
                target_url,
                model_provider=data.get("model_provider"),
                model_name=data.get("model_name"),
                auth_config=auth_config,
                custom_base_url=custom_base_url,
                user_id=user_id,
            )
            # Consume quota only after a scan has been accepted.
            if user_id:
                try:
                    from auth import UserStore
                    UserStore.use_quota(user_id)
                except Exception:
                    pass
            return jsonify({
                "success": True,
                "scan_id": scan_id,
                "status": "queued",
                "message": "鎵弿宸插姞鍏ラ槦鍒楋紝鍙€氳繃 GET /scans/<scan_id>/status 鏌ヨ杩涘害",
            })
        except Exception as e:
            logger.error("鎻愪氦寮傛鎵弿澶辫触: %s", e)
            return jsonify({"success": False, "error": f"鎻愪氦鎵弿澶辫触: {e}"}), 500

    # ---- 鍚屾妯″紡锛堜繚鐣欎綔涓鸿皟璇曞洖閫€锛?---
    # ---- Step 1: 鎶撳彇 Swagger 鏂囨。 ----
    try:
        swagger_data = fetch_remote_swagger(target_url)
    except Exception as e:
        logger.error("鎶撳彇鐩爣鏂囨。澶辫触: %s", e)
        return jsonify({"success": False, "error": f"鎶撳彇鐩爣鏂囨。澶辫触: {e}"}), 502

    # ---- Step 2: AI 涓氬姟閫昏緫鍒嗘瀽 + 鏀诲嚮鏂规鐢熸垚 ----
    rules_result = {"attack_plans": [], "rules_summary": {}, "total_plans": 0}
    heuristic_result = {"attack_plans": [], "summary": {}, "total_plans": 0}
    try:
        from rules_engine import run_rules_engine
        rules_result = run_rules_engine(swagger_data)
    except Exception as e:
        logger.warning("Rules engine failed in sync scan (non-fatal): %s", e)
    try:
        from heuristic_engine import run_heuristic_engine
        heuristic_result = run_heuristic_engine(swagger_data)
    except Exception as e:
        logger.warning("Heuristic engine failed in sync scan (non-fatal): %s", e)

    try:
        business_analysis, ai_attack_plans = analyze_and_generate_plans(swagger_data)
    except Exception as e:
        logger.warning("Phase 1 AI analysis failed; continuing with deterministic plans: %s", e)
        business_analysis = {"domain": "unknown", "analysis_mode": "deterministic_fallback"}
        ai_attack_plans = []

    attack_plans = _merge_attack_plans(
        rules_result.get("attack_plans", []),
        heuristic_result.get("attack_plans", []),
        ai_attack_plans,
    )
    if not attack_plans:
        return jsonify({"success": False, "error": "AI 鏈兘鐢熸垚鏈夋晥鏀诲嚮鏂规"}), 502

    logger.info(
        "Analysis completed: domain=%s, plans=%d",
        business_analysis.get("domain", "unknown"),
        len(attack_plans),
    )

    # ---- Step 3: 执行第一轮攻击 ----
    execution_results = execute_dynamic_attack(attack_plans, target_url)
    from result_analyzer import analyze_execution_results, merge_ai_and_local_analysis
    local_result_analysis, local_security_assessment = analyze_execution_results(execution_results)
    logger.info("First attack round completed: %d results, %d vulnerabilities found",
                len(execution_results), len(local_result_analysis.get("confirmed_vulnerabilities", [])))

    # ---- Step 4: AI 分析结果 + 生成后续攻击 ----
    result_analysis = {}
    followup_plans = []
    followup_execution = []
    security_assessment = {}

    if ENABLE_FOLLOWUP:
        try:
            result_analysis, followup_plans, security_assessment = analyze_results_and_followup(
                business_analysis, execution_results, swagger_data
            )
            logger.info("AI result analysis completed: %d follow-up plans", len(followup_plans))
        except Exception as e:
            logger.warning("Phase 3 分析失败 (非致命): %s", e)
            result_analysis = {
                "error": str(e),
                "summary": "AI result analysis failed, but first-round execution results remain available.",
            }

        # ---- Step 5: 执行后续攻击 ----
        if followup_plans:
            followup_execution = execute_dynamic_attack(followup_plans, target_url)
            logger.info("Follow-up attack round completed: %d results", len(followup_execution))

    # ---- Step 6: 合并分析结果 ----
    result_analysis, security_assessment = merge_ai_and_local_analysis(
        result_analysis,
        security_assessment,
        local_result_analysis,
        local_security_assessment,
    )

    # ---- Step 7: 二次验证（v3.6 新增）----
    # 对确认的漏洞进行二次验证，减少误报
    verified_vulns = []
    verification_results = []
    confirmed_vulns = security_assessment.get("vulnerabilities_found", [])

    if confirmed_vulns and len(confirmed_vulns) > 0:
        logger.info("Starting verification phase for %d vulnerabilities...", len(confirmed_vulns))
        from result_analyzer import verify_vulnerabilities
        verified_vulns, verification_results = verify_vulnerabilities(
            confirmed_vulns, execution_results, followup_execution
        )
        security_assessment["vulnerabilities_found"] = verified_vulns
        security_assessment["verification_applied"] = True
        security_assessment["verified_count"] = len(verified_vulns)
        security_assessment["original_count"] = len(confirmed_vulns)
        result_analysis["verified_vulnerabilities"] = verified_vulns
        result_analysis["verification_results"] = verification_results
        logger.info("Verification completed: %d/%d vulnerabilities confirmed",
                    len(verified_vulns), len(confirmed_vulns))

    # ---- 汇总返回 ----
    result = {
        "success": True,
        "target_url": target_url,
        "business_analysis": business_analysis,
        "attack_plans": attack_plans,
        "execution_results": execution_results,
        "result_analysis": result_analysis,
        "followup_plans": followup_plans,
        "followup_execution": followup_execution,
        "security_assessment": security_assessment,
        "stats": {
            "phase1_plan_count": len(attack_plans),
            "phase1_executed": len(execution_results),
            "phase2_plan_count": len(followup_plans),
            "phase2_executed": len(followup_execution),
            "verified_vulnerabilities": len(verified_vulns) if verified_vulns else len(confirmed_vulns),
            "ai_model": data.get("model_name") or MODEL,
        },
    }

    # ---- 鎸佷箙鍖栦繚瀛?----
    try:
        scan_id = save_scan(result)
        result["scan_id"] = scan_id
    except Exception as e:
        logger.warning("淇濆瓨鎵弿璁板綍澶辫触 (闈炶嚧鍛?: %s", e)

    return jsonify(result)


@app.route("/scans", methods=["GET"])
def list_scans_handler():
    """Endpoint handler."""
    try:
        limit = request.args.get("limit", 20, type=int)
        offset = request.args.get("offset", 0, type=int)
        search = request.args.get("search", "", type=str)
        status = request.args.get("status", "", type=str)
        rating = request.args.get("rating", "", type=str)

        result = list_scans(
            limit=limit, offset=offset,
            search=search, status=status, rating=rating,
        )
        return jsonify({"success": True, **result})
    except Exception as e:
        logger.error("鑾峰彇鎵弿鍒楄〃澶辫触: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/scans/compare", methods=["GET"])
def compare_scans_handler():
    """Endpoint handler."""
    scan_id_a = request.args.get("a", "", type=str)
    scan_id_b = request.args.get("b", "", type=str)

    if not scan_id_a or not scan_id_b:
        return jsonify({"success": False, "error": "缂哄皯鍙傛暟 a 鍜?b (涓や釜 scan_id)"}), 400

    try:
        comparison = get_scan_for_comparison(scan_id_a, scan_id_b)
        if comparison is None:
            return jsonify({"success": False, "error": "鏃犳硶鑾峰彇鎵弿璁板綍杩涜瀵规瘮"}), 404
        return jsonify({"success": True, **comparison})
    except Exception as e:
        logger.error("鎵弿瀵规瘮澶辫触: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/scans/<scan_id>", methods=["GET"])
def get_scan_handler(scan_id):
    """Endpoint handler."""
    try:
        record = get_scan(scan_id)
        if record is None:
            return jsonify({"success": False, "error": f"鎵弿璁板綍涓嶅瓨鍦? {scan_id}"}), 404
        return jsonify({"success": True, "scan": record})
    except Exception as e:
        logger.error("鑾峰彇鎵弿璇︽儏澶辫触: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/scans/<scan_id>/status", methods=["GET"])
def get_scan_status_handler(scan_id):
    """Endpoint handler."""
    try:
        from task_runner import get_task_status

        status = get_task_status(scan_id)
        if status is None:
            # Check database for completed or failed scans after in-memory task state expires.
            record = get_scan(scan_id)
            if record:
                return jsonify({
                    "success": True,
                    "scan_id": scan_id,
                    "status": record.get("status", "completed"),
                    "phase": "done",
                    "message": "Scan completed" if record.get("status") == "completed" else record.get("error_message", ""),
                })
            return jsonify({"success": False, "error": f"鎵弿浠诲姟涓嶅瓨鍦? {scan_id}"}), 404
        return jsonify({"success": True, "scan_id": scan_id, **status})
    except Exception as e:
        logger.error("鑾峰彇鎵弿鐘舵€佸け璐? %s", e)
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/scans/<scan_id>/score", methods=["GET"])
def get_scan_score_handler(scan_id):
    """Endpoint handler."""
    record = get_scan(scan_id)
    if record is None:
        return jsonify({"success": False, "error": f"鎵弿璁板綍涓嶅瓨鍦? {scan_id}"}), 404

    try:
        from scoring import calculate_score
        score_result = calculate_score(record)
        return jsonify({"success": True, "score": score_result})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/scans/<scan_id>/report", methods=["GET"])
def get_scan_report_handler(scan_id):
    """Endpoint handler."""
    record = get_scan(scan_id)
    if record is None:
        return jsonify({"success": False, "error": f"鎵弿璁板綍涓嶅瓨鍦? {scan_id}"}), 404

    output_format = request.args.get("format", "pdf", type=str)

    try:
        if output_format == "json":
            from report_generator import build_report_data

            report_data = build_report_data(record)
            return jsonify({"success": True, "report": report_data})

        # PDF 鏍煎紡
        from report_generator import generate_pdf_report

        pdf_bytes = generate_pdf_report(record)
        response = make_response(pdf_bytes)
        response.headers["Content-Type"] = "application/pdf"
        response.headers["Content-Disposition"] = (
            f'attachment; filename="SmartAttack_{scan_id}.pdf"'
        )
        return response

    except Exception as e:
        logger.error("鐢熸垚鎶ュ憡澶辫触: %s", e)
        return jsonify({"success": False, "error": f"鐢熸垚鎶ュ憡澶辫触: {e}"}), 500


@app.route("/models", methods=["GET"])
def list_models_handler():
    """Endpoint handler."""
    providers = [
        {
            "id": "deepseek",
            "name": "DeepSeek",
            "models": ["deepseek-chat", "deepseek-reasoner"],
            "default_model": "deepseek-chat",
        },
        {
            "id": "openai",
            "name": "OpenAI",
            "models": ["gpt-4o", "gpt-4o-mini", "gpt-4.1"],
            "default_model": "gpt-4o",
        },
        {
            "id": "anthropic",
            "name": "Anthropic Claude",
            "models": ["claude-sonnet-4-20250514", "claude-haiku-4-5-20251001", "claude-opus-4-8"],
            "default_model": "claude-sonnet-4-20250514",
        },
        {
            "id": "custom",
            "name": "鑷畾涔?(OpenAI 鍏煎)",
            "models": [],
            "default_model": "",
            "requires_base_url": True,
        },
    ]

    return jsonify({
        "success": True,
        "providers": providers,
        "current": {
            "provider": LLM_PROVIDER,
            "model": MODEL,
        },
    })


@app.route("/import", methods=["POST"])
def import_api_docs_handler():
    """Endpoint handler."""
    data = request.get_json(silent=True) or {}
    content = data.get("content", "")
    fmt = data.get("format", "auto")
    base_url = data.get("base_url", "")

    if not content:
        return jsonify({"success": False, "error": "缂哄皯 content 鍙傛暟"}), 400

    try:
        from importer import import_api_docs, convert_to_swagger

        result = import_api_docs(content, fmt, base_url)
        if not result.get("success"):
            return jsonify(result), 400

        # Also generate Swagger text so the scanner can consume imported APIs.
        swagger_text = convert_to_swagger(result["endpoints"],
                                          result.get("source_name", "Imported API"))
        result["swagger"] = swagger_text
        return jsonify(result)
    except Exception as e:
        logger.error("瀵煎叆 API 鏂囨。澶辫触: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/import/formats", methods=["GET"])
def import_formats_handler():
    """Endpoint handler."""
    return jsonify({
        "success": True,
        "formats": [
            {"id": "postman", "name": "Postman Collection", "description": "Postman Collection v2.1 JSON export"},
            {"id": "graphql", "name": "GraphQL Schema", "description": "GraphQL introspection JSON"},
            {"id": "har", "name": "HAR (HTTP Archive)", "description": "Browser DevTools HAR export"},
            {"id": "urls", "name": "URL List", "description": "Plain text URL list, one URL per line"},
            {"id": "auto", "name": "Auto Detect", "description": "Automatically detect input format"},
        ],
    })


@app.route("/shadow_api/detect", methods=["POST"])
def shadow_api_detect():
    """Endpoint handler."""
    data = request.get_json(silent=True) or {}
    swagger_url = data.get("swagger_url")
    traffic_log = data.get("traffic_log")
    traffic_format = data.get("traffic_format", "auto")

    if not swagger_url:
        return jsonify({"success": False, "error": "缂哄皯鍙傛暟 swagger_url"}), 400
    if not traffic_log:
        return jsonify({"success": False, "error": "缂哄皯鍙傛暟 traffic_log"}), 400

    try:
        # 鎶撳彇 Swagger 鏂囨。
        swagger_text = fetch_remote_swagger(swagger_url)
    except Exception as e:
        logger.error("鎶撳彇 Swagger 鏂囨。澶辫触: %s", e)
        return jsonify({"success": False, "error": f"鎶撳彇 Swagger 鏂囨。澶辫触: {e}"}), 502

    try:
        from shadow_api import detect_shadow_apis

        result = detect_shadow_apis(swagger_text, traffic_log, traffic_format)
        return jsonify({"success": True, **result})
    except Exception as e:
        logger.error("褰卞瓙 API 妫€娴嬪け璐? %s", e)
        return jsonify({"success": False, "error": f"妫€娴嬪け璐? {e}"}), 500


@app.route("/shadow_api/scan", methods=["POST"])
def shadow_api_scan():
    """Endpoint handler."""
    data = request.get_json(silent=True) or {}
    base_url = data.get("base_url")
    shadow_apis = data.get("shadow_apis", [])

    if not base_url:
        return jsonify({"success": False, "error": "缂哄皯鍙傛暟 base_url"}), 400
    if not shadow_apis:
        return jsonify({"success": False, "error": "缂哄皯鍙傛暟 shadow_apis"}), 400

    try:
        from task_runner import submit_shadow_scan

        scan_id = submit_shadow_scan(
            base_url, shadow_apis,
            model_provider=data.get("model_provider"),
            model_name=data.get("model_name"),
        )
        return jsonify({
            "success": True,
            "scan_id": scan_id,
            "status": "queued",
            "message": f"宸插 {len(shadow_apis)} 涓奖瀛?API 鍙戣捣鎵弿锛屽彲閫氳繃 GET /scans/<scan_id>/status 鏌ヨ杩涘害",
        })
    except Exception as e:
        logger.error("褰卞瓙 API 鎵弿澶辫触: %s", e)
        return jsonify({"success": False, "error": f"鎵弿澶辫触: {e}"}), 500


@app.route("/health", methods=["GET"])
def health():
    """Endpoint handler."""
    kb_stats = {}
    try:
        from knowledge_base import get_knowledge_stats
        kb_stats = get_knowledge_stats()
    except Exception:
        pass

    # 瑙勫垯寮曟搸鐘舵€?    rules_info = []
    try:
        from rules_engine import get_rules_info
        rules_info = get_rules_info()
    except Exception:
        pass

    return jsonify({
        "status": "ok",
        "model": MODEL,
        "provider": LLM_PROVIDER,
        "knowledge_base": kb_stats,
        "rules_engine": {
            "rules_loaded": len(rules_info),
            "rules": [r["name"] for r in rules_info],
        },
        "version": "3.5.0",
        "features": ["multi_agent", "rag_knowledge_base", "chromadb", "rules_engine", "dual_engine", "websocket"],
    })


@app.route("/rules", methods=["GET"])
def list_rules_handler():
    """Endpoint handler."""
    try:
        from rules_engine import get_rules_info
        rules = get_rules_info()
        return jsonify({"success": True, "rules": rules, "total": len(rules)})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/knowledge_base/stats", methods=["GET"])
def knowledge_base_stats():
    """Endpoint handler."""
    try:
        from knowledge_base import get_knowledge_stats
        return jsonify({"success": True, **get_knowledge_stats()})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ======================================================================
# 璁よ瘉 & 鐢ㄦ埛绠＄悊 API
# ======================================================================


@app.route("/auth/register", methods=["POST"])
def auth_register():
    """Endpoint handler."""
    data = request.get_json(silent=True) or {}
    email = data.get("email", "").strip()
    username = data.get("username", "").strip()
    password = data.get("password", "")
    company = data.get("company", "").strip()

    if not email or not username or not password:
        return jsonify({"success": False, "error": "Missing required fields: email, username, password"}), 400
    if len(password) < 6:
        return jsonify({"success": False, "error": "Password must be at least 6 characters"}), 400

    from auth import UserStore
    user = UserStore.create_user(email, username, password, company=company)
    if user is None:
        return jsonify({"success": False, "error": "璇ラ偖绠卞凡娉ㄥ唽"}), 409

    from auth import create_token
    token = create_token(user)
    return jsonify({"success": True, "user": user, "token": token}), 201


@app.route("/auth/login", methods=["POST"])
def auth_login():
    """Endpoint handler."""
    data = request.get_json(silent=True) or {}
    email = data.get("email", "").strip()
    password = data.get("password", "")

    if not email or not password:
        return jsonify({"success": False, "error": "Missing email or password"}), 400

    from auth import UserStore, create_token
    user = UserStore.authenticate(email, password)
    if user is None:
        return jsonify({"success": False, "error": "Invalid email or password"}), 401

    token = create_token(user)
    return jsonify({"success": True, "user": user, "token": token})


@app.route("/auth/me", methods=["GET"])
def auth_me():
    """Endpoint handler."""
    from auth import login_required

    @login_required
    def _me():
        from auth import UserStore, PLANS
        from flask import g
        user = UserStore.get_user(g.user_id)
        if user is None:
            return jsonify({"success": False, "error": "User not found"}), 404
        plan_info = PLANS.get(user.get("plan", "free"), PLANS["free"])
        return jsonify({"success": True, "user": user, "plan_info": plan_info})

    return _me()


@app.route("/auth/quota", methods=["GET"])
def auth_quota():
    """Endpoint handler."""
    from auth import login_required, UserStore, PLANS
    from flask import g

    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"success": False, "error": "Authentication required"}), 401

    from auth import decode_token
    payload = decode_token(auth_header[7:])
    if not payload:
        return jsonify({"success": False, "error": "Token 鏃犳晥"}), 401

    quota = UserStore.check_quota(payload["sub"])
    plan_info = PLANS.get(quota["plan"], PLANS["free"])
    return jsonify({"success": True, "quota": quota, "plan_info": plan_info})


# ---- API Assets 绠＄悊 ----


@app.route("/auth/assets", methods=["GET"])
def auth_assets_list():
    """Endpoint handler."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"success": False, "error": "Authentication required"}), 401

    from auth import decode_token, UserStore
    payload = decode_token(auth_header[7:])
    if not payload:
        return jsonify({"success": False, "error": "Token 鏃犳晥"}), 401

    assets = UserStore.list_assets(payload["sub"])
    return jsonify({"success": True, "assets": assets})


@app.route("/auth/assets", methods=["POST"])
def auth_assets_create():
    """Endpoint handler."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"success": False, "error": "Authentication required"}), 401

    from auth import decode_token, UserStore
    payload = decode_token(auth_header[7:])
    if not payload:
        return jsonify({"success": False, "error": "Token 鏃犳晥"}), 401

    data = request.get_json(silent=True) or {}
    name = data.get("name", "").strip()
    url = data.get("url", "").strip()
    if not name or not url:
        return jsonify({"success": False, "error": "Missing name or url"}), 400

    asset_id = UserStore.create_asset(
        payload["sub"], name, url,
        asset_type=data.get("asset_type", "swagger"),
        auth_config=data.get("auth_config", {}),
    )
    return jsonify({"success": True, "asset_id": asset_id}), 201


@app.route("/auth/assets/<asset_id>", methods=["DELETE"])
def auth_assets_delete(asset_id):
    """Endpoint handler."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"success": False, "error": "Authentication required"}), 401

    from auth import decode_token, UserStore
    payload = decode_token(auth_header[7:])
    if not payload:
        return jsonify({"success": False, "error": "Token 鏃犳晥"}), 401

    ok = UserStore.delete_asset(payload["sub"], asset_id)
    return jsonify({"success": ok, "message": "Deleted" if ok else "Not found or not allowed"})


# ======================================================================
# WebSocket 浜嬩欢澶勭悊
# ======================================================================


@socketio.on("connect", namespace="/ws")
def ws_connect():
    """Endpoint handler."""
    logger.info("WebSocket 瀹㈡埛绔凡杩炴帴: %s", request.sid)


@socketio.on("disconnect", namespace="/ws")
def ws_disconnect():
    """Endpoint handler."""
    logger.info("WebSocket 瀹㈡埛绔凡鏂紑: %s", request.sid)


@socketio.on("subscribe_scan", namespace="/ws")
def ws_subscribe_scan(data: dict):
    """Endpoint handler."""
    scan_id = data.get("scan_id", "")
    if scan_id:
        socketio.server.enter_room(request.sid, f"scan_{scan_id}", namespace="/ws")
        logger.info("瀹㈡埛绔?%s 宸茶闃呮壂鎻忔埧闂? scan_%s", request.sid, scan_id)
        emit("subscribed", {"scan_id": scan_id, "status": "ok"})
    else:
        emit("error", {"message": "缂哄皯 scan_id"})


@socketio.on("unsubscribe_scan", namespace="/ws")
def ws_unsubscribe_scan(data: dict):
    """Endpoint handler."""
    scan_id = data.get("scan_id", "")
    if scan_id:
        socketio.server.leave_room(request.sid, f"scan_{scan_id}", namespace="/ws")
        emit("unsubscribed", {"scan_id": scan_id, "status": "ok"})


# ======================================================================
# 鍚姩鍏ュ彛
# ======================================================================
if __name__ == "__main__":
    logger.info(
        "鏅烘敾鍚庣寮曟搸 v3.5 (鍙屽紩鎿?+ WebSocket) 鍚姩: http://%s:%s", HOST, PORT
    )
    socketio.run(app, host=HOST, port=PORT, debug=DEBUG_MODE, allow_unsafe_werkzeug=True)
