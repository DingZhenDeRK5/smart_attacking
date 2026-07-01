"""
Local evidence-based result analyzer.

The LLM can still provide deeper reasoning, but this module prevents scans from
ending with no findings simply because model output failed or varied.

v3.6 鏀硅繘锛?- 鎻愰珮缃俊搴﹂槇鍊硷紝鍑忓皯璇姤
- 娣诲姞婕忔礊鍚堝苟鏈哄埗锛岄伩鍏嶉噸澶嶆姤鍛?- 娣诲姞浜屾楠岃瘉閫昏緫
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from typing import Any

# 鎻愰珮闃堝€硷細浠?0.55 鎻愰珮鍒?0.72
CONFIDENCE_THRESHOLD_CONFIRMED = 0.72  # 纭涓烘紡娲炵殑鏈€浣庣疆淇″害
CONFIDENCE_THRESHOLD_PARTIAL = 0.60    # 閮ㄥ垎纭鐨勬渶浣庣疆淇″害

# 姣忎釜绔偣姣忕婕忔礊绫诲瀷鏈€澶氭姤鍛婁竴娆?MAX_VULNS_PER_ENDPOINT_TYPE = 1

SENSITIVE_PATTERNS = {
    "password": r"\bpassword\b",
    "token": r"\b(auth_)?token\b|bearer\s+[A-Za-z0-9._-]+",
    "secret": r"\bsecret(_key|_token)?\b",
    "api_key": r"\bapi[_-]?key\b",
    "private_key": r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",
    "debug": r"\b(debug|traceback|stack trace)\b",
    "internal_config": r"\b(db_host|db_password|database_url|secret_key|internal_config|env_vars)\b",
    "role": r"\b(role|admin|is_admin|permission_level)\b",
    "personal_data": r"\b(phone|address|ssn|passport)\b",
    "internal_ip": r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b|\b172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}\b|\b192\.168\.\d{1,3}\.\d{1,3}\b",
}

SQL_ERROR_PATTERNS = [
    r"sql syntax",
    r"mysql_fetch",
    r"mysql error",
    r"sqlite(?:3)?::",
    r"sqlite error",
    r"postgresql",
    r"psycopg2",
    r"ora-\d{5}",
    r"sqlstate",
    r"unclosed quotation",
    r"unknown column",
    r"syntax error at or near",
]

TRAVERSAL_PATTERNS = [
    r"root:.*:0:0:",
    r"\[fonts\]",
    r"for 16-bit app support",
    r"DB_PASSWORD",
    r"SECRET_KEY",
]

NEGATIVE_MARKERS = [
    "unauthorized",
    "forbidden",
    "invalid token",
    "not authorized",
    "permission denied",
    "not found",
    "does not exist",
    "password incorrect",
    "username does not exist",
    "invalid credentials",
    "authentication required",
]


def analyze_execution_results(results: list[dict]) -> tuple[dict, dict]:
    """Return result_analysis and security_assessment derived from responses.

    v3.6 鏀硅繘锛?    - 鎻愰珮缃俊搴﹂槇鍊?    - 娣诲姞浜屾楠岃瘉閫昏緫
    - 鏀硅繘婕忔礊鍚堝苟鏈哄埗
    """
    per_attack = []
    confirmed = []
    leaked = []

    for result in results or []:
        analysis = analyze_single_result(result)
        per_attack.append({
            "round": result.get("round", 0),
            "verdict": analysis["verdict"],
            "finding": analysis["finding"],
            "why": analysis["why"],
            "confidence": analysis["confidence"],
        })
        leaked.extend(analysis["leaked"])

        if analysis["verdict"] == "success" and analysis["confidence"] >= CONFIDENCE_THRESHOLD_CONFIRMED:
            confirmed.append(_vulnerability_from_analysis(result, analysis))

    # 鏀硅繘鐨勫幓閲嶅拰鍚堝苟
    confirmed = _smart_dedupe_vulnerabilities(confirmed)

    # 闄愬埗娉勯湶淇℃伅鏁伴噺
    leaked = sorted(set(leaked))[:20]

    defense_level = _defense_level(confirmed, len(results or []))
    rating = _overall_rating(confirmed)

    result_analysis = {
        "per_attack_analysis": per_attack,
        "confirmed_vulnerabilities": confirmed,
        "information_leaked": leaked,
        "defense_level": defense_level,
        "summary": f"Local analyzer found {len(confirmed)} confirmed vulnerabilities from {len(results or [])} executed attacks (threshold: {CONFIDENCE_THRESHOLD_CONFIRMED}).",
        "source": "local_evidence_analyzer",
    }
    security_assessment = {
        "overall_rating": rating,
        "vulnerabilities_found": confirmed,
        "remediation_advice": _remediation_advice(confirmed),
        "source": "local_evidence_analyzer",
    }
    return result_analysis, security_assessment


def analyze_single_result(result: dict) -> dict:
    """Analyze a single attack result with stricter criteria.

    v3.6 鏀硅繘锛?    - 娣诲姞浜屾楠岃瘉閫昏緫
    - 鏇翠弗鏍肩殑鍒ゅ畾鏍囧噯
    - 鍑忓皯璇姤
    """
    text = result.get("response_text", "") or ""
    text_lower = text.lower()
    status = int(result.get("status_code", 0) or 0)
    vuln_type = result.get("vulnerability_type", "unknown")
    payload = result.get("payload", {}) or {}
    injected = payload.get("injected_data")

    signals = []
    leaked = []
    confidence = 0.0

    has_rejection = any(marker in text_lower for marker in NEGATIVE_MARKERS)
    is_success_status = 200 <= status < 300
    has_body = len(text.strip()) > 2

    rejection_confidence_penalty = 0.3 if has_rejection else 0

    sensitive_hits = _filter_contextual_sensitive_hits(
        text,
        _match_named_patterns(text, SENSITIVE_PATTERNS),
    )
    if sensitive_hits:
        signals.append(f"sensitive fields exposed: {', '.join(sensitive_hits[:5])}")
        leaked.extend(sensitive_hits)
        confidence = max(confidence, 0.78)  # 鎻愰珮鍩虹缃俊搴?
    if _match_any(text, SQL_ERROR_PATTERNS):
        signals.append("database error signature in response")
        confidence = max(confidence, 0.85)
        vuln_type = "sql_injection" if vuln_type in {"baseline_probe", "unknown"} else vuln_type

    if _match_any(text, TRAVERSAL_PATTERNS):
        signals.append("local file or environment content signature in response")
        confidence = max(confidence, 0.85)

    injection_reflected = _injected_privilege_reflected(injected, text)
    if injection_reflected:
        signals.append("privilege-related injected fields reflected or persisted")
        confidence = max(confidence, 0.88)
        vuln_type = "mass_assignment"

    if vuln_type in {"auth_bypass", "idor", "bola"} and is_success_status and has_body and not has_rejection:
        # 浜屾楠岃瘉锛氭鏌ュ搷搴旀槸鍚﹀寘鍚疄闄呯殑鏁版嵁锛堜笉浠呬粎鏄垚鍔熸秷鎭級
        if _contains_actual_data(text):
            signals.append("protected or object-level access test returned actual data with 2xx status")
            confidence = max(confidence, 0.80)
        else:
            signals.append("test returned 2xx but without substantial data")
            confidence = max(confidence, 0.55)

    if vuln_type == "weak_credentials" and is_success_status and re.search(r"token|jwt|logged in", text_lower):
        if re.search(r"eyJ[A-Za-z0-9_-]+\.|bearer\s+[A-Za-z0-9._-]+", text_lower):
            signals.append("weak credential login returned valid token")
            confidence = max(confidence, 0.90)
        elif re.search(r"logged in|successfully", text_lower) and not has_rejection:
            signals.append("weak credential login returned success")
            confidence = max(confidence, 0.82)

    if vuln_type == "logic_bypass" and is_success_status and re.search(r"reset|password|changed|success", text_lower):
        if re.search(r"successfully|password (was )?reset|changed successfully", text_lower) and not has_rejection:
            signals.append("sensitive workflow completed without required prior proof or authentication")
            confidence = max(confidence, 0.88)

    if vuln_type == "auth_bypass" and payload.get("method") in {"POST", "PUT", "PATCH", "DELETE"} and is_success_status and not has_rejection:
        signals.append("write operation succeeded without valid authentication")
        confidence = max(confidence, 0.85)

    if vuln_type == "debug_exposure" and is_success_status and re.search(
        r"debug|actuator|metrics|env|config|secret|heapdump|db_password",
        text_lower,
    ):
        signals.append("debug or management endpoint exposed diagnostic data")
        confidence = max(confidence, 0.88)

    if status >= 500 and _interesting_error(text):
        signals.append("server error leaked implementation details")
        confidence = max(confidence, 0.55)  # 闄嶄綆

    if not signals and is_success_status and vuln_type in {"info_leak", "baseline_probe"} and has_body:
        if _looks_like_business_data(text):
            if _contains_sensitive_business_data(text):
                signals.append("unauthenticated request returned sensitive business data")
                confidence = max(confidence, 0.72)
            else:
                # 鍙槸鏅€氫笟鍔℃暟鎹紝涓嶆槸鏁忔劅鏁版嵁
                signals.append("unauthenticated request returned business data (may be intended)")
                confidence = max(confidence, 0.45)  # 浣庝簬闃堝€硷紝涓嶆姤鍛?
    # 搴旂敤鎷掔粷鎯╃綒
    confidence = max(0, confidence - rejection_confidence_penalty)

    verdict = "failed"
    if confidence >= CONFIDENCE_THRESHOLD_CONFIRMED:
        verdict = "success"
    elif confidence >= CONFIDENCE_THRESHOLD_PARTIAL:
        verdict = "partial"

    return {
        "verdict": verdict,
        "finding": "; ".join(signals) if signals else "No clear vulnerability evidence found.",
        "why": _why(result, signals),
        "confidence": round(confidence, 2),
        "leaked": leaked,
        "normalized_type": _normalize_vulnerability_type(
            result,
            vuln_type,
            status,
            text_lower,
            sensitive_hits,
            injection_reflected,
            signals,
        ),
    }


def merge_ai_and_local_analysis(
    ai_result_analysis: dict | None,
    ai_security_assessment: dict | None,
    local_result_analysis: dict,
    local_security_assessment: dict,
) -> tuple[dict, dict]:
    """Merge LLM findings with deterministic local findings.

    v3.6 鏀硅繘锛氫娇鐢ㄦ洿鏅鸿兘鐨勫幓閲嶉€昏緫
    """
    ai_result_analysis = ai_result_analysis or {}
    ai_security_assessment = ai_security_assessment or {}

    merged_analysis = dict(ai_result_analysis)
    if not merged_analysis.get("per_attack_analysis"):
        merged_analysis["per_attack_analysis"] = local_result_analysis.get("per_attack_analysis", [])

    ai_vulns = merged_analysis.get("confirmed_vulnerabilities", [])
    local_vulns = local_result_analysis.get("confirmed_vulnerabilities", [])
    # 浣跨敤鏇存櫤鑳界殑鍘婚噸閫昏緫
    merged_vulns = _smart_dedupe_vulnerabilities(_as_list(ai_vulns) + _as_list(local_vulns))
    merged_analysis["confirmed_vulnerabilities"] = merged_vulns

    info_leaked = set(_as_list(merged_analysis.get("information_leaked", [])))
    info_leaked.update(local_result_analysis.get("information_leaked", []))
    merged_analysis["information_leaked"] = sorted(info_leaked)[:20]  # 闄愬埗鏁伴噺
    merged_analysis.setdefault("defense_level", local_result_analysis.get("defense_level", "unknown"))
    merged_analysis.setdefault("summary", local_result_analysis.get("summary", ""))
    merged_analysis["local_evidence_count"] = len(local_vulns)

    merged_assessment = dict(ai_security_assessment)
    ai_assessment_vulns = merged_assessment.get("vulnerabilities_found", [])
    merged_assessment["vulnerabilities_found"] = _smart_dedupe_vulnerabilities(
        _as_list(ai_assessment_vulns) + merged_vulns
    )
    if not merged_assessment.get("overall_rating") or merged_assessment.get("overall_rating") == "unknown":
        merged_assessment["overall_rating"] = local_security_assessment.get("overall_rating", "unknown")
    else:
        merged_assessment["overall_rating"] = _max_rating(
            merged_assessment.get("overall_rating"),
            local_security_assessment.get("overall_rating"),
        )
    merged_assessment.setdefault(
        "remediation_advice",
        local_security_assessment.get("remediation_advice", ""),
    )
    merged_assessment["local_evidence_count"] = len(local_vulns)
    return merged_analysis, merged_assessment


def _vulnerability_from_analysis(result: dict, analysis: dict) -> dict:
    payload = result.get("payload", {}) or {}
    endpoint = payload.get("path") or result.get("path", "")
    vuln_type = analysis.get("normalized_type") or result.get("vulnerability_type", "unknown")
    return {
        "vulnerability_type": vuln_type,
        "endpoint": endpoint,
        "severity": _severity_for(vuln_type, analysis["confidence"]),
        "finding": analysis["finding"],
        "evidence": _shorten(result.get("response_text", "") or "", 500),
        "confidence": analysis["confidence"],
        "recommendation": _recommendation_for(vuln_type),
    }


def _dedupe_vulnerabilities(vulns: list[Any]) -> list[dict]:
    best: dict[tuple[str, str], dict] = {}
    for raw in vulns:
        if isinstance(raw, str):
            item = {"vulnerability_type": "unknown", "endpoint": "", "finding": raw}
        elif isinstance(raw, dict):
            item = dict(raw)
        else:
            continue
        key = (
            str(item.get("vulnerability_type", item.get("type", "unknown"))),
            str(item.get("endpoint", item.get("path", ""))),
        )
        item["vulnerability_type"] = key[0]
        item["endpoint"] = key[1]
        item.setdefault("severity", _severity_for(key[0], float(item.get("confidence", 0.6) or 0.6)))
        if key not in best or float(item.get("confidence", 0) or 0) > float(best[key].get("confidence", 0) or 0):
            best[key] = item
    return list(best.values())


def _match_named_patterns(text: str, patterns: dict[str, str]) -> list[str]:
    hits = []
    for name, pattern in patterns.items():
        if re.search(pattern, text, re.IGNORECASE | re.MULTILINE):
            hits.append(name)
    return hits


def _filter_contextual_sensitive_hits(text: str, hits: list[str]) -> list[str]:
    """Avoid treating generic error text like 'Password incorrect' as leakage."""
    if not hits:
        return []
    filtered = []
    for hit in hits:
        if hit == "password" and not re.search(r'["\']password["\']\s*:', text, re.I):
            continue
        if hit == "role" and not re.search(r'["\'](?:role|admin|is_admin|permission_level)["\']\s*:', text, re.I):
            continue
        if hit == "token" and not re.search(r'["\'](?:auth_)?token["\']\s*:|bearer\s+[A-Za-z0-9._-]+|jwt_', text, re.I):
            continue
        filtered.append(hit)
    return filtered


def _match_any(text: str, patterns: list[str]) -> bool:
    return any(re.search(pattern, text, re.IGNORECASE | re.MULTILINE) for pattern in patterns)


def _normalize_vulnerability_type(
    result: dict,
    current_type: str,
    status: int,
    text_lower: str,
    sensitive_hits: list[str],
    injection_reflected: bool,
    signals: list[str],
) -> str:
    """Map noisy payload labels to the vulnerability proven by the response."""
    original_type = result.get("vulnerability_type", current_type or "unknown")
    payload = result.get("payload", {}) or {}
    method = payload.get("method", result.get("method", "GET"))
    endpoint = payload.get("path", result.get("path", ""))
    has_rejection = any(marker in text_lower for marker in NEGATIVE_MARKERS)
    is_success_status = 200 <= status < 300

    if original_type == "weak_credentials" and re.search(r"auth_token|jwt_|logged in|successfully logged", text_lower):
        return "weak_credentials"
    if original_type == "logic_bypass" and is_success_status and re.search(r"reset|password|changed|success", text_lower):
        return "logic_bypass"
    if original_type == "mass_assignment" and injection_reflected:
        return "mass_assignment"
    if original_type == "debug_exposure" and (
        "debug" in endpoint.lower()
        or re.search(r"debug|actuator|env_vars|internal_config|db_password", text_lower)
    ):
        return "debug_exposure"
    if original_type in {"auth_bypass", "idor", "bola"} and is_success_status and not has_rejection:
        return original_type
    if method in {"PUT", "PATCH", "DELETE"} and is_success_status and not has_rejection:
        return "auth_bypass"
    if any("database error signature" in signal for signal in signals):
        return "sql_injection"
    if any("local file or environment content" in signal for signal in signals):
        return "path_traversal" if original_type == "path_traversal" else "debug_exposure"
    if sensitive_hits:
        if original_type in {
            "baseline_probe",
            "brute_force",
            "command_injection",
            "nosql_injection",
            "sql_injection",
            "xss",
            "injection",
            "unknown",
        }:
            return "info_leak"
        return original_type
    if original_type == "baseline_probe":
        return "info_leak"
    return original_type


def _injected_privilege_reflected(injected: Any, text: str) -> bool:
    if not isinstance(injected, dict):
        return False
    lowered = text.lower()
    for key in ("role", "admin", "is_admin", "verified", "permission", "permission_level", "credit", "balance"):
        if key not in injected:
            continue
        val = injected.get(key)
        if key.lower() in lowered and str(val).lower() in lowered:
            return True
    return False


def _interesting_error(text: str) -> bool:
    return bool(re.search(r"traceback|exception|stack|line \d+|sql|database|internal", text, re.I))


def _looks_like_business_data(text: str) -> bool:
    try:
        data = json.loads(text)
    except (TypeError, json.JSONDecodeError):
        return False
    if isinstance(data, dict):
        keys = {str(k).lower() for k in data.keys()}
        return bool(keys & {"users", "user", "data", "books", "orders", "items", "email", "username"})
    if isinstance(data, list):
        return bool(data)
    return False


def _contains_actual_data(text: str) -> bool:
    """Check if response contains actual data (not just success message)."""
    try:
        data = json.loads(text)
    except (TypeError, json.JSONDecodeError):
        return False

    # 妫€鏌ユ槸鍚﹀寘鍚疄闄呯殑鏁版嵁瀛楁
    if isinstance(data, dict):
        data_keys = {"data", "result", "item", "items", "user", "users", "order", "orders", "book", "books"}
        keys = {str(k).lower() for k in data.keys()}
        if keys & data_keys:
            return True
        non_message_keys = keys - {"message", "success", "status", "code", "error"}
        return len(non_message_keys) >= 2
    if isinstance(data, list):
        return len(data) > 0
    return False


def _contains_sensitive_business_data(text: str) -> bool:
    """Check if response contains sensitive business data."""
    text_lower = text.lower()
    sensitive_keywords = [
        "password", "token", "secret", "api_key", "private",
        "credit_card", "ssn", "phone", "address", "email",
        "admin", "role", "permission", "is_admin",
    ]
    return any(kw in text_lower for kw in sensitive_keywords)


def _smart_dedupe_vulnerabilities(vulns: list[Any]) -> list[dict]:
    """Merge raw evidence into user-facing findings.

    The scanner may hit the same teaching vulnerability through several URLs,
    payloads, or LLM guesses. Report a risk bucket once, while preserving the
    affected endpoints and evidence count for traceability.
    """
    if not vulns:
        return []

    grouped: dict[str, list[dict]] = {}
    for raw in vulns:
        if isinstance(raw, str):
            item = {"vulnerability_type": "unknown", "endpoint": "", "finding": raw}
        elif isinstance(raw, dict):
            item = dict(raw)
        else:
            continue

        endpoint = _normalize_endpoint_for_dedup(str(item.get("endpoint", item.get("path", ""))))
        vuln_type = _normalize_vuln_type_for_dedup(str(item.get("vulnerability_type", item.get("type", "unknown"))))
        item["endpoint"] = endpoint
        item["vulnerability_type"] = vuln_type

        if not _has_enough_finding_support(item):
            continue

        bucket = _finding_bucket(item)
        item["vulnerability_type"] = _canonical_type_for_bucket(bucket, vuln_type)
        grouped.setdefault(bucket, []).append(item)

    deduped = []
    for bucket, items in grouped.items():
        best = max(items, key=_dedup_rank)
        affected_endpoints = sorted({item.get("endpoint", "") for item in items if item.get("endpoint")})
        findings = []
        for item in sorted(items, key=_dedup_rank, reverse=True):
            finding = str(item.get("finding", "")).strip()
            if finding and finding not in findings:
                findings.append(finding)

        best = dict(best)
        best["endpoint"] = _canonical_endpoint_for_bucket(bucket, affected_endpoints)
        best["affected_endpoints"] = affected_endpoints
        best["evidence_count"] = len(items)
        best["finding"] = " | ".join(findings[:3]) if findings else best.get("finding", "")
        best["severity"] = _strongest_severity(items)
        best["recommendation"] = _recommendation_for(best.get("vulnerability_type", "unknown"))
        deduped.append(best)

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    deduped.sort(
        key=lambda x: (
            severity_order.get(x.get("severity", "medium"), 2),
            -float(x.get("confidence", 0) or 0),
            x.get("endpoint", ""),
        )
    )
    return deduped


def _normalize_endpoint_for_dedup(endpoint: str) -> str:
    endpoint = (endpoint or "").strip()
    if not endpoint:
        return ""
    endpoint = re.sub(r"/+", "/", endpoint)
    if not endpoint.startswith("/"):
        endpoint = "/" + endpoint
    return endpoint.rstrip("/") if endpoint != "/" else endpoint


def _has_enough_finding_support(item: dict) -> bool:
    vuln_type = item.get("vulnerability_type", "unknown")
    finding = str(item.get("finding", "") or "")
    evidence = str(item.get("evidence", "") or "")
    combined = f"{finding}\n{evidence}".lower()

    # Generic LLM guesses like "accepts special chars" should not become
    # confirmed injection findings without server-side error/output evidence.
    if vuln_type in {"injection", "sql_injection", "command_injection", "nosql_injection"}:
        concrete = re.search(
            r"sql syntax|sqlite|mysql|postgres|ora-\d{5}|stack trace|traceback|"
            r"command output|uid=\d+|root:.*:0:0|syntax error at or near",
            combined,
        )
        return bool(concrete)
    return True


def _finding_bucket(item: dict) -> str:
    endpoint = item.get("endpoint", "")
    vuln_type = item.get("vulnerability_type", "unknown")
    finding = str(item.get("finding", "") or "").lower()

    if endpoint == "/debug" or (vuln_type == "debug_exposure" and re.search(r"debug|env|config|secret|db_password", finding)):
        return "debug_exposure:/debug"
    if endpoint == "/mail/v1":
        return "info_leak:/mail/v1"
    if endpoint == "/users/v1/login" and vuln_type == "weak_credentials":
        return "weak_credentials:/users/v1/login"
    if endpoint == "/users/v1/reset-password" or vuln_type == "logic_bypass":
        return "logic_bypass:/users/v1/reset-password"
    if endpoint == "/users/v1/login" and vuln_type == "mass_assignment":
        return "info_leak:/sensitive_api_data"
    if endpoint.startswith("/users/v1") and vuln_type == "mass_assignment":
        return "mass_assignment:/users/v1"
    if (endpoint.startswith("/users/v1/") or endpoint.startswith("/books/v1")) and vuln_type in {"idor", "auth_bypass"}:
        return "idor:/object_access"
    if endpoint.startswith("/users/v1") and vuln_type in {"info_leak", "debug_exposure"}:
        return "info_leak:/sensitive_api_data"
    if endpoint.startswith("/books/v1") and vuln_type in {"info_leak", "debug_exposure"}:
        return "info_leak:/sensitive_api_data"
    return f"{vuln_type}:{endpoint or 'global'}"


def _canonical_type_for_bucket(bucket: str, fallback: str) -> str:
    return bucket.split(":", 1)[0] if ":" in bucket else fallback


def _canonical_endpoint_for_bucket(bucket: str, affected_endpoints: list[str]) -> str:
    if ":" in bucket:
        return bucket.split(":", 1)[1]
    return affected_endpoints[0] if affected_endpoints else ""


def _dedup_rank(item: dict) -> tuple[float, int]:
    severity_weight = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    confidence = float(item.get("confidence", 0) or 0)
    return confidence, severity_weight.get(item.get("severity", "medium"), 2)


def _strongest_severity(items: list[dict]) -> str:
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    strongest = max(items, key=lambda item: order.get(item.get("severity", "medium"), 2))
    return strongest.get("severity", "medium")


def _normalize_vuln_type_for_dedup(vuln_type: str) -> str:
    """Normalize vulnerability type for better deduplication."""
    type_aliases = {
        "bola": "idor",
        "broken_object_level_authorization": "idor",
        "broken_authentication": "auth_bypass",
        "authentication_bypass": "auth_bypass",
        "sensitive_data_exposure": "info_leak",
        "information_disclosure": "info_leak",
    }
    return type_aliases.get(vuln_type.lower(), vuln_type.lower())


def _why(result: dict, signals: list[str]) -> str:
    payload = result.get("payload", {}) or {}
    method = payload.get("method", "?")
    path = payload.get("path", "?")
    status = result.get("status_code", 0)
    if signals:
        return f"{method} {path} returned HTTP {status}; " + "; ".join(signals)
    return f"{method} {path} returned HTTP {status} without matching local evidence patterns."


def _defense_level(vulns: list[dict], total_results: int) -> str:
    if not vulns:
        return "strong" if total_results else "unknown"
    high_count = sum(1 for v in vulns if v.get("severity") in {"critical", "high"})
    if high_count >= 3:
        return "none"
    if high_count >= 1:
        return "weak"
    return "moderate"


def _overall_rating(vulns: list[dict]) -> str:
    if any(v.get("severity") in {"critical", "high"} for v in vulns):
        return "high"
    if vulns:
        return "medium"
    return "low"


def _max_rating(a: str | None, b: str | None) -> str:
    order = {"unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    a = a or "unknown"
    b = b or "unknown"
    return a if order.get(a, 0) >= order.get(b, 0) else b


def _severity_for(vuln_type: str, confidence: float) -> str:
    if vuln_type in {"sql_injection", "command_injection", "auth_bypass", "weak_credentials"}:
        return "critical" if confidence >= 0.8 else "high"
    if vuln_type in {"idor", "bola", "mass_assignment", "info_leak", "debug_exposure"}:
        return "high" if confidence >= 0.7 else "medium"
    return "medium" if confidence >= 0.6 else "low"


def _recommendation_for(vuln_type: str) -> str:
    recommendations = {
        "auth_bypass": "Enforce authentication on the server for every protected endpoint and reject missing or malformed tokens.",
        "idor": "Check object ownership and authorization for every resource identifier before returning or modifying data.",
        "bola": "Check object ownership and authorization for every resource identifier before returning or modifying data.",
        "mass_assignment": "Use explicit allow-lists for writable fields and ignore server-controlled fields from client input.",
        "info_leak": "Remove sensitive fields from API responses and apply least-privilege serialization.",
        "debug_exposure": "Disable debug, environment, metrics, and management endpoints in exposed environments.",
        "sql_injection": "Use parameterized queries and avoid concatenating user input into database statements.",
        "weak_credentials": "Remove default credentials, enforce strong passwords, and add rate limiting to login endpoints.",
    }
    return recommendations.get(vuln_type, "Validate authorization, input handling, and response filtering for this endpoint.")


def _remediation_advice(vulns: list[dict]) -> str:
    if not vulns:
        return "No local evidence-backed vulnerabilities were found. Keep authorization, validation, and response filtering controls in place."
    grouped = defaultdict(int)
    for vuln in vulns:
        grouped[vuln.get("vulnerability_type", "unknown")] += 1
    parts = []
    for vuln_type in sorted(grouped):
        parts.append(f"{vuln_type}: {_recommendation_for(vuln_type)}")
    return " ".join(parts)


def _as_list(value: Any) -> list:
    if isinstance(value, list):
        return value
    if value in (None, ""):
        return []
    return [value]


def _shorten(text: str, limit: int) -> str:
    text = text.strip()
    if len(text) <= limit:
        return text
    return text[:limit] + "..."


def verify_vulnerabilities(
    vulns: list[dict],
    execution_results: list[dict],
    followup_results: list[dict] | None = None,
) -> tuple[list[dict], list[dict]]:
    """Verify vulnerabilities through secondary validation.

    v3.6 鏂板鐨勪簩娆￠獙璇佹満鍒讹細
    1. 妫€鏌ユ槸鍚︽湁瓒冲鐨勮瘉鎹敮鎸?    2. 妫€鏌ユ槸鍚﹀瓨鍦ㄧ煕鐩剧殑璇佹嵁
    3. 妫€鏌ユ紡娲炴槸鍚﹀湪涓嶅悓娴嬭瘯涓閲嶅纭
    4. 杩囨护鎺変綆缃俊搴︽垨璇佹嵁涓嶈冻鐨勬紡娲?
    Returns:
        (verified_vulns, verification_results)
        - verified_vulns: 楠岃瘉閫氳繃鐨勬紡娲炲垪琛?        - verification_results: 姣忎釜婕忔礊鐨勯獙璇佽鎯?    """
    if not vulns:
        return [], []

    all_results = list(execution_results or [])
    if followup_results:
        all_results.extend(followup_results)

    verified = []
    verification_details = []

    for vuln in vulns:
        endpoint = vuln.get("endpoint", "")
        vuln_type = vuln.get("vulnerability_type", "unknown")
        confidence = float(vuln.get("confidence", 0) or 0)

        # 楠岃瘉鏍囧噯
        verification = {
            "endpoint": endpoint,
            "vulnerability_type": vuln_type,
            "original_confidence": confidence,
            "passed": False,
            "reason": "",
        }

        if confidence < CONFIDENCE_THRESHOLD_CONFIRMED:
            verification["reason"] = f"Confidence {confidence:.2f} below threshold {CONFIDENCE_THRESHOLD_CONFIRMED}"
            verification_details.append(verification)
            continue

        has_contradiction = _check_contradicting_evidence(vuln, all_results)
        if has_contradiction:
            verification["reason"] = "Contradicting evidence found in other test results"
            verification_details.append(verification)
            continue

        confirmation_count = _count_confirmations(endpoint, vuln_type, all_results)
        if confirmation_count > 1:
            # 澶氭纭锛屽鍔犲彲淇″害
            vuln["evidence_count"] = confirmation_count
            verification["bonus"] = "Multiple confirmations"

        evidence_quality = _assess_evidence_quality(vuln, all_results)
        if evidence_quality < 0.5:
            verification["reason"] = f"Evidence quality too low: {evidence_quality:.2f}"
            verification_details.append(verification)
            continue

        # 楠岃瘉閫氳繃
        verification["passed"] = True
        verification["reason"] = "Verification passed"
        verification["evidence_quality"] = evidence_quality
        verification_details.append(verification)
        verified.append(vuln)

    max_vulns = 10
    if len(verified) > max_vulns:
        verified.sort(key=lambda x: float(x.get("confidence", 0) or 0), reverse=True)
        verified = verified[:max_vulns]

    return verified, verification_details


def _check_contradicting_evidence(vuln: dict, all_results: list[dict]) -> bool:
    """Check if there's contradicting evidence for this vulnerability."""
    endpoint = vuln.get("endpoint", "")
    vuln_type = vuln.get("vulnerability_type", "")

    for result in all_results:
        result_endpoint = result.get("payload", {}).get("path", "")
        if result_endpoint != endpoint:
            continue

        # 濡傛灉鏈夋槑纭殑鎷掔粷鏍囪锛屽彲鑳芥槸鐭涚浘璇佹嵁
        response_text = (result.get("response_text", "") or "").lower()
        if any(marker in response_text for marker in [
            "unauthorized", "forbidden", "not authorized",
            "permission denied", "authentication required",
        ]):
            return True

    return False


def _count_confirmations(endpoint: str, vuln_type: str, all_results: list[dict]) -> int:
    """Count how many times this vulnerability type was confirmed for this endpoint."""
    count = 0
    for result in all_results:
        result_endpoint = result.get("payload", {}).get("path", "")
        result_type = result.get("vulnerability_type", "")
        status = result.get("status_code", 0)

        if result_endpoint == endpoint and result_type == vuln_type:
            if 200 <= status < 300:
                count += 1

    return count


def _assess_evidence_quality(vuln: dict, all_results: list[dict]) -> float:
    """Assess the quality of evidence for a vulnerability.

    Returns a score from 0 to 1.
    """
    endpoint = vuln.get("endpoint", "")
    vuln_type = vuln.get("vulnerability_type", "")
    confidence = float(vuln.get("confidence", 0) or 0)

    # 鍩虹鍒嗘暟
    score = confidence

    for result in all_results:
        result_endpoint = result.get("payload", {}).get("path", "")
        result_type = result.get("vulnerability_type", "")

        if result_endpoint == endpoint and result_type == vuln_type:
            response_text = result.get("response_text", "")
            status = result.get("status_code", 0)

            # 妫€鏌ュ搷搴旀槸鍚﹀寘鍚疄闄呮暟鎹紙涓嶅彧鏄垚鍔熸秷鎭級
            if _contains_actual_data(response_text):
                score = min(1.0, score + 0.1)

            # 妫€鏌ユ槸鍚︽湁鏄庣‘鐨勯敊璇俊鎭紙鍙兘琛ㄦ槑涓嶆槸鐪熸鐨勬紡娲烇級
            if "error" in response_text.lower() or "invalid" in response_text.lower():
                if "not found" in response_text.lower() or "does not exist" in response_text.lower():
                    score = max(0, score - 0.2)

    return score
