"""
Deterministic OpenAPI attack planner.

This module gives the scanner a stable baseline that does not depend on LLM
output. The generated plans are intentionally conservative and aimed at
authorized API security testing targets.
"""

from __future__ import annotations

import copy
import json
import logging
import re
from typing import Any

logger = logging.getLogger("smart_attack.heuristic_engine")

HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
WRITE_METHODS = {"POST", "PUT", "PATCH"}

# 限制配置
MAX_ENDPOINTS_TO_TEST = 10  # 最多测试的端点数量
MAX_DEBUG_PATHS = 5  # 最多测试的调试路径
MAX_HIDDEN_PATHS = 3  # 最多测试的隐藏路径
MAX_PLANS_PER_TYPE = 3  # 每种漏洞类型每个端点最多方案数
MAX_TOTAL_PLANS = 25  # 启发式引擎总计最多方案数

COMMON_DEBUG_PATHS = [
    "/debug",
    "/actuator",
    "/actuator/env",
    "/.env",
    "/.git/config",
]

WEAK_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "admin123"),
    ("admin", "password"),
]

PRIVILEGE_FIELDS = {
    "role": "admin",
    "admin": True,
    "is_admin": True,
    "verified": True,
}


def run_heuristic_engine(swagger_text: str) -> dict:
    """Generate deterministic attack plans from an OpenAPI/Swagger document."""
    spec = _load_spec(swagger_text)
    if not spec:
        return {
            "attack_plans": [],
            "endpoints_analyzed": 0,
            "total_plans": 0,
            "summary": {},
        }

    endpoints = _parse_endpoints(spec)

    # 限制端点数量：优先选择高风险端点
    if len(endpoints) > MAX_ENDPOINTS_TO_TEST:
        endpoints = _prioritize_endpoints(endpoints)[:MAX_ENDPOINTS_TO_TEST]

    plans: list[dict] = []

    for endpoint in endpoints:
        # 为每个端点生成核心测试（精简版）
        plans.extend(_auth_plans(endpoint)[:1])  # 最多1个认证测试
        plans.extend(_idor_plans(endpoint)[:2])  # 最多2个IDOR测试
        plans.extend(_mass_assignment_plans(endpoint)[:1])  # 最多1个Mass Assignment测试

    # 全局探测（限制数量）
    plans.extend(_debug_endpoint_plans(endpoints)[:MAX_DEBUG_PATHS])
    plans.extend(_hidden_business_logic_plans(endpoints)[:MAX_HIDDEN_PATHS])

    # 弱口令测试只对登录端点
    login_endpoints = [ep for ep in endpoints if _is_login_endpoint(ep)]
    for ep in login_endpoints[:2]:  # 最多测试2个登录端点
        plans.extend(_weak_login_plans(ep)[:MAX_PLANS_PER_TYPE])

    deduped = _dedupe_plans(plans)

    # 限制总数
    if len(deduped) > MAX_TOTAL_PLANS:
        # 按漏洞类型优先级排序
        priority_order = {
            "auth_bypass": 0,
            "weak_credentials": 1,
            "idor": 2,
            "bola": 3,
            "mass_assignment": 4,
            "debug_exposure": 5,
            "logic_bypass": 6,
            "info_leak": 7,
            "baseline_probe": 8,
        }
        deduped.sort(key=lambda p: priority_order.get(p.get("vulnerability_type", ""), 9))
        deduped = deduped[:MAX_TOTAL_PLANS]

    summary: dict[str, int] = {}
    for plan in deduped:
        summary[plan.get("vulnerability_type", "unknown")] = (
            summary.get(plan.get("vulnerability_type", "unknown"), 0) + 1
        )

    logger.info(
        "Heuristic engine analyzed %d endpoints and generated %d plans (limited from %d)",
        len(endpoints),
        len(deduped),
        len(plans),
    )
    return {
        "attack_plans": deduped,
        "endpoints_analyzed": len(endpoints),
        "total_plans": len(deduped),
        "summary": summary,
    }


def _is_login_endpoint(endpoint: dict) -> bool:
    """Check if an endpoint is a login endpoint."""
    path = endpoint["path"].lower()
    operation_text = " ".join([
        endpoint.get("summary", ""),
        endpoint.get("description", ""),
        endpoint.get("operation_id", ""),
    ]).lower()
    return "login" in path or "auth" in path or "login" in operation_text


def _prioritize_endpoints(endpoints: list[dict]) -> list[dict]:
    """Prioritize endpoints for testing based on risk."""
    high_priority = []
    normal_priority = []

    for ep in endpoints:
        path = ep["path"].lower()
        method = ep["method"]

        # 高优先级：写操作、包含敏感关键词、有路径参数
        has_path_params = any(p.get("location") == "path" for p in ep.get("params", []))
        is_sensitive = any(kw in path for kw in [
            "admin", "user", "auth", "login", "order", "payment",
            "debug", "config", "account", "profile"
        ])
        is_write = method in WRITE_METHODS

        if has_path_params or is_sensitive or is_write:
            high_priority.append(ep)
        else:
            normal_priority.append(ep)

    return high_priority + normal_priority


def _load_spec(swagger_text: str) -> dict:
    try:
        return json.loads(swagger_text)
    except (TypeError, json.JSONDecodeError) as exc:
        logger.warning("Heuristic engine could not parse OpenAPI JSON: %s", exc)
        return {}


def _parse_endpoints(spec: dict) -> list[dict]:
    endpoints: list[dict] = []
    paths = spec.get("paths", {})
    if not isinstance(paths, dict):
        return endpoints

    global_security = spec.get("security", [])
    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        common_params = path_item.get("parameters", [])
        for method, detail in path_item.items():
            method_upper = method.upper()
            if method_upper not in HTTP_METHODS or not isinstance(detail, dict):
                continue

            params = []
            params.extend(_extract_parameters(common_params, spec))
            params.extend(_extract_parameters(detail.get("parameters", []), spec))
            body_schema = _extract_request_body_schema(detail, spec)
            body_fields = _schema_properties(body_schema, spec)

            endpoints.append({
                "method": method_upper,
                "path": path,
                "summary": detail.get("summary", ""),
                "description": detail.get("description", ""),
                "operation_id": detail.get("operationId", ""),
                "tags": detail.get("tags", []),
                "secured": bool(detail.get("security", global_security)),
                "params": params,
                "body_schema": body_schema,
                "body_fields": body_fields,
            })
    return endpoints


def _extract_parameters(parameters: Any, spec: dict) -> list[dict]:
    extracted = []
    if not isinstance(parameters, list):
        return extracted
    for raw in parameters:
        param = _resolve_ref(raw, spec)
        if not isinstance(param, dict):
            continue
        schema = _resolve_ref(param.get("schema", {}), spec)
        extracted.append({
            "name": param.get("name", ""),
            "location": param.get("in", "query"),
            "required": param.get("required", False),
            "type": schema.get("type", param.get("type", "string")),
            "example": _first_present(
                param.get("example"),
                schema.get("example"),
                schema.get("default"),
                _enum_example(schema),
            ),
        })
    return extracted


def _extract_request_body_schema(detail: dict, spec: dict) -> dict:
    if "requestBody" in detail:
        request_body = _resolve_ref(detail.get("requestBody", {}), spec)
        content = request_body.get("content", {}) if isinstance(request_body, dict) else {}
        for content_type in (
            "application/json",
            "application/x-www-form-urlencoded",
            "multipart/form-data",
            "*/*",
        ):
            media = content.get(content_type)
            if isinstance(media, dict) and media.get("schema"):
                schema = _resolve_ref(media["schema"], spec)
                schema = copy.deepcopy(schema)
                schema["_content_type"] = content_type
                return schema
        for media in content.values():
            if isinstance(media, dict) and media.get("schema"):
                schema = _resolve_ref(media["schema"], spec)
                schema = copy.deepcopy(schema)
                schema["_content_type"] = "application/json"
                return schema

    swagger2_body = [
        p for p in detail.get("parameters", [])
        if isinstance(p, dict) and p.get("in") in {"body", "formData"}
    ]
    if swagger2_body:
        param = swagger2_body[0]
        schema = _resolve_ref(param.get("schema", param), spec)
        schema = copy.deepcopy(schema)
        schema["_content_type"] = (
            "application/x-www-form-urlencoded"
            if param.get("in") == "formData"
            else "application/json"
        )
        return schema
    return {}


def _schema_properties(schema: Any, spec: dict) -> dict:
    schema = _resolve_ref(schema, spec)
    if not isinstance(schema, dict):
        return {}

    merged: dict[str, Any] = {}
    for key in ("allOf", "anyOf", "oneOf"):
        if isinstance(schema.get(key), list):
            for item in schema[key]:
                merged.update(_schema_properties(item, spec))

    props = schema.get("properties", {})
    if isinstance(props, dict):
        for name, prop_schema in props.items():
            merged[name] = _resolve_ref(prop_schema, spec)

    if not merged and schema.get("type") == "array":
        merged.update(_schema_properties(schema.get("items", {}), spec))

    return merged


def _resolve_ref(value: Any, spec: dict) -> Any:
    if not isinstance(value, dict) or "$ref" not in value:
        return value
    ref = value.get("$ref", "")
    if not ref.startswith("#/"):
        return value
    cur: Any = spec
    for part in ref[2:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if not isinstance(cur, dict) or part not in cur:
            return value
        cur = cur[part]
    resolved = copy.deepcopy(cur)
    for key, val in value.items():
        if key != "$ref":
            resolved[key] = val
    return resolved


def _baseline_probe_plans(endpoint: dict) -> list[dict]:
    if endpoint["method"] not in {"GET", "OPTIONS"}:
        return []
    return [_make_plan(
        "baseline_probe",
        endpoint,
        "Baseline request used to learn real response shape and status behavior.",
        "The endpoint should expose only documented non-sensitive fields.",
        "Response includes sensitive or undocumented fields, or returns data without expected authorization.",
        _request_for(endpoint),
    )]


def _auth_plans(endpoint: dict) -> list[dict]:
    if not endpoint.get("secured"):
        return []
    plans = []
    for label, header_value in (
        ("missing token", ""),
        ("malformed token", "Bearer invalid.invalid.invalid"),
    ):
        req = _request_for(endpoint)
        req.setdefault("headers", {})["Authorization"] = header_value
        plans.append(_make_plan(
            "auth_bypass",
            endpoint,
            f"Call a documented protected endpoint with {label}.",
            "The API should return 401 or 403 and no business data.",
            "A 2xx response with business data indicates missing or weak authorization enforcement.",
            req,
        ))
    return plans


def _info_leak_plans(endpoint: dict) -> list[dict]:
    if endpoint["method"] != "GET":
        return []
    risk_words = "user|account|profile|admin|debug|config|secret|token|book|order"
    if endpoint.get("secured") and not re.search(risk_words, endpoint["path"], re.I):
        return []
    return [_make_plan(
        "info_leak",
        endpoint,
        "Fetch the endpoint and inspect the real response for sensitive or undocumented fields.",
        "The response should not include passwords, secrets, tokens, internal config, or privileged fields.",
        "Response contains sensitive fields such as password, token, secret, role, internal config, or debug data.",
        _request_for(endpoint),
    )]


def _mass_assignment_plans(endpoint: dict) -> list[dict]:
    if endpoint["method"] not in WRITE_METHODS:
        return []
    body = _example_body(endpoint)
    if not body:
        body = {"name": "smartattack-test"}
    injected = dict(body)
    injected.update(PRIVILEGE_FIELDS)
    req = _request_for(endpoint)
    req["headers"]["Content-Type"] = endpoint.get("body_schema", {}).get(
        "_content_type",
        "application/json",
    )
    req["body"] = injected
    return [_make_plan(
        "mass_assignment",
        endpoint,
        "Submit normal body fields plus undocumented privilege and finance fields.",
        "The server should ignore or reject client-controlled privilege fields.",
        "The response persists or reflects injected fields such as role=admin, admin=true, credit, or balance.",
        req,
    )]


def _idor_plans(endpoint: dict) -> list[dict]:
    path_params = [p for p in endpoint.get("params", []) if p.get("location") == "path"]
    if not path_params:
        return []
    plans = []
    for candidate in _candidate_ids(endpoint):
        req = _request_for(endpoint, path_override=_fill_path(endpoint["path"], candidate))
        plans.append(_make_plan(
            "idor",
            endpoint,
            f"Replace path identifier with candidate value {candidate!r} to test object-level authorization.",
            "The API should only return resources the caller is allowed to access.",
            "A 2xx response containing another user's resource or sensitive object data indicates IDOR/BOLA.",
            req,
        ))
    return plans[:4]


def _weak_login_plans(endpoint: dict) -> list[dict]:
    path = endpoint["path"].lower()
    operation_text = " ".join([
        endpoint.get("summary", ""),
        endpoint.get("description", ""),
        endpoint.get("operation_id", ""),
    ]).lower()
    if "login" not in path and "auth" not in path and "login" not in operation_text:
        return []

    plans = []
    for username, password in WEAK_CREDENTIALS:
        body = _example_body(endpoint)
        body.update({"username": username, "email": username, "password": password})
        req = _request_for(endpoint)
        req["headers"]["Content-Type"] = "application/json"
        req["body"] = body
        plans.append(_make_plan(
            "weak_credentials",
            endpoint,
            f"Try a common credential pair for login: {username}/{password}.",
            "The API should reject weak or default credentials.",
            "A successful login response or returned token indicates default or weak credentials.",
            req,
        ))
    return plans


def _debug_endpoint_plans(endpoints: list[dict]) -> list[dict]:
    """Probe common debug or management endpoints (limited)."""
    if not endpoints:
        return []
    first = endpoints[0]
    plans = []
    # 只测试最关键的调试路径
    for path in COMMON_DEBUG_PATHS[:MAX_DEBUG_PATHS]:
        ep = dict(first)
        ep["method"] = "GET"
        ep["path"] = path
        req = _request_for(ep, path_override=path)
        plans.append(_make_plan(
            "debug_exposure",
            ep,
            f"Probe common debug or management endpoint {path}.",
            "Debug, management, and environment endpoints should not be publicly exposed.",
            "A 2xx response with debug, env, config, actuator, metrics, or secret data indicates exposure.",
            req,
        ))
    return plans


def _hidden_business_logic_plans(endpoints: list[dict]) -> list[dict]:
    """Probe common undocumented API paths (limited)."""
    if not endpoints:
        return []

    first = dict(endpoints[0])
    # 精简探测列表，只保留最关键的
    probes = [
        {
            "method": "POST",
            "path": "/users/v1/reset-password",
            "vulnerability_type": "logic_bypass",
            "body": {"username": "admin", "new_password": "SmartAttack123!"},
            "reason": "Probe undocumented password reset endpoint without old password or token.",
            "indicator": "A 2xx response saying the password was reset indicates business logic bypass.",
        },
        {
            "method": "GET",
            "path": "/mail/v1",
            "vulnerability_type": "info_leak",
            "body": None,
            "reason": "Probe undocumented mail endpoint for message and internal IP exposure.",
            "indicator": "A 2xx response containing emails, subjects, message bodies, or internal IPs indicates information exposure.",
        },
        {
            "method": "PUT",
            "path": "/users/v1/admin",
            "vulnerability_type": "mass_assignment",
            "body": {"email": "admin-updated@example.com", "role": "admin"},
            "reason": "Probe whether user fields can be modified without authentication and with privileged fields.",
            "indicator": "A 2xx response reflecting role or modified email indicates unauthorized field update.",
        },
    ][:MAX_HIDDEN_PATHS]  # 限制数量

    plans = []
    for probe in probes:
        ep = dict(first)
        ep["method"] = probe["method"]
        ep["path"] = probe["path"]
        req = _request_for(ep, path_override=probe["path"])
        if probe["body"] is not None:
            req["headers"]["Content-Type"] = "application/json"
            req["body"] = probe["body"]
        plans.append(_make_plan(
            probe["vulnerability_type"],
            ep,
            probe["reason"],
            "Undocumented or sensitive business endpoints should require authorization and proper workflow validation.",
            probe["indicator"],
            req,
        ))
    return plans


def _request_for(endpoint: dict, path_override: str | None = None) -> dict:
    path = path_override or _fill_path(endpoint["path"], None)
    query_params = {}
    headers = {}

    for param in endpoint.get("params", []):
        loc = param.get("location")
        if loc == "query":
            query_params[param["name"]] = _example_for_param(param)
        elif loc == "header" and param.get("required"):
            headers[param["name"]] = _example_for_param(param)

    body = _example_body(endpoint) if endpoint["method"] in WRITE_METHODS else None
    if body:
        headers.setdefault(
            "Content-Type",
            endpoint.get("body_schema", {}).get("_content_type", "application/json"),
        )

    return {
        "method": endpoint["method"],
        "url_path": path,
        "headers": headers,
        "query_params": query_params or None,
        "body": body,
    }


def _example_body(endpoint: dict) -> dict:
    body = {}
    for name, schema in endpoint.get("body_fields", {}).items():
        body[name] = _example_for_schema(name, schema)
    return body


def _example_for_param(param: dict) -> Any:
    if param.get("example") not in (None, ""):
        return param["example"]
    return _example_for_schema(param.get("name", "value"), param)


def _example_for_schema(name: str, schema: dict) -> Any:
    if not isinstance(schema, dict):
        schema = {}
    for key in ("example", "default"):
        if schema.get(key) not in (None, ""):
            return schema[key]
    enum_val = _enum_example(schema)
    if enum_val not in (None, ""):
        return enum_val

    lowered = name.lower()
    typ = schema.get("type", "string")
    if "email" in lowered:
        return "smartattack@example.com"
    if "password" in lowered:
        return "Password123!"
    if "username" in lowered or lowered in {"user", "owner"}:
        return "admin"
    if "title" in lowered or "name" in lowered:
        return "smartattack-test"
    if "price" in lowered or "amount" in lowered or "balance" in lowered:
        return 1
    if typ in {"integer", "number"}:
        return 1
    if typ == "boolean":
        return True
    if typ == "array":
        return []
    if typ == "object":
        return {}
    return "smartattack-test"


def _candidate_ids(endpoint: dict) -> list[str]:
    path = endpoint["path"].lower()
    if "book" in path:
        return ["1", "2", "999"]
    if "user" in path or "account" in path or "profile" in path:
        return ["admin", "test", "user1", "1"]
    return ["1", "2", "admin", "test"]


def _fill_path(path: str, candidate: str | None) -> str:
    def repl(match: re.Match) -> str:
        name = match.group(1).lower()
        if candidate is not None:
            return str(candidate)
        if "book" in name:
            return "1"
        if "user" in name or "name" in name or "account" in name:
            return "admin"
        if "id" in name:
            return "1"
        return "smartattack-test"

    return re.sub(r"\{([^}]+)\}", repl, path)


def _make_plan(
    vuln_type: str,
    endpoint: dict,
    reason: str,
    expected: str,
    indicator: str,
    request: dict,
) -> dict:
    return {
        "reason": f"[heuristic:{vuln_type}] {reason}",
        "vulnerability_type": vuln_type,
        "expected_normal_behavior": expected,
        "exploit_indicator": indicator,
        "source": "heuristic_engine",
        "request": request,
    }


def _dedupe_plans(plans: list[dict]) -> list[dict]:
    seen = set()
    deduped = []
    for plan in plans:
        req = plan.get("request", {})
        key = (
            req.get("method", "GET"),
            req.get("url_path", ""),
            json.dumps(req.get("query_params"), sort_keys=True, ensure_ascii=False),
            json.dumps(req.get("body"), sort_keys=True, ensure_ascii=False),
            plan.get("vulnerability_type", ""),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(plan)
    return deduped


def _enum_example(schema: dict) -> Any:
    enum = schema.get("enum") if isinstance(schema, dict) else None
    if isinstance(enum, list) and enum:
        return enum[0]
    return None


def _first_present(*values: Any) -> Any:
    for value in values:
        if value not in (None, ""):
            return value
    return ""
