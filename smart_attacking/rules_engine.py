"""
智攻 (SmartAttack) v3.5 — YAML 规则引擎
======================================
基于 YAML 模板的快速漏洞检测引擎，零 token 消耗。
与 AI 引擎并行工作：
  - 规则引擎：快速、稳定，覆盖已知漏洞模式（SQLi/XSS/Path Traversal/SSRF 等）
  - AI 引擎：处理业务逻辑漏洞（BOLA/IDOR/Mass Assignment 等）

架构：
  Swagger 文档 → 规则引擎（YAML 模板）→ 规则攻击方案
             → AI 引擎（LLM 驱动）   → AI 攻击方案
             → 合并去重 → 执行攻击
"""

import json
import logging
import os
import re
from typing import Any

import yaml

logger = logging.getLogger("smart_attack.rules_engine")

# ---------------------------------------------------------------------------
# 规则目录
# ---------------------------------------------------------------------------
_RULES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules")


def _load_yaml_rules() -> list[dict]:
    """加载 rules/ 目录下所有 .yaml 规则文件。"""
    rules = []
    if not os.path.isdir(_RULES_DIR):
        logger.warning("规则目录不存在: %s", _RULES_DIR)
        return rules

    for fname in sorted(os.listdir(_RULES_DIR)):
        if not fname.endswith((".yaml", ".yml")):
            continue
        fpath = os.path.join(_RULES_DIR, fname)
        try:
            with open(fpath, "r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
                if data and data.get("enabled", True):
                    rules.append(data)
                    pcount = len(data.get("payloads", []))
                    logger.info("已加载规则: %s (%s) — %d 组 payload", data.get("name"), fname, pcount)
        except Exception as e:
            logger.warning("规则加载失败 %s: %s", fname, e)
    return rules


# ---------------------------------------------------------------------------
# Swagger 解析
# ---------------------------------------------------------------------------


def _parse_swagger_endpoints(swagger_text: str) -> list[dict]:
    """从 Swagger/OpenAPI 文档中提取所有端点及其参数。

    Returns:
        [ { method, path, params: [{name, location, type, example}] }, ... ]
    """
    try:
        spec = json.loads(swagger_text)
    except (json.JSONDecodeError, TypeError):
        logger.warning("Swagger JSON 解析失败，规则引擎跳过")
        return []

    endpoints = []

    # OpenAPI 3.x
    if "paths" in spec:
        base_url = ""
        if "servers" in spec and spec["servers"]:
            base_url = spec["servers"][0].get("url", "")

        for path, methods in spec["paths"].items():
            if not isinstance(methods, dict):
                continue
            for method, detail in methods.items():
                if method.upper() not in ("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"):
                    continue
                if not isinstance(detail, dict):
                    continue

                # 提取参数
                params = _extract_params(detail, spec)
                endpoints.append({
                    "method": method.upper(),
                    "path": path,
                    "base_url": base_url,
                    "params": params,
                    "summary": detail.get("summary", ""),
                    "description": detail.get("description", ""),
                    "tags": detail.get("tags", []),
                    "request_body": detail.get("requestBody", {}),
                })

    # Swagger 2.0
    elif "swagger" in spec:
        base_url = spec.get("host", "")
        base_path = spec.get("basePath", "")
        if base_url and base_path:
            base_url = f"{base_url}{base_path}"

        for path, methods in spec.get("paths", {}).items():
            if not isinstance(methods, dict):
                continue
            for method, detail in methods.items():
                if method.upper() not in ("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"):
                    continue
                if not isinstance(detail, dict):
                    continue

                params = _extract_params_swagger2(detail, spec)
                endpoints.append({
                    "method": method.upper(),
                    "path": path,
                    "base_url": base_url,
                    "params": params,
                    "summary": detail.get("summary", ""),
                    "description": detail.get("description", ""),
                    "tags": detail.get("tags", []),
                })

    logger.info("规则引擎解析 Swagger: 提取 %d 个端点", len(endpoints))
    return endpoints


def _extract_params(detail: dict, spec: dict) -> list[dict]:
    """OpenAPI 3.x 参数提取。"""
    params = []
    for p in detail.get("parameters", []):
        schema = p.get("schema", {})
        params.append({
            "name": p.get("name", ""),
            "location": p.get("in", "query"),
            "type": schema.get("type", "string"),
            "example": schema.get("example", ""),
            "required": p.get("required", False),
        })

    # 也提取 requestBody 中的 JSON body 属性
    req_body = detail.get("requestBody", {})
    content = req_body.get("content", {})
    json_content = content.get("application/json", {})
    json_schema = json_content.get("schema", {})
    for prop_name, prop_schema in json_schema.get("properties", {}).items():
        params.append({
            "name": prop_name,
            "location": "body",
            "type": prop_schema.get("type", "string"),
            "example": prop_schema.get("example", ""),
            "required": prop_name in json_schema.get("required", []),
        })

    return params


def _extract_params_swagger2(detail: dict, spec: dict) -> list[dict]:
    """Swagger 2.0 参数提取。"""
    params = []
    for p in detail.get("parameters", []):
        params.append({
            "name": p.get("name", ""),
            "location": p.get("in", "query"),
            "type": p.get("type", "string"),
            "example": p.get("example", ""),
            "required": p.get("required", False),
        })
    return params


# ---------------------------------------------------------------------------
# 规则匹配与攻击方案生成
# ---------------------------------------------------------------------------

# 每个规则最多保留的 payload 数量（避免过度测试）
MAX_PAYLOADS_PER_RULE = 5

# 每个端点每种漏洞类型最多保留的方案数量
MAX_PLANS_PER_ENDPOINT_VULN = 2

# 规则引擎总计最多生成的方案数量
MAX_TOTAL_PLANS = 30


def _match_rule_to_endpoint(rule: dict, endpoint: dict) -> list[dict]:
    """将一条规则匹配到一个端点，生成攻击方案列表。"""
    plans = []
    ep_filter = rule.get("endpoint_filter", {})

    # 方法检查
    allowed_methods = ep_filter.get("methods", [])
    if allowed_methods and endpoint["method"] not in allowed_methods:
        return plans

    # skip_patterns 检查
    skip_patterns = ep_filter.get("skip_patterns", [])
    if skip_patterns:
        for sp in skip_patterns:
            if re.search(sp, endpoint["path"]):
                return plans

    # param_name_patterns 检查（可选）
    param_name_patterns = ep_filter.get("param_name_patterns", [])
    allowed_param_types = ep_filter.get("param_types", ["query", "body", "path"])

    params = endpoint.get("params", [])

    # 限制参数数量：只测试最重要的几个参数
    if len(params) > 3:
        # 优先测试 required 参数
        required_params = [p for p in params if p.get("required")]
        optional_params = [p for p in params if not p.get("required")]
        params = required_params[:2] + optional_params[:1] if required_params else optional_params[:3]

    for param in params:
        # 参数位置过滤
        if param.get("location", "query") not in allowed_param_types:
            continue

        # 参数名模式过滤（如果配置了）
        if param_name_patterns:
            matched = False
            for pattern in param_name_patterns:
                if re.search(pattern, param.get("name", ""), re.IGNORECASE):
                    matched = True
                    break
            if not matched:
                continue

        # 为该参数生成每种 payload 的攻击方案（限制数量）
        payloads = rule.get("payloads", [])[:MAX_PAYLOADS_PER_RULE]
        for payload in payloads:
            plan = _build_plan(rule, endpoint, param, payload)
            if plan:
                plans.append(plan)

    # 如果端点没有参数但有 request body，且规则支持 body 注入
    if not params and "body" in allowed_param_types:
        req_body = endpoint.get("request_body", {})
        if req_body:
            payloads = rule.get("payloads", [])[:MAX_PAYLOADS_PER_RULE]
            for payload in payloads:
                plan = _build_plan(rule, endpoint, {"name": "body", "location": "body"}, payload)
                if plan:
                    plans.append(plan)

    return plans


def _build_plan(rule: dict, endpoint: dict, param: dict, payload: dict) -> dict | None:
    """构建单个攻击方案（与 AI 生成的 plan 格式兼容）。"""
    try:
        param_name = param.get("name", "")
        param_loc = param.get("location", "query")
        method = endpoint["method"]
        path = endpoint["path"]
        payload_value = payload.get("value", "")
        payload_desc = payload.get("description", "")

        # 构建请求
        url_path = path
        if "{" in path and "}" in path:
            # 路径参数替换
            url_path = re.sub(r"\{[^}]*\}", payload_value, path)

        req = {
            "method": method,
            "url_path": url_path,
            "headers": {},
        }

        # 根据参数位置放置 payload
        if param_loc == "query":
            req["query_params"] = {param_name: payload_value}
        elif param_loc == "body":
            content_type = payload.get("content_type", "application/json")
            req["headers"]["Content-Type"] = content_type
            if content_type == "application/json":
                # 尝试解析 JSON payload
                try:
                    req["body"] = json.loads(payload_value)
                except (json.JSONDecodeError, TypeError):
                    req["body"] = {param_name: payload_value}
            else:
                req["body"] = {param_name: payload_value}
        elif param_loc == "path":
            # 已通过路径替换处理
            pass
        elif param_loc == "header":
            req["headers"][param_name] = payload_value

        # 注入理由
        reasoning = rule.get("reasoning_template", "对 {param_name} 参数进行测试")
        reasoning = reasoning.replace("{param_name}", param_name)
        reasoning = reasoning.replace("{payload_value}", str(payload_value))
        reasoning = reasoning.replace("{description}", payload_desc)

        return {
            "reason": f"[规则引擎:{rule['name']}] {reasoning}",
            "vulnerability_type": rule["name"],
            "expected_normal_behavior": rule.get("expected_normal", ""),
            "exploit_indicator": rule.get("exploit_indicator", {}),
            "rule_confidence": rule.get("confidence", 0.5),
            "source": "rules_engine",  # 标记来源，便于区分
            "request": req,
        }
    except Exception as e:
        logger.debug("构建规则攻击方案失败: %s", e)
        return None


# ---------------------------------------------------------------------------
# 公开 API
# ---------------------------------------------------------------------------


def _resolve_ref(value: Any, spec: dict) -> Any:
    """Resolve local JSON references in OpenAPI/Swagger documents."""
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
    return cur


def _schema_properties(schema: Any, spec: dict) -> dict:
    """Extract object properties, including composed schema forms."""
    schema = _resolve_ref(schema, spec)
    if not isinstance(schema, dict):
        return {}
    props = {}
    for key in ("allOf", "anyOf", "oneOf"):
        if isinstance(schema.get(key), list):
            for item in schema[key]:
                props.update(_schema_properties(item, spec))
    own_props = schema.get("properties", {})
    if isinstance(own_props, dict):
        for name, prop_schema in own_props.items():
            props[name] = _resolve_ref(prop_schema, spec)
    if not props and schema.get("type") == "array":
        props.update(_schema_properties(schema.get("items", {}), spec))
    return props


def _extract_params(detail: dict, spec: dict) -> list[dict]:
    """OpenAPI 3.x parameter extraction with schema reference support."""
    params = []
    for raw_param in detail.get("parameters", []):
        p = _resolve_ref(raw_param, spec)
        if not isinstance(p, dict):
            continue
        schema = _resolve_ref(p.get("schema", {}), spec)
        params.append({
            "name": p.get("name", ""),
            "location": p.get("in", "query"),
            "type": schema.get("type", "string") if isinstance(schema, dict) else "string",
            "example": p.get("example", schema.get("example", schema.get("default", "")) if isinstance(schema, dict) else ""),
            "required": p.get("required", False),
        })
    req_body = _resolve_ref(detail.get("requestBody", {}), spec)
    content = req_body.get("content", {}) if isinstance(req_body, dict) else {}
    body_schema = {}
    for media_type in ("application/json", "application/x-www-form-urlencoded", "multipart/form-data"):
        media = content.get(media_type, {})
        if isinstance(media, dict) and media.get("schema"):
            body_schema = _resolve_ref(media.get("schema", {}), spec)
            break
    for prop_name, prop_schema in _schema_properties(body_schema, spec).items():
        params.append({
            "name": prop_name,
            "location": "body",
            "type": prop_schema.get("type", "string"),
            "example": prop_schema.get("example", prop_schema.get("default", "")),
            "required": prop_name in body_schema.get("required", []) if isinstance(body_schema, dict) else False,
        })
    return params


def _extract_params_swagger2(detail: dict, spec: dict) -> list[dict]:
    """Swagger 2.0 parameter extraction with body/formData support."""
    params = []
    for raw_param in detail.get("parameters", []):
        p = _resolve_ref(raw_param, spec)
        if not isinstance(p, dict):
            continue
        if p.get("in") == "body":
            schema = _resolve_ref(p.get("schema", {}), spec)
            for prop_name, prop_schema in _schema_properties(schema, spec).items():
                params.append({
                    "name": prop_name,
                    "location": "body",
                    "type": prop_schema.get("type", "string"),
                    "example": prop_schema.get("example", prop_schema.get("default", "")),
                    "required": prop_name in schema.get("required", []) if isinstance(schema, dict) else False,
                })
            continue
        params.append({
            "name": p.get("name", ""),
            "location": "body" if p.get("in") == "formData" else p.get("in", "query"),
            "type": p.get("type", "string"),
            "example": p.get("example", p.get("default", "")),
            "required": p.get("required", False),
        })
    return params


def run_rules_engine(swagger_text: str) -> dict:
    """执行规则引擎：加载 YAML 规则 → 解析 Swagger → 生成攻击方案。

    Returns:
        {
            "attack_plans": [...],    # 规则引擎生成的攻击方案
            "rules_summary": {...},   # 各规则命中统计
            "endpoints_analyzed": N,  # 分析的端点数
            "total_plans": N,         # 生成方案总数
        }
    """
    # 加载规则
    rules = _load_yaml_rules()
    if not rules:
        logger.warning("未加载到任何规则")
        return {"attack_plans": [], "rules_summary": {}, "endpoints_analyzed": 0, "total_plans": 0}

    # 解析 Swagger
    endpoints = _parse_swagger_endpoints(swagger_text)
    if not endpoints:
        logger.info("规则引擎: 未解析到端点，跳过")
        return {"attack_plans": [], "rules_summary": {}, "endpoints_analyzed": 0, "total_plans": 0}

    # 限制端点数量：优先测试高风险端点
    if len(endpoints) > 10:
        # 优先选择有写操作或包含敏感关键词的端点
        high_priority = []
        normal_priority = []
        for ep in endpoints:
            path = ep["path"].lower()
            method = ep["method"]
            # 高优先级：写操作、包含敏感关键词
            if method in {"POST", "PUT", "PATCH", "DELETE"} or any(
                kw in path for kw in ["admin", "user", "auth", "login", "order", "payment", "debug"]
            ):
                high_priority.append(ep)
            else:
                normal_priority.append(ep)
        endpoints = (high_priority + normal_priority)[:10]
        logger.info("规则引擎: 端点过多，选择前 %d 个高优先级端点", len(endpoints))

    # 应用规则
    all_plans = []
    rules_summary = {}

    for rule in rules:
        rule_plans = []
        for ep in endpoints:
            plans = _match_rule_to_endpoint(rule, ep)
            rule_plans.extend(plans)
            all_plans.extend(plans)

        if rule_plans:
            rules_summary[rule["name"]] = {
                "count": len(rule_plans),
                "severity": rule.get("severity", "medium"),
                "owasp": rule.get("owasp", ""),
            }
            logger.info("规则 [%s]: 生成 %d 组攻击方案", rule["name"], len(rule_plans))

    # 改进的去重逻辑：按 (method, path, vuln_type) 分组，每组只保留置信度最高的
    grouped_plans: dict[tuple, list[dict]] = {}
    for plan in all_plans:
        key = (
            plan["request"]["method"],
            plan["request"]["url_path"],
            plan["vulnerability_type"],
        )
        if key not in grouped_plans:
            grouped_plans[key] = []
        grouped_plans[key].append(plan)

    # 每组只保留一个最佳方案（优先选择置信度高的）
    deduped = []
    for key, plans_group in grouped_plans.items():
        # 按置信度排序，选择最高的
        best_plan = max(plans_group, key=lambda p: p.get("rule_confidence", 0.5))
        deduped.append(best_plan)

    # 限制总数
    if len(deduped) > MAX_TOTAL_PLANS:
        # 按严重性排序，保留最重要的
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        deduped.sort(key=lambda p: severity_order.get(p.get("severity", "medium"), 2))
        deduped = deduped[:MAX_TOTAL_PLANS]
        logger.info("规则引擎: 方案过多，截断至 %d 个", MAX_TOTAL_PLANS)

    logger.info("规则引擎总计: %d 个端点 × %d 条规则 → %d 组攻击方案（去重后 %d 组）",
                len(endpoints), len(rules), len(all_plans), len(deduped))

    return {
        "attack_plans": deduped,
        "rules_summary": rules_summary,
        "endpoints_analyzed": len(endpoints),
        "total_plans": len(deduped),
    }


def get_rules_info() -> list[dict]:
    """获取所有已加载规则的信息（供 API 查询）。"""
    rules = _load_yaml_rules()
    return [{
        "name": r.get("name", ""),
        "description": r.get("description", ""),
        "severity": r.get("severity", "medium"),
        "owasp": r.get("owasp", ""),
        "payload_count": len(r.get("payloads", [])),
        "confidence": r.get("confidence", 0),
    } for r in rules]
