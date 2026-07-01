"""
智攻 (SmartAttack) — 影子 API 检测引擎
=======================================
通过对比真实流量日志与 Swagger/OpenAPI 文档，发现未登记的"影子 API"。

支持的流量格式：
- HAR (HTTP Archive) 1.2 — 浏览器 DevTools 导出
- JSON 数组: [{"method": "GET", "path": "/api/users"}, ...]
- 纯文本 URL 列表: 每行一个 "/api/users"

核心算法：
1. 从 Swagger 文档提取所有已声明的 endpoint（method + path）
2. 从流量日志提取所有实际调用的 endpoint
3. 路径归一化（参数化）/api/users/123 → /api/users/{id}
4. 差集运算：影子 API = 流量 - 文档
"""

import json
import logging
import re
from typing import Optional
from urllib.parse import urlparse

logger = logging.getLogger("smart_attack.shadow_api")


# ======================================================================
# 路径归一化
# ======================================================================


def normalize_path(path: str) -> str:
    """将路径中的动态参数替换为占位符。

    Examples:
        /api/users/123        → /api/users/{id}
        /api/orders/abc-456   → /api/orders/{id}
        /api/v1/products/99   → /api/v1/products/{id}
        /health               → /health
    """
    if not path:
        return "/"

    # 去掉 query string
    path = path.split("?")[0]

    # 去掉尾部斜杠
    path = path.rstrip("/")
    if not path:
        return "/"

    # 分段处理
    segments = path.split("/")
    normalized = []

    for seg in segments:
        if not seg:
            continue
        # 纯数字 → {id}
        if seg.isdigit():
            normalized.append("{id}")
        # UUID 格式
        elif re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', seg, re.I):
            normalized.append("{uuid}")
        # 混合字母数字且长度 > 20（hash/token）
        elif re.match(r'^[0-9a-f]{16,}$', seg, re.I):
            normalized.append("{hash}")
        # 包含字母数字下划线横线，看起来像 ID
        elif re.match(r'^[a-zA-Z0-9_-]+$', seg) and not _looks_like_resource(seg):
            normalized.append("{id}")
        else:
            normalized.append(seg.lower())

    return "/" + "/".join(normalized)


def _looks_like_resource(segment: str) -> bool:
    """判断路径段是否像资源名（而非参数值）。"""
    resource_words = {
        "api", "v1", "v2", "v3", "v4", "users", "user", "orders", "order",
        "products", "product", "items", "item", "auth", "login", "logout",
        "register", "token", "refresh", "profile", "settings", "config",
        "admin", "dashboard", "health", "status", "metrics", "search",
        "upload", "download", "export", "import", "list", "create", "update",
        "delete", "batch", "bulk", "count", "stats", "summary", "detail",
        "public", "private", "internal", "webhook", "callback", "notify",
        "payment", "checkout", "cart", "wishlist", "review", "rating",
        "comment", "post", "message", "notification",
    }
    return segment.lower() in resource_words


# ======================================================================
# Swagger 文档解析
# ======================================================================


def extract_endpoints_from_swagger(swagger_text: str) -> list[dict]:
    """从 Swagger/OpenAPI JSON 中提取所有已声明的 endpoint。

    Returns:
        [{"method": "GET", "path": "/api/users/{id}", "raw_path": "/api/users/{id}"}, ...]
    """
    try:
        doc = json.loads(swagger_text) if isinstance(swagger_text, str) else swagger_text
    except json.JSONDecodeError:
        logger.error("Swagger 文档 JSON 解析失败")
        return []

    endpoints = []
    paths = doc.get("paths", {})

    for raw_path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        for method in methods:
            if method.upper() in {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}:
                # Swagger 路径本身已有 {param} 占位符
                normalized = _normalize_swagger_path(raw_path)
                endpoints.append({
                    "method": method.upper(),
                    "path": normalized,
                    "raw_path": raw_path,
                })

    logger.info("从 Swagger 提取 %d 个已声明 endpoint", len(endpoints))
    return endpoints


def _normalize_swagger_path(path: str) -> str:
    """统一 Swagger 路径中的参数占位符格式。

    Swagger 支持 {paramName} 格式，有些是 :paramName。
    统一转为 {param} 以方便对比。
    """
    # :paramName → {paramName}
    path = re.sub(r'/:(?P<name>[a-zA-Z_]\w*)', r'/{\g<name>}', path)
    return path.rstrip("/") or "/"


# ======================================================================
# 流量日志解析
# ======================================================================


def extract_endpoints_from_traffic(traffic_input: str, format_hint: str = "auto") -> list[dict]:
    """从流量日志中提取所有实际调用的 endpoint。

    Args:
        traffic_input: 日志内容字符串
        format_hint: "har" | "json" | "urls" | "auto"

    Returns:
        [{"method": "GET", "path": "/api/users/{id}", "raw_path": "/api/users/123"}, ...]
    """
    text = traffic_input.strip()

    # 尝试 HAR
    if format_hint in ("auto", "har"):
        try:
            return _parse_har(text)
        except (json.JSONDecodeError, KeyError, TypeError):
            pass

    # 尝试 JSON 数组
    if format_hint in ("auto", "json"):
        try:
            parsed = json.loads(text)
            if isinstance(parsed, list):
                return _parse_json_array(parsed)
        except json.JSONDecodeError:
            pass

    # 兜底：纯文本 URL 列表
    return _parse_url_list(text)


def _parse_har(har_text: str) -> list[dict]:
    """解析 HAR 1.2 格式。"""
    har = json.loads(har_text) if isinstance(har_text, str) else har_text
    entries = har["log"]["entries"]

    endpoints = []
    for entry in entries:
        request = entry.get("request", {})
        method = request.get("method", "GET").upper()
        url = request.get("url", "")
        path = urlparse(url).path or "/"

        endpoints.append({
            "method": method,
            "path": normalize_path(path),
            "raw_path": path,
        })

    logger.info("从 HAR 提取 %d 个请求 endpoint", len(endpoints))
    return endpoints


def _parse_json_array(arr: list) -> list[dict]:
    """解析 JSON 数组格式：[{method, path}, ...] 或 [{method, url}, ...]。"""
    endpoints = []
    for item in arr:
        if not isinstance(item, dict):
            continue
        method = item.get("method", "GET").upper()
        raw = item.get("path") or item.get("url") or ""
        if raw.startswith("http"):
            raw = urlparse(raw).path
        endpoints.append({
            "method": method,
            "path": normalize_path(raw),
            "raw_path": raw,
        })
    logger.info("从 JSON 数组提取 %d 个请求 endpoint", len(endpoints))
    return endpoints


def _parse_url_list(text: str) -> list[dict]:
    """解析纯文本 URL 列表（每行一个）。"""
    endpoints = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # 尝试提取 method
        method = "GET"
        if " " in line:
            parts = line.split(None, 1)
            if parts[0].upper() in {"GET", "POST", "PUT", "DELETE", "PATCH"}:
                method = parts[0].upper()
                line = parts[1].strip()
        if line.startswith("http"):
            line = urlparse(line).path
        endpoints.append({
            "method": method,
            "path": normalize_path(line),
            "raw_path": line,
        })
    logger.info("从 URL 列表提取 %d 个请求 endpoint", len(endpoints))
    return endpoints


# ======================================================================
# 核心：差分对比
# ======================================================================


def detect_shadow_apis(swagger_text: str, traffic_input: str,
                       traffic_format: str = "auto") -> dict:
    """检测影子 API：流量中存在但 Swagger 文档中未声明的 endpoint。

    Returns:
        {
            "swagger_endpoints": [...],          # 已声明 endpoint
            "traffic_endpoints": [...],           # 流量中所有 endpoint（去重）
            "shadow_apis": [...],                 # 影子 API（流量有，文档无）
            "documented_apis": [...],             # 合法 API（文档 + 流量都有）
            "only_documented": [...],             # 仅文档声明但无流量的（可能是僵尸文档）
            "stats": {
                "swagger_count": N,
                "traffic_unique_count": N,
                "shadow_count": N,
                "documented_count": N,
                "only_documented_count": N,
                "shadow_rate": "XX%",
            }
        }
    """
    # 1. 提取
    swagger_endpoints = extract_endpoints_from_swagger(swagger_text)
    traffic_endpoints_raw = extract_endpoints_from_traffic(traffic_input, traffic_format)

    # 2. 去重流量 endpoint
    seen = set()
    traffic_endpoints = []
    for ep in traffic_endpoints_raw:
        key = (ep["method"], ep["path"])
        if key not in seen:
            seen.add(key)
            traffic_endpoints.append(ep)

    # 3. 构建文档索引
    doc_keys = {(ep["method"], ep["path"]) for ep in swagger_endpoints}
    # 也加入仅方法不同的 key 用于宽松匹配
    doc_paths = {ep["path"] for ep in swagger_endpoints}

    # 4. 差分
    shadow_apis = []
    documented_apis = []
    for ep in traffic_endpoints:
        key = (ep["method"], ep["path"])
        if key in doc_keys:
            documented_apis.append(ep)
        else:
            # 宽松匹配：同路径但不同方法也算发现
            if ep["path"] in doc_paths:
                ep["note"] = f"路径已声明但 {ep['method']} 方法未在文档中"
            else:
                ep["note"] = "完全未声明的端点"
            shadow_apis.append(ep)

    # 仅文档有的（无流量）
    traffic_keys = {(ep["method"], ep["path"]) for ep in traffic_endpoints}
    only_documented = [ep for ep in swagger_endpoints
                       if (ep["method"], ep["path"]) not in traffic_keys]

    # 5. 风险评分
    for api in shadow_apis:
        api["risk"] = _assess_risk(api)

    # 按风险排序
    shadow_apis.sort(key=lambda a: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(a.get("risk", "low"), 4))

    # 6. 统计
    total_traffic = len(traffic_endpoints)
    shadow_count = len(shadow_apis)
    shadow_rate = f"{round(shadow_count / total_traffic * 100)}%" if total_traffic > 0 else "0%"

    return {
        "swagger_endpoints": swagger_endpoints,
        "traffic_endpoints": traffic_endpoints,
        "shadow_apis": shadow_apis,
        "documented_apis": documented_apis,
        "only_documented": only_documented,
        "stats": {
            "swagger_count": len(swagger_endpoints),
            "traffic_unique_count": total_traffic,
            "shadow_count": shadow_count,
            "documented_count": len(documented_apis),
            "only_documented_count": len(only_documented),
            "shadow_rate": shadow_rate,
        },
    }


def _assess_risk(api: dict) -> str:
    """评估影子 API 的风险等级。"""
    method = api.get("method", "GET")
    path = api.get("path", "")
    note = api.get("note", "")

    # 完全未声明 + 写操作 = critical
    if "完全未声明" in note:
        if method in ("POST", "PUT", "DELETE", "PATCH"):
            return "critical"
        if any(kw in path.lower() for kw in ("admin", "delete", "remove", "exec", "cmd", "debug")):
            return "critical"
        return "high"

    # 方法不匹配
    if method == "DELETE" and "方法未在文档中" in note:
        return "critical"
    if method in ("POST", "PUT", "PATCH") and "方法未在文档中" in note:
        return "high"

    return "medium"
