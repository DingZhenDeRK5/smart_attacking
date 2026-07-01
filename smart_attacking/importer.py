"""
智攻 (SmartAttack) v3.5 — 多格式 API 文档导入器
================================================
支持导入：
  - Postman Collection v2.1 JSON
  - GraphQL Schema (Introspection JSON)
  - HAR (HTTP Archive) 文件
  - 纯文本 URL 列表

导入结果统一转换为内部端点格式，可直接用于扫描。
"""

import json
import logging
import re
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger("smart_attack.importer")

# 支持的导入格式
SUPPORTED_FORMATS = ["postman", "graphql", "har", "urls", "auto"]


def import_api_docs(content: str, fmt: str = "auto",
                     base_url: str = "") -> dict:
    """统一的文档导入入口。

    Args:
        content: 文档内容（JSON 字符串或纯文本）
        fmt: 格式: "postman" | "graphql" | "har" | "urls" | "auto"
        base_url: API 基础地址（GraphQL 需要）

    Returns:
        {
            "success": True,
            "format": "postman",
            "endpoints": [{method, path, description, params, headers}],
            "summary": { total_endpoints, methods_found, ... },
        }
    """
    # 自动检测格式
    if fmt == "auto":
        fmt = _detect_format(content)

    if fmt == "postman":
        return _import_postman(content)
    elif fmt == "graphql":
        return _import_graphql(content, base_url)
    elif fmt == "har":
        return _import_har(content)
    elif fmt == "urls":
        return _import_urls(content)
    else:
        return {"success": False, "error": f"不支持的格式: {fmt}",
                "supported_formats": SUPPORTED_FORMATS}


def _detect_format(content: str) -> str:
    """自动检测文档格式。"""
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, TypeError):
        # 可能是 URL 列表
        lines = [l.strip() for l in content.splitlines() if l.strip()]
        if lines and all(l.startswith(("http://", "https://", "/", "GET ", "POST ", "PUT ", "DELETE ")) for l in lines):
            return "urls"
        return "urls"  # fallback

    # Postman Collection
    if "info" in data and "item" in data and data.get("info", {}).get("schema", "").startswith("https://schema.getpostman.com"):
        return "postman"

    # GraphQL Introspection
    if "__schema" in data and "queryType" in data.get("__schema", {}):
        return "graphql"
    if "data" in data and "__schema" in data.get("data", {}):
        return "graphql"

    # HAR
    if "log" in data and "entries" in data.get("log", {}):
        return "har"

    # Fallback: try URL list
    return "urls"


# ======================================================================
# Postman Collection v2.1 导入
# ======================================================================


def _import_postman(content: str) -> dict:
    """导入 Postman Collection JSON。"""
    try:
        collection = json.loads(content)
    except json.JSONDecodeError as e:
        return {"success": False, "error": f"JSON 解析失败: {e}"}

    endpoints = []
    items = collection.get("item", [])

    def _walk(items, base_path=""):
        for item in items:
            if "item" in item:  # 文件夹
                folder_name = item.get("name", "")
                _walk(item["item"], f"{base_path}/{folder_name}")
            elif "request" in item:  # 具体请求
                req = item["request"]
                method = req.get("method", "GET")
                url_obj = req.get("url", {})
                path = _extract_postman_path(url_obj)

                # 提取 headers
                headers = {}
                for h in req.get("header", []):
                    headers[h.get("key", "")] = h.get("value", "")

                # 提取 query params
                params = []
                for q in url_obj.get("query", []):
                    params.append({
                        "name": q.get("key", ""),
                        "value": q.get("value", ""),
                    })

                # 提取 body
                body = None
                req_body = req.get("body", {})
                if req_body.get("mode") == "raw":
                    body = req_body.get("raw", "")

                endpoints.append({
                    "method": method,
                    "path": path,
                    "description": item.get("name", ""),
                    "params": params,
                    "headers": headers,
                    "body": body,
                })

    _walk(items)
    return _build_result(endpoints, "postman", collection.get("info", {}).get("name", ""))


def _extract_postman_path(url_obj: dict) -> str:
    """从 Postman URL 对象提取路径。"""
    if isinstance(url_obj, str):
        parsed = urlparse(url_obj)
        return parsed.path or "/"
    if isinstance(url_obj, dict):
        path_parts = url_obj.get("path", [])
        if path_parts:
            return "/" + "/".join(p for p in path_parts if p)
        raw = url_obj.get("raw", "")
        if raw:
            parsed = urlparse(raw)
            return parsed.path or "/"
    return "/"


# ======================================================================
# GraphQL Schema 导入
# ======================================================================


def _import_graphql(content: str, base_url: str = "") -> dict:
    """从 GraphQL Introspection JSON 导入 queries 和 mutations。"""
    try:
        data = json.loads(content)
    except json.JSONDecodeError as e:
        return {"success": False, "error": f"JSON 解析失败: {e}"}

    # 提取 schema
    schema = data.get("data", data).get("__schema", {})
    query_type = schema.get("queryType", {})
    mutation_type = schema.get("mutationType", {})

    gql_path = base_url.rstrip("/") + "/graphql" if base_url else "/graphql"
    endpoints = []

    # Query
    query_name = query_type.get("name", "Query")
    query_fields = _find_type_fields(schema, query_name)
    for field in query_fields:
        args = field.get("args", [])
        params = [{"name": a.get("name", ""), "type": _gql_type_name(a.get("type", {})),
                   "description": a.get("description", "")} for a in args]
        endpoints.append({
            "method": "POST",
            "path": gql_path,
            "description": f"GraphQL Query: {field.get('name', '')}",
            "params": params,
            "graphql_query": _build_gql_query(field),
            "body": _build_gql_body(field),
        })

    # Mutation
    mut_name = mutation_type.get("name", "")
    if mut_name:
        mut_fields = _find_type_fields(schema, mut_name)
        for field in mut_fields:
            args = field.get("args", [])
            params = [{"name": a.get("name", ""), "type": _gql_type_name(a.get("type", {})),
                       "description": a.get("description", "")} for a in args]
            endpoints.append({
                "method": "POST",
                "path": gql_path,
                "description": f"GraphQL Mutation: {field.get('name', '')}",
                "params": params,
                "graphql_query": _build_gql_mutation(field),
                "body": _build_gql_body(field),
            })

    return _build_result(endpoints, "graphql", f"GraphQL ({len(endpoints)} 操作)")


def _find_type_fields(schema: dict, type_name: str) -> list:
    for t in schema.get("types", []):
        if t.get("name") == type_name:
            return t.get("fields", [])
    return []


def _gql_type_name(type_obj: dict) -> str:
    if isinstance(type_obj, dict):
        name = type_obj.get("name", "")
        if type_obj.get("kind") == "NON_NULL":
            return _gql_type_name(type_obj.get("ofType", {}))
        if type_obj.get("kind") == "LIST":
            return f"[{_gql_type_name(type_obj.get('ofType', {}))}]"
        return name or "String"
    return "String"


def _build_gql_body(field: dict) -> dict:
    return {"query": _build_gql_query(field), "variables": {}}


def _build_gql_query(field: dict) -> str:
    name = field.get("name", "data")
    args = field.get("args", [])
    arg_str = ""
    if args:
        arg_parts = [f"${a['name']}: {_gql_type_name(a.get('type', {}))}" for a in args]
        arg_str = f"({', '.join(arg_parts)})"
    return f"query {{ {name}{arg_str} {{ id }} }}"


def _build_gql_mutation(field: dict) -> str:
    name = field.get("name", "mutate")
    args = field.get("args", [])
    arg_str = ""
    if args:
        arg_parts = [f"${a['name']}: {_gql_type_name(a.get('type', {}))}" for a in args]
        arg_str = f"({', '.join(arg_parts)})"
    return f"mutation {{ {name}{arg_str} {{ id }} }}"


# ======================================================================
# HAR (HTTP Archive) 导入
# ======================================================================


def _import_har(content: str) -> dict:
    try:
        data = json.loads(content)
    except json.JSONDecodeError as e:
        return {"success": False, "error": f"JSON 解析失败: {e}"}

    endpoints = []
    entries = data.get("log", {}).get("entries", [])

    for entry in entries:
        req = entry.get("request", {})
        url = req.get("url", "")
        parsed = urlparse(url)
        method = req.get("method", "GET")
        path = parsed.path or "/"

        headers = {}
        for h in req.get("headers", []):
            headers[h.get("name", "")] = h.get("value", "")

        body = req.get("postData", {}).get("text", "")
        params = []
        for q in req.get("queryString", []):
            params.append({"name": q.get("name", ""), "value": q.get("value", "")})

        # 只导入 API 类请求
        if _is_api_path(path):
            endpoints.append({
                "method": method,
                "path": path,
                "description": f"HAR: {method} {path}",
                "params": params,
                "headers": headers,
                "body": body,
            })

    return _build_result(endpoints, "har", f"HAR ({len(entries)} entries)")


def _is_api_path(path: str) -> bool:
    """判断路径是否为 API 调用。"""
    skip_extensions = {".js", ".css", ".png", ".jpg", ".jpeg", ".gif",
                       ".ico", ".svg", ".woff", ".woff2", ".ttf", ".eot",
                       ".html", ".htm", ".map"}
    for ext in skip_extensions:
        if path.endswith(ext):
            return False
    return True


# ======================================================================
# URL 列表导入
# ======================================================================


def _import_urls(content: str) -> dict:
    lines = [l.strip() for l in content.splitlines() if l.strip()]
    endpoints = []

    for line in lines:
        # 支持 "METHOD URL" 格式
        match = re.match(r'^(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\s+(.+)', line, re.IGNORECASE)
        if match:
            method = match.group(1).upper()
            url = match.group(2).strip()
        elif line.startswith(("http://", "https://")):
            method = "GET"
            url = line
        elif line.startswith("/"):
            method = "GET"
            url = line
        else:
            continue

        parsed = urlparse(url) if "://" in url else urlparse("http://localhost" + url)
        endpoints.append({
            "method": method,
            "path": parsed.path or "/",
            "description": f"URL: {method} {parsed.path}",
            "params": [],
            "headers": {},
            "body": None,
        })

    return _build_result(endpoints, "urls", f"URL List ({len(lines)} lines)")


# ======================================================================
# 工具函数
# ======================================================================


def _build_result(endpoints: list, fmt: str, source_name: str) -> dict:
    methods = sorted(set(e["method"] for e in endpoints))
    return {
        "success": True,
        "format": fmt,
        "source_name": source_name,
        "endpoints": endpoints,
        "summary": {
            "total_endpoints": len(endpoints),
            "methods_found": methods,
            "unique_paths": len(set(e["path"] for e in endpoints)),
        },
    }


def convert_to_swagger(endpoints: list, title: str = "Imported API") -> str:
    """将端点列表转换为最简单的 Swagger/OpenAPI 3.0 JSON，供扫描引擎使用。"""
    paths = {}
    for ep in endpoints:
        path = ep["path"]
        method = ep["method"].lower()
        if path not in paths:
            paths[path] = {}
        paths[path][method] = {
            "summary": ep.get("description", ""),
            "parameters": [
                {"name": p.get("name", "param"), "in": "query",
                 "schema": {"type": p.get("type", "string")}}
                for p in ep.get("params", [])
            ],
            "responses": {"200": {"description": "OK"}},
        }

    spec = {
        "openapi": "3.0.0",
        "info": {"title": title, "version": "1.0.0"},
        "paths": paths,
    }
    return json.dumps(spec, indent=2)
