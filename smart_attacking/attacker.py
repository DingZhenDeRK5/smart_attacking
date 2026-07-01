"""
智攻 (SmartAttack) — HTTP 攻击执行引擎
=====================================
负责抓取 Swagger 文档、构造 HTTP 请求并并发执行攻击载荷。
不依赖 AI 模块，仅使用 requests 库。
"""

import logging
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote, urljoin, urlparse

import requests

try:
    from config import HTTP_TIMEOUT, MAX_WORKERS
except ImportError:
    from .config import HTTP_TIMEOUT, MAX_WORKERS

logger = logging.getLogger("smart_attack.attacker")


def build_root_url(target_url: str) -> str:
    """从 Swagger 文档地址推导出服务根地址 (scheme://host:port)。"""
    parsed = urlparse(target_url)
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}"
    if "/api/" in target_url:
        return target_url.split("/api/")[0]
    return target_url.rsplit("/", 1)[0]


def _join_url(root_url: str, url_path: str) -> str:
    """Join root URL and relative path without losing API base paths."""
    if url_path.startswith(("http://", "https://")):
        return url_path
    if not url_path.startswith("/"):
        url_path = "/" + url_path
    return urljoin(root_url.rstrip("/") + "/", url_path.lstrip("/"))


def _fill_unresolved_path_params(url_path: str, req: dict) -> str:
    """Replace leftover OpenAPI {path} params with safe deterministic values."""
    params = req.get("path_params") or {}

    def repl(match):
        name = match.group(1)
        if name in params:
            return quote(str(params[name]), safe="")
        lowered = name.lower()
        if "user" in lowered or "name" in lowered or "account" in lowered:
            return "admin"
        if "book" in lowered or "id" in lowered:
            return "1"
        return "smartattack-test"

    return re.sub(r"\{([^}]+)\}", repl, url_path)


def fetch_remote_swagger(url: str, headers: dict = None) -> str:
    """抓取远程 Swagger/OpenAPI 文档。"""
    logger.info("正在抓取目标文档: %s", url)
    response = requests.get(url, timeout=HTTP_TIMEOUT, headers=headers or {})
    response.raise_for_status()
    return response.text


def execute_single_attack(index: int, plan: dict, root_url: str,
                          auth_headers: dict = None) -> dict:
    """按 AI 设计的结构发出单个请求，永不抛异常（失败也返回结构化结果）。

    认证 headers 会与 AI 生成 headers 合并，AI 的 headers 优先。
    """
    req = plan["request"]
    url_path = _fill_unresolved_path_params(req.get("url_path", ""), req)
    full_url = _join_url(root_url, url_path)

    reason = plan.get("reason", "")
    vuln_type = plan.get("vulnerability_type", "unknown")
    payload = {
        "method": req.get("method", "GET"),
        "path": url_path,
        "vulnerability_type": vuln_type,
        "injected_data": req.get("body") or req.get("query_params"),
    }
    logger.info("执行第 %s 波攻击 [%s]: %s", index + 1, vuln_type, reason)

    # 合并认证 headers（AI 的 headers 优先级更高）
    merged_headers = dict(auth_headers or {})
    merged_headers.update(req.get("headers", {}))
    merged_headers = {k: v for k, v in merged_headers.items() if v is not None}

    body = req.get("body")
    request_kwargs = {
        "method": req.get("method", "GET"),
        "url": full_url,
        "headers": merged_headers,
        "params": req.get("query_params"),
        "timeout": HTTP_TIMEOUT,
    }
    content_type = (merged_headers.get("Content-Type") or merged_headers.get("content-type") or "").lower()
    if body is not None:
        if "application/x-www-form-urlencoded" in content_type or "multipart/form-data" in content_type:
            request_kwargs["data"] = body
        elif isinstance(body, (dict, list)):
            request_kwargs["json"] = body
        else:
            request_kwargs["data"] = body

    try:
        res = requests.request(**request_kwargs)
        return {
            "round": index + 1,
            "reason": reason,
            "vulnerability_type": vuln_type,
            "source": plan.get("source", "ai"),
            "rule_confidence": plan.get("rule_confidence"),
            "expected_normal": plan.get("expected_normal_behavior", ""),
            "exploit_indicator": plan.get("exploit_indicator", ""),
            "payload": payload,
            "method": req.get("method", "GET"),
            "path": url_path,
            "status_code": res.status_code,
            "elapsed_ms": int(res.elapsed.total_seconds() * 1000),  # 供 AI 判断时间盲注
            "response_len": len(res.text),                          # 供 AI 识别异常超大响应
            "response_text": res.text[:4000],  # 增大响应截取长度，确保捕获完整敏感数据
        }
    except Exception as e:
        logger.warning("第 %s 波攻击执行失败: %s", index + 1, e)
        return {
            "round": index + 1,
            "reason": reason,
            "vulnerability_type": vuln_type,
            "source": plan.get("source", "ai"),
            "rule_confidence": plan.get("rule_confidence"),
            "expected_normal": plan.get("expected_normal_behavior", ""),
            "exploit_indicator": plan.get("exploit_indicator", ""),
            "payload": payload,
            "method": req.get("method", "GET"),
            "path": url_path,
            "status_code": 0,
            "elapsed_ms": 0,
            "response_len": 0,
            "response_text": f"执行失败: {e}",
        }


def execute_dynamic_attack(attack_plans, base_url, auth_headers: dict = None):
    """动态执行引擎：并发执行 AI 设计的多组请求，按轮次排序返回。

    auth_headers 会注入到每个攻击请求中（认证感知扫描）。
    """
    root_url = build_root_url(base_url)

    results = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = [
            pool.submit(execute_single_attack, i, plan, root_url, auth_headers)
            for i, plan in enumerate(attack_plans)
        ]
        for future in as_completed(futures):
            results.append(future.result())

    results.sort(key=lambda r: r["round"])
    return results
