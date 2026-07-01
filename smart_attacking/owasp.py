"""
智攻 (SmartAttack) — OWASP Top 10 (2021) 漏洞分类映射
=====================================================
将 SmartAttack 内部漏洞类型映射到 OWASP 十大安全风险分类。
"""

# OWASP Top 10 (2021) 分类定义
OWASP_CATEGORIES = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable and Outdated Components",
    "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Integrity Failures",
    "A09": "Security Logging and Monitoring Failures",
    "A10": "Server-Side Request Forgery (SSRF)",
}

# 漏洞类型 → OWASP 分类映射
VULN_TO_OWASP = {
    # 越权访问 → A01: 访问控制失效
    "bola": "A01",
    "idor": "A01",
    "privilege_escalation": "A01",
    "authz_bypass": "A01",

    # 认证绕过 → A07: 身份识别和认证失败
    "auth_bypass": "A07",
    "weak_auth": "A07",
    "brute_force": "A07",

    # 批量赋值 → A04: 不安全设计
    "mass_assignment": "A04",
    "logic_bypass": "A04",
    "business_logic": "A04",

    # 参数篡改 / 注入 → A03: 注入
    "param_tampering": "A03",
    "injection": "A03",
    "sql_injection": "A03",
    "command_injection": "A03",

    # 信息泄露 → A05: 安全配置错误
    "info_leak": "A05",
    "security_misconfig": "A05",
    "error_disclosure": "A05",

    # SSRF → A10
    "ssrf": "A10",

    # JWT/Token 弱点
    "jwt_weakness": "A02",

    # 默认
    "unknown": "A04",
}

# 中文标签
OWASP_LABELS_ZH = {
    "A01": "访问控制失效",
    "A02": "加密失效",
    "A03": "注入",
    "A04": "不安全设计",
    "A05": "安全配置错误",
    "A06": "脆弱的第三方组件",
    "A07": "身份识别和认证失败",
    "A08": "软件和数据完整性失效",
    "A09": "安全日志和监控失效",
    "A10": "服务端请求伪造 (SSRF)",
}


def get_owasp_category(vuln_type: str) -> tuple:
    """根据漏洞类型返回 OWASP 分类。

    Returns:
        (category_id, category_name_en, category_name_zh)
        例如: ("A01", "Broken Access Control", "访问控制失效")
    """
    vuln_lower = vuln_type.lower().strip()
    cat_id = VULN_TO_OWASP.get(vuln_lower, "A04")
    return cat_id, OWASP_CATEGORIES[cat_id], OWASP_LABELS_ZH.get(cat_id, "")


def get_owasp_summary(vulnerabilities: list) -> dict:
    """给定漏洞列表，汇总 OWASP 覆盖情况。

    Args:
        vulnerabilities: dict 列表，每个至少包含 vuln_type 字段

    Returns:
        { "A01": {"name": "Broken Access Control", "name_zh": "访问控制失效",
                   "count": 3, "vulns": [...]}, ... }
    """
    summary = {}
    for v in vulnerabilities:
        vuln_type = v.get("vuln_type", "unknown")
        cat_id, cat_name, cat_name_zh = get_owasp_category(vuln_type)
        if cat_id not in summary:
            summary[cat_id] = {
                "name": cat_name,
                "name_zh": cat_name_zh,
                "count": 0,
                "vulns": [],
            }
        summary[cat_id]["count"] += 1
        summary[cat_id]["vulns"].append(v)
    return summary
