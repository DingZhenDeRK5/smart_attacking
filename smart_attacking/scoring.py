"""
智攻 (SmartAttack) v3.5 — SmartAttack Score™ 安全评分引擎
==========================================================
基于漏洞数量、严重度分布、CVSS 加权、业务影响的多维度安全评分体系。

评分维度：
  1. 漏洞密度 (20%)：漏洞数 / API 端点数
  2. 严重度分布 (40%)：CVSS 加权严重度
  3. 攻击面覆盖 (15%)：OWASP 类别覆盖度
  4. 认证安全 (15%)：认证相关漏洞占比
  5. 数据安全 (10%)：数据泄露相关漏洞占比

得分：0-100，越高越安全
等级：A (90-100) / B (75-89) / C (60-74) / D (40-59) / F (0-39)
"""

import math

# 严重度 CVSS 权重
SEVERITY_WEIGHT = {
    "critical": 10.0,
    "high": 7.5,
    "medium": 5.0,
    "low": 2.5,
    "info": 1.0,
}

# 等级定义
GRADE_THRESHOLDS = [
    (90, "A", "优秀 — API 安全防护完善"),
    (75, "B", "良好 — 存在少量中低危漏洞"),
    (60, "C", "一般 — 存在中高危漏洞，需关注"),
    (40, "D", "较差 — 存在严重漏洞，急需修复"),
    (0, "F", "危险 — API 安全形同虚设"),
]

# OWASP API Top 10 映射
OWASP_CATEGORIES = {
    "bola": "API1:2023 — Broken Object Level Authorization",
    "idor": "API1:2023 — Broken Object Level Authorization",
    "privilege_escalation": "API1:2023 — Broken Object Level Authorization",
    "auth_bypass": "API2:2023 — Broken Authentication",
    "jwt_weakness": "API2:2023 — Broken Authentication",
    "info_leak": "API3:2023 — Broken Object Property Level Authorization",
    "mass_assignment": "API3:2023 — Broken Object Property Level Authorization",
    "sql_injection": "API8:2023 — Injection",
    "command_injection": "API8:2023 — Injection",
    "xss": "API8:2023 — Injection",
    "nosql_injection": "API8:2023 — Injection",
    "path_traversal": "API1:2023 — Broken Access Control",
    "ssrf": "API10:2023 — Unsafe Consumption of APIs",
    "open_redirect": "API1:2023 — Broken Access Control",
    "security_misconfig": "API7:2023 — Security Misconfiguration",
    "logic_bypass": "API1:2023 — Broken Access Control",
    "param_tampering": "API5:2023 — Broken Function Level Authorization",
}


def calculate_score(scan_result: dict) -> dict:
    """计算 SmartAttack Score。

    Args:
        scan_result: 包含 execution_results, security_assessment 等的扫描结果

    Returns:
        { score, grade, grade_label, dimensions, recommendations, cvss_stats }
    """
    data = scan_result.get("data", scan_result)
    assessment = data.get("security_assessment", {})
    vulns = assessment.get("vulnerabilities_found", [])
    results = data.get("execution_results", [])
    business = data.get("business_analysis", {})
    stats = data.get("stats", {})

    if not vulns and not results:
        return _perfect_score()

    # ---- 维度 1: 漏洞密度 (20%) ----
    endpoint_count = max(len(_extract_endpoints(results)), 1)
    vuln_count = len(vulns)
    density_ratio = min(vuln_count / endpoint_count, 3.0)  # cap at 3x
    density_score = max(0, 100 - (density_ratio / 3.0) * 100)
    density_weighted = density_score * 0.20

    # ---- 维度 2: 严重度分布 (40%) ----
    severity_scores = []
    max_possible = 0
    for v in vulns:
        sev = v.get("severity", "medium")
        weight = SEVERITY_WEIGHT.get(sev, 5.0)
        severity_scores.append(weight)
        max_possible += 10.0  # worst case: all critical

    if max_possible == 0:
        severity_weighted = 40  # perfect on this dimension
    else:
        total_severity = sum(severity_scores)
        ratio = min(total_severity / max_possible, 1.0)
        severity_score = (1 - ratio) * 100
        severity_weighted = severity_score * 0.40

    # ---- 维度 3: 攻击面覆盖 (15%) ----
    covered_owasp = set()
    for v in vulns:
        vtype = v.get("vulnerability_type", "")
        owasp_cat = OWASP_CATEGORIES.get(vtype, "")
        if owasp_cat:
            covered_owasp.add(owasp_cat[:4])  # API1, API2, etc.
    coverage_ratio = max(len(covered_owasp) / 7.0, 0.1)  # at least 10%
    coverage_score = max(0, (1 - coverage_ratio) * 100)
    coverage_weighted = coverage_score * 0.15

    # ---- 维度 4: 认证安全 (15%) ----
    auth_vulns = [v for v in vulns
                  if v.get("vulnerability_type", "") in
                  ("bola", "idor", "privilege_escalation", "auth_bypass", "jwt_weakness")]
    auth_ratio = len(auth_vulns) / max(vuln_count, 1)
    auth_score = max(0, (1 - auth_ratio) * 100)
    auth_weighted = auth_score * 0.15

    # ---- 维度 5: 数据安全 (10%) ----
    data_vulns = [v for v in vulns
                  if v.get("vulnerability_type", "") in
                  ("info_leak", "mass_assignment", "security_misconfig")]
    data_ratio = len(data_vulns) / max(vuln_count, 1)
    data_score = max(0, (1 - data_ratio) * 100)
    data_weighted = data_score * 0.10

    # ---- 综合得分 ----
    total_score = density_weighted + severity_weighted + coverage_weighted + auth_weighted + data_weighted
    total_score = max(0, min(100, round(total_score)))

    # ---- 等级评定 ----
    grade, grade_label = _get_grade(total_score)

    # ---- 修复建议 ----
    recommendations = _generate_recommendations(vulns, total_score)

    # ---- CVSS 统计 ----
    cvss_stats = _calculate_cvss_stats(vulns)

    return {
        "score": total_score,
        "grade": grade,
        "grade_label": grade_label,
        "dimensions": {
            "vulnerability_density": round(density_weighted, 1),
            "severity_distribution": round(severity_weighted, 1),
            "attack_surface_coverage": round(coverage_weighted, 1),
            "authentication_security": round(auth_weighted, 1),
            "data_security": round(data_weighted, 1),
        },
        "vulnerability_summary": {
            "total": vuln_count,
            "critical": len([v for v in vulns if v.get("severity") == "critical"]),
            "high": len([v for v in vulns if v.get("severity") == "high"]),
            "medium": len([v for v in vulns if v.get("severity") == "medium"]),
            "low": len([v for v in vulns if v.get("severity") == "low"]),
            "info": len([v for v in vulns if v.get("severity") == "info"]),
            "endpoints_tested": endpoint_count,
        },
        "cvss_stats": cvss_stats,
        "owasp_coverage": sorted(covered_owasp),
        "recommendations": recommendations,
    }


def _perfect_score() -> dict:
    return {
        "score": 100,
        "grade": "A",
        "grade_label": "优秀 — 未发现任何漏洞",
        "dimensions": {k: 20.0 if "density" in k else
                          40.0 if "severity" in k else
                          15.0 if "auth" in k or "coverage" in k else
                          10.0
                       for k in ["vulnerability_density", "severity_distribution",
                                  "attack_surface_coverage", "authentication_security",
                                  "data_security"]},
        "vulnerability_summary": {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "endpoints_tested": 0},
        "cvss_stats": {"avg_cvss": 0, "max_cvss": 0, "total_cvss": 0},
        "owasp_coverage": [],
        "recommendations": ["🎉 恭喜！未发现安全漏洞。"],
    }


def _get_grade(score: int) -> tuple[str, str]:
    for threshold, grade, label in GRADE_THRESHOLDS:
        if score >= threshold:
            return grade, label
    return "F", "危险"


def _extract_endpoints(results: list) -> set:
    eps = set()
    for r in results:
        path = r.get("payload", {}).get("path", r.get("path", "/"))
        method = r.get("payload", {}).get("method", r.get("method", "GET"))
        eps.add(f"{method}:{path}")
    return eps


def _calculate_cvss_stats(vulns: list) -> dict:
    scores = [v.get("cvss_score", 0) for v in vulns if v.get("cvss_score", 0) > 0]
    if not scores:
        return {"avg_cvss": 0, "max_cvss": 0, "total_cvss": 0}
    return {
        "avg_cvss": round(sum(scores) / len(scores), 1),
        "max_cvss": round(max(scores), 1),
        "total_cvss": round(sum(scores), 1),
    }


def _generate_recommendations(vulns: list, score: int) -> list[str]:
    recs = []
    vuln_types = [v.get("vulnerability_type", "") for v in vulns]

    if any(t in vuln_types for t in ("sql_injection", "nosql_injection", "command_injection")):
        recs.append("🔴 使用参数化查询/ORM 防止注入攻击，对所有用户输入进行严格校验")
    if any(t in vuln_types for t in ("bola", "idor", "privilege_escalation")):
        recs.append("🔴 实施对象级访问控制 (Object-Level Authorization)，验证用户对资源的访问权限")
    if any(t in vuln_types for t in ("auth_bypass", "jwt_weakness")):
        recs.append("🟠 强化认证机制：使用强算法签名 JWT，验证 alg 参数，设置合理过期时间")
    if any(t in vuln_types for t in ("xss",)):
        recs.append("🟠 对输出进行 HTML 实体编码，实施 Content-Security-Policy")
    if any(t in vuln_types for t in ("info_leak", "mass_assignment")):
        recs.append("🟡 定义明确的 DTO/View Model，避免敏感字段无意暴露")
    if any(t in vuln_types for t in ("path_traversal",)):
        recs.append("🟡 使用白名单限制文件访问路径，避免用户输入直接拼接文件路径")
    if any(t in vuln_types for t in ("ssrf",)):
        recs.append("🟡 实施 URL 白名单，禁止服务端访问内网地址")
    if any(t in vuln_types for t in ("open_redirect",)):
        recs.append("🟢 重定向目标使用白名单或相对路径，禁止用户完全控制重定向 URL")

    if not recs:
        if score >= 90:
            recs.append("🎉 安全状况良好，建议定期进行渗透测试保持安全")
        elif score >= 60:
            recs.append("📋 建议定期进行 AI 渗透扫描，持续监控 API 安全状况")
        else:
            recs.append("🚨 建议立即进行全面的安全审计和漏洞修复")

    # 通用建议
    recs.append("💡 将 SmartAttack 集成到 CI/CD 流水线中，实现每次部署前的自动安全检测")
    return recs
