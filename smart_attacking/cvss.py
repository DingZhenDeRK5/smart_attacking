"""
智攻 (SmartAttack) — CVSS 3.1 评分计算器
=========================================
实现 CVSS v3.1 Base Score 计算，并提供 API 漏洞类型的预估值。
参考: https://www.first.org/cvss/v3.1/specification-document
"""

import math


# ======================================================================
# CVSS v3.1 Base Score 计算
# ======================================================================

# 攻击向量 (Attack Vector)
AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}

# 攻击复杂度 (Attack Complexity)
AC = {"L": 0.77, "H": 0.44}

# 权限要求 (Privileges Required)
PR = {
    "U": {"N": 0.85, "L": 0.62, "H": 0.27},
    "C": {"N": 0.85, "L": 0.68, "H": 0.50},
}

# 用户交互 (User Interaction)
UI = {"N": 0.85, "R": 0.62}

# 影响度 (C/I/A Impact)
IMPACT = {"N": 0.0, "L": 0.22, "H": 0.56}


def _severity(score: float) -> str:
    """根据 CVSS 分数返回严重等级。"""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score >= 0.1:
        return "low"
    return "info"


def calculate_cvss(
    attack_vector: str = "N",
    attack_complexity: str = "L",
    privileges_required: str = "N",
    user_interaction: str = "N",
    scope: str = "U",
    confidentiality: str = "N",
    integrity: str = "N",
    availability: str = "N",
) -> tuple:
    """计算 CVSS v3.1 Base Score。

    Args:
        attack_vector: N(网络) | A(相邻) | L(本地) | P(物理)
        attack_complexity: L(低) | H(高)
        privileges_required: N(无) | L(低) | H(高)
        user_interaction: N(无) | R(需要)
        scope: U(不变) | C(改变)
        confidentiality: N(无) | L(低) | H(高)
        integrity: N(无) | L(低) | H(高)
        availability: N(无) | L(低) | H(高)

    Returns:
        (score: float, vector_string: str, severity_label: str)
    """
    # ISS (Impact Sub Score)
    iss = 1.0 - (
        (1 - IMPACT.get(confidentiality, 0)) *
        (1 - IMPACT.get(integrity, 0)) *
        (1 - IMPACT.get(availability, 0))
    )

    # Impact
    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15

    # Exploitability
    pr_value = PR.get(scope, PR["U"]).get(privileges_required, 0.85)
    exploitability = 8.22 * AV.get(attack_vector, 0.85) * AC.get(attack_complexity, 0.77) * pr_value * UI.get(user_interaction, 0.85)

    # Base Score
    if impact <= 0:
        score = 0.0
    elif scope == "U":
        score = min(impact + exploitability, 10)
    else:
        score = min(1.08 * (impact + exploitability), 10)

    score = round(score, 1)
    score = math.ceil(score * 10) / 10  # Round up to 1 decimal

    # Vector String
    vector = (
        f"CVSS:3.1/AV:{attack_vector}/AC:{attack_complexity}/PR:{privileges_required}/"
        f"UI:{user_interaction}/S:{scope}/C:{confidentiality}/I:{integrity}/A:{availability}"
    )

    return score, vector, _severity(score)


# ======================================================================
# API 漏洞类型的 CVSS 预估值
# ======================================================================

# 为每种 API 漏洞类型预设合理的 CVSS 参数
_VULN_CVSS_PARAMS = {
    "bola": {
        # BOLA/IDOR: 网络可达、低复杂度、无需权限、无用户交互，影响机密性和完整性
        "attack_vector": "N", "attack_complexity": "L",
        "privileges_required": "N", "user_interaction": "N",
        "scope": "U", "confidentiality": "H", "integrity": "H",
        "availability": "N",
    },
    "idor": {
        "attack_vector": "N", "attack_complexity": "L",
        "privileges_required": "N", "user_interaction": "N",
        "scope": "U", "confidentiality": "H", "integrity": "H",
        "availability": "N",
    },
    "privilege_escalation": {
        "attack_vector": "N", "attack_complexity": "L",
        "privileges_required": "L", "user_interaction": "N",
        "scope": "C", "confidentiality": "H", "integrity": "H",
        "availability": "H",
    },
    "auth_bypass": {
        "attack_vector": "N", "attack_complexity": "L",
        "privileges_required": "N", "user_interaction": "N",
        "scope": "U", "confidentiality": "H", "integrity": "H",
        "availability": "H",
    },
    "mass_assignment": {
        "attack_vector": "N", "attack_complexity": "L",
        "privileges_required": "N", "user_interaction": "N",
        "scope": "U", "confidentiality": "L", "integrity": "H",
        "availability": "N",
    },
    "param_tampering": {
        "attack_vector": "N", "attack_complexity": "L",
        "privileges_required": "N", "user_interaction": "N",
        "scope": "U", "confidentiality": "L", "integrity": "L",
        "availability": "N",
    },
    "logic_bypass": {
        "attack_vector": "N", "attack_complexity": "H",
        "privileges_required": "N", "user_interaction": "N",
        "scope": "U", "confidentiality": "L", "integrity": "H",
        "availability": "N",
    },
    "info_leak": {
        "attack_vector": "N", "attack_complexity": "L",
        "privileges_required": "N", "user_interaction": "N",
        "scope": "U", "confidentiality": "L", "integrity": "N",
        "availability": "N",
    },
    "injection": {
        "attack_vector": "N", "attack_complexity": "L",
        "privileges_required": "N", "user_interaction": "N",
        "scope": "U", "confidentiality": "H", "integrity": "H",
        "availability": "H",
    },
    "ssrf": {
        "attack_vector": "N", "attack_complexity": "L",
        "privileges_required": "N", "user_interaction": "N",
        "scope": "C", "confidentiality": "H", "integrity": "N",
        "availability": "N",
    },
    "injection": {
        "attack_vector": "N", "attack_complexity": "L",
        "privileges_required": "N", "user_interaction": "N",
        "scope": "U", "confidentiality": "H", "integrity": "H",
        "availability": "H",
    },
    "jwt_weakness": {
        "attack_vector": "N", "attack_complexity": "L",
        "privileges_required": "N", "user_interaction": "N",
        "scope": "U", "confidentiality": "H", "integrity": "H",
        "availability": "N",
    },
    "security_misconfig": {
        "attack_vector": "N", "attack_complexity": "L",
        "privileges_required": "N", "user_interaction": "N",
        "scope": "U", "confidentiality": "L", "integrity": "L",
        "availability": "N",
    },
    "brute_force": {
        "attack_vector": "N", "attack_complexity": "L",
        "privileges_required": "N", "user_interaction": "N",
        "scope": "U", "confidentiality": "L", "integrity": "L",
        "availability": "N",
    },
}


def estimate_cvss_for_vuln(vuln_type: str) -> tuple:
    """根据漏洞类型估算 CVSS 3.1 评分。

    Args:
        vuln_type: 漏洞类型字符串（bola, mass_assignment, info_leak 等）

    Returns:
        (score: float, vector_string: str, severity_label: str)
    """
    vuln_lower = vuln_type.lower().strip()
    params = _VULN_CVSS_PARAMS.get(vuln_lower)
    if params is None:
        # 未知类型使用保守估计
        params = {
            "attack_vector": "N", "attack_complexity": "L",
            "privileges_required": "N", "user_interaction": "N",
            "scope": "U", "confidentiality": "L", "integrity": "L",
            "availability": "N",
        }
    return calculate_cvss(**params)
