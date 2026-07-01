"""
智攻 (SmartAttack) v3.5 — 对抗式验证引擎
========================================
每个疑似漏洞经过「攻击 Agent」+「防御 Agent」交叉验证：
  - 攻击 Agent：构造更多 payload 变体，证明漏洞真实存在
  - 防御 Agent：分析响应逻辑，论证为何这不是真正的漏洞
  - 判决：攻击方论据强于防御方 → 确认漏洞；否则降级或丢弃

这大幅降低误报率（False Positive），是 SmartAttack 区别于传统扫描器的核心技术壁垒。
"""

import json
import logging

try:
    from models.llm_provider import create_llm_provider, get_cached_provider
    from parser import extract_json
except ImportError:
    from .models.llm_provider import create_llm_provider, get_cached_provider
    from .parser import extract_json

logger = logging.getLogger("smart_attack.adversarial")

# ---------------------------------------------------------------------------
# System prompts（对抗双方的核心思维模式）
# ---------------------------------------------------------------------------

ATTACKER_SYSTEM_PROMPT = """你是一位资深 Red Team 渗透测试专家。你的任务是：
1. 分析给定的疑似漏洞的 HTTP 请求和响应
2. 构造 3-5 个更强的攻击 payload 变体来确认真实性
3. 论证为什么这是一个真实的、可利用的漏洞
4. 给出漏洞严重度评估（critical/high/medium/low/info）

输出 JSON 格式：
{
  "is_real_vulnerability": true/false,
  "confidence": 0.0-1.0,
  "attack_evidence": ["证据1", "证据2"],
  "enhanced_payloads": [{"method":"GET","path":"/xxx","body":null,"headers":{},"expected_result":"..."}],
  "severity": "high",
  "exploit_scenario": "攻击场景描述"
}"""

DEFENDER_SYSTEM_PROMPT = """你是一位资深 Blue Team 安全防御专家。你的任务是：
1. 分析给定的疑似漏洞的 HTTP 请求和响应
2. 从防御角度反驳：为什么这可能不是真正的漏洞
3. 分析响应是否可能是正常业务逻辑的预期行为
4. 判断是否存在误报的可能性

输出 JSON 格式：
{
  "is_false_positive": true/false,
  "confidence": 0.0-1.0,
  "defense_arguments": ["防御论据1", "防御论据2"],
  "alternative_explanation": "对响应行为的替代解释",
  "suggested_verification": "建议的进一步验证方法",
  "recommended_severity": "critical/high/medium/low/info/none"
}"""

JUDGE_SYSTEM_PROMPT = """你是一位中立的网络安全裁决专家。根据攻击方和防御方的论证，做出最终判决。

输出 JSON 格式：
{
  "final_verdict": "confirmed" | "downgraded" | "false_positive",
  "final_severity": "critical"|"high"|"medium"|"low"|"info",
  "reasoning": "判决理由",
  "attacker_strength": 0.0-1.0,
  "defender_strength": 0.0-1.0
}

判决标准：
- confirmed: 攻击方证据确凿，漏洞真实存在 → 保留
- downgraded: 漏洞存在但严重度被高估 → 降级保留
- false_positive: 防御方论证有力，系误报 → 丢弃"""


# ---------------------------------------------------------------------------
# 核心验证逻辑
# ---------------------------------------------------------------------------


def _build_case_context(vuln: dict, index: int) -> str:
    """构建给 AI Agent 看的漏洞案例上下文。"""
    parts = [
        f"### 疑似漏洞 #{index + 1}",
        f"- 漏洞类型: {vuln.get('vulnerability_type', 'unknown')}",
        f"- 当前严重度: {vuln.get('severity', 'medium')}",
        f"- 端点: {vuln.get('method', 'GET')} {vuln.get('path', '/')}",
    ]

    # 请求信息
    req = vuln.get("payload", {})
    parts.append(f"\n**请求:**")
    parts.append(f"- Method: {req.get('method', 'GET')}")
    parts.append(f"- Path: {req.get('path', '/')}")
    if req.get("injected_data"):
        injected = req["injected_data"]
        if isinstance(injected, dict):
            parts.append(f"- Payload: {json.dumps(injected, ensure_ascii=False)[:500]}")
        else:
            parts.append(f"- Payload: {str(injected)[:500]}")
    if req.get("headers"):
        parts.append(f"- Headers: {json.dumps(req['headers'], ensure_ascii=False)[:300]}")

    # 响应信息
    parts.append(f"\n**响应:**")
    parts.append(f"- 状态码: {vuln.get('status_code', 0)}")
    resp_text = (vuln.get('response_text', '') or '')[:1500]
    parts.append(f"- 响应体 (截取):\n```\n{resp_text}\n```")

    # 原始攻击理由
    if vuln.get("reason"):
        parts.append(f"\n**AI 攻击理由:** {vuln['reason'][:300]}")

    return "\n".join(parts)


def _call_agent(system_prompt: str, user_message: str) -> dict:
    """调用 LLM Agent 并解析 JSON 响应。"""
    try:
        provider = get_cached_provider()
    except Exception:
        logger.warning("对抗验证: LLM 不可用，跳过")
        return {}

    try:
        response = provider.chat(
            system_prompt=system_prompt,
            user_prompt=user_message,
            temperature=0.3,  # 低温度，更确定性的判断
            max_tokens=1000,
        )
    except Exception as e:
        logger.warning("对抗验证 Agent 调用失败: %s", e)
        return {}

    # 复用稳健的 JSON 解析（兼容代码围栏、前后文字、轻微格式错误）
    try:
        return extract_json(response)
    except ValueError as e:
        logger.debug("对抗验证 JSON 解析失败: %s", e)
        return {}


def _make_verdict(vuln: dict, attacker_result: dict, defender_result: dict) -> dict:
    """根据攻防双方论证做出最终判决。"""
    att_conf = attacker_result.get("confidence", 0)
    def_conf = defender_result.get("confidence", 0)
    att_real = attacker_result.get("is_real_vulnerability", True)
    def_fp = defender_result.get("is_false_positive", False)

    # 规则 1: 双方都认为不是漏洞 → 误报
    if not att_real and def_fp:
        return {"verdict": "false_positive", "severity": "info",
                "reason": "攻击方和防御方都认为这不是真实漏洞"}

    # 规则 2: 防御方信心很强，攻击方信心弱 → 误报
    if def_fp and def_conf > 0.7 and att_conf < 0.5:
        return {"verdict": "false_positive", "severity": "info",
                "reason": "防御方有强证据表明为误报"}

    # 规则 3: 攻击方信心很强，防御方信心弱 → 确认
    if att_real and att_conf > 0.7 and (not def_fp or def_conf < 0.3):
        return {"verdict": "confirmed", "severity": attacker_result.get("severity", vuln.get("severity", "medium")),
                "reason": "攻击方证据确凿，防御方未能有效反驳"}

    # 规则 4: 双方都中等信心 → 使用 Judge Agent 终裁
    if att_conf > 0.3 and def_conf > 0.3:
        return {"verdict": "needs_judge", "severity": vuln.get("severity", "medium"),
                "reason": "双方论证存在争议，需要裁判 Agent 终裁"}

    # 规则 5: 攻击方略强 → 降级确认
    if att_conf > def_conf:
        def_severity = defender_result.get("recommended_severity", vuln.get("severity", "medium"))
        return {"verdict": "downgraded", "severity": def_severity,
                "reason": "漏洞存在但严重度下调"}

    # 默认：保守保留
    return {"verdict": "confirmed", "severity": vuln.get("severity", "medium"),
            "reason": "默认保留，需人工审查"}


def adversarial_verify(vulnerabilities: list, max_verify: int = 15) -> dict:
    """对抗式验证入口：对疑似漏洞列表进行攻防交叉验证。

    Args:
        vulnerabilities: 疑似漏洞列表
        max_verify: 最多验证的漏洞数（控制 token 消耗）

    Returns:
        {
            "verified_vulns": [...],      # 验证后确认/降级的漏洞
            "false_positives": [...],     # 被判定为误报的漏洞
            "stats": { confirmed, downgraded, false_positive, skipped },
        }
    """
    if not vulnerabilities:
        return {"verified_vulns": [], "false_positives": [],
                "stats": {"confirmed": 0, "downgraded": 0, "false_positive": 0, "skipped": 0}}

    # 只验证高危和严重漏洞（低危不做对抗验证，节省 token）
    high_risk = [v for v in vulnerabilities
                 if v.get("severity") in ("critical", "high")]
    medium_risk = [v for v in vulnerabilities
                   if v.get("severity") == "medium"]
    others = [v for v in vulnerabilities
              if v.get("severity") not in ("critical", "high", "medium")]

    to_verify = (high_risk + medium_risk)[:max_verify]
    skipped = len(high_risk) + len(medium_risk) - len(to_verify) + len(others)

    confirmed = []
    downgraded = []
    false_positives = []

    for i, vuln in enumerate(to_verify):
        try:
            context = _build_case_context(vuln, i)

            # Step 1: 攻击 Agent
            logger.info("对抗验证 [%d/%d]: 攻击 Agent 分析 %s", i + 1, len(to_verify),
                        vuln.get("vulnerability_type", "unknown"))
            attacker_result = _call_agent(ATTACKER_SYSTEM_PROMPT, context)

            # Step 2: 防御 Agent
            logger.info("对抗验证 [%d/%d]: 防御 Agent 分析 %s", i + 1, len(to_verify),
                        vuln.get("vulnerability_type", "unknown"))
            defender_result = _call_agent(DEFENDER_SYSTEM_PROMPT, context)

            if not attacker_result or not defender_result:
                # LLM 不可用时保留原漏洞
                confirmed.append(vuln)
                continue

            # Step 3: 判决
            verdict = _make_verdict(vuln, attacker_result, defender_result)

            # Step 4: 如有争议，调用 Judge Agent
            if verdict["verdict"] == "needs_judge":
                judge_context = f"""## 漏洞案例
{context}

## 攻击方论证
{json.dumps(attacker_result, ensure_ascii=False, indent=2)}

## 防御方论证
{json.dumps(defender_result, ensure_ascii=False, indent=2)}

请做出最终判决。"""
                judge_result = _call_agent(JUDGE_SYSTEM_PROMPT, judge_context)
                if judge_result:
                    verdict["verdict"] = judge_result.get("final_verdict", "confirmed")
                    verdict["severity"] = judge_result.get("final_severity", vuln.get("severity", "medium"))
                    verdict["reason"] = judge_result.get("reasoning", verdict["reason"])

            # 记录对抗信息
            vuln["adversarial_verification"] = {
                "attacker_confidence": attacker_result.get("confidence", 0),
                "defender_confidence": defender_result.get("confidence", 0),
                "verdict": verdict["verdict"],
                "reason": verdict["reason"],
            }

            if verdict["verdict"] == "false_positive":
                vuln["severity"] = "info"
                vuln["adversarial_verification"]["original_severity"] = vuln.get("severity", "medium")
                false_positives.append(vuln)
            elif verdict["verdict"] == "downgraded":
                vuln["severity"] = verdict["severity"]
                downgraded.append(vuln)
                confirmed.append(vuln)  # 降级后仍保留
            else:  # confirmed
                vuln["severity"] = verdict.get("severity", vuln.get("severity", "medium"))
                confirmed.append(vuln)

            logger.info("对抗验证 [%d/%d] 判决: %s (严重度: %s)",
                        i + 1, len(to_verify), verdict["verdict"], vuln["severity"])

        except Exception as e:
            logger.warning("对抗验证 [%d/%d] 异常: %s，保留原漏洞", i + 1, len(to_verify), e)
            confirmed.append(vuln)  # 异常时保留

    # 低危漏洞直接保留
    confirmed.extend(others)

    stats = {
        "confirmed": len([v for v in confirmed if v.get("adversarial_verification", {}).get("verdict") != "downgraded"]),
        "downgraded": len(downgraded),
        "false_positive": len(false_positives),
        "skipped": skipped,
        "total_verified": len(to_verify),
    }

    logger.info("对抗验证完成: 确认=%d 降级=%d 误报=%d 跳过=%d",
                stats["confirmed"], stats["downgraded"],
                stats["false_positive"], stats["skipped"])

    return {
        "verified_vulns": confirmed,
        "false_positives": false_positives,
        "stats": stats,
    }
