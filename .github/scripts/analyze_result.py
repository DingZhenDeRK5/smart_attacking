#!/usr/bin/env python3
"""
SmartAttack 扫描结果分析脚本
=============================
解析扫描结果 JSON，判断是否通过 CI/CD 质量门禁，生成 Markdown 报告。

用法:
    python analyze_result.py --input scan-result.json --fail-on high
"""

import argparse
import json
import sys
from datetime import datetime


SEVERITY_ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
SEVERITY_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🟢",
    "info": "🔵",
}


def main():
    parser = argparse.ArgumentParser(description="SmartAttack 结果分析")
    parser.add_argument("--input", required=True, help="扫描结果 JSON 文件")
    parser.add_argument("--fail-on", default="high",
                        choices=["critical", "high", "medium", "never"],
                        help="漏洞严重度阈值，达到即失败 (default: high)")
    parser.add_argument("--output-report", default="smartattack-report.md",
                        help="Markdown 报告输出路径")
    args = parser.parse_args()

    # 读取结果
    try:
        with open(args.input, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception as e:
        print(f"❌ 无法读取结果文件: {e}")
        sys.exit(1)

    scan = data.get("scan", data)
    scan_data = scan.get("data", scan)
    assessment = scan_data.get("security_assessment", {})

    # 提取漏洞
    vulns = assessment.get("vulnerabilities_found", [])
    score_info = assessment.get("smartattack_score", {})

    # 统计
    stats = {
        "total": len(vulns),
        "critical": len([v for v in vulns if v.get("severity") == "critical"]),
        "high": len([v for v in vulns if v.get("severity") == "high"]),
        "medium": len([v for v in vulns if v.get("severity") == "medium"]),
        "low": len([v for v in vulns if v.get("severity") == "low"]),
        "info": len([v for v in vulns if v.get("severity") == "info"]),
    }

    # ---- 生成 Markdown 报告 ----
    report_lines = [
        f"# 🛡️ SmartAttack API 安全扫描报告",
        f"",
        f"**生成时间:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"**扫描目标:** {scan.get('target_url', 'unknown')}",
        f"**扫描 ID:** {scan.get('scan_id', 'N/A')}",
        f"",
    ]

    # 安全评分
    if score_info:
        grade_emoji = {"A": "🟢", "B": "🟢", "C": "🟡", "D": "🟠", "F": "🔴"}
        emoji = grade_emoji.get(score_info.get("grade", "C"), "⚪")
        report_lines.extend([
            f"## 📊 SmartAttack Score: {score_info.get('score', 0)}/100 {emoji}",
            f"",
            f"**等级:** {score_info.get('grade', '?')} — {score_info.get('grade_label', '')}",
            f"",
        ])

    # 漏洞统计
    report_lines.extend([
        f"## 🔍 漏洞统计",
        f"",
        f"| 严重度 | 数量 |",
        f"|--------|------|",
        f"| 🔴 严重 | {stats['critical']} |",
        f"| 🟠 高危 | {stats['high']} |",
        f"| 🟡 中危 | {stats['medium']} |",
        f"| 🟢 低危 | {stats['low']} |",
        f"| 🔵 信息 | {stats['info']} |",
        f"| **总计** | **{stats['total']}** |",
        f"",
    ])

    # 漏洞详情
    if vulns:
        report_lines.append("## 🚨 漏洞详情")
        report_lines.append("")
        for i, v in enumerate(vulns[:20], 1):
            severity = v.get("severity", "medium")
            emoji = SEVERITY_EMOJI.get(severity, "⚪")
            report_lines.extend([
                f"### {i}. {emoji} {v.get('vulnerability_type', 'unknown').replace('_', ' ').title()}",
                f"",
                f"- **严重度:** {severity.upper()}",
                f"- **端点:** {v.get('method', 'GET')} {v.get('path', '/')}",
                f"- **CVSS:** {v.get('cvss_score', 'N/A')}",
                f"- **描述:** {v.get('description', v.get('reason', 'N/A'))[:200]}",
                f"",
            ])

    # 修复建议
    if score_info.get("recommendations"):
        report_lines.extend([
            "## 💡 修复建议",
            "",
        ])
        for rec in score_info.get("recommendations", []):
            report_lines.append(f"- {rec}")
        report_lines.append("")

    # 对抗验证信息
    adversarial = scan.get("adversarial_report", scan_data.get("adversarial_report", {}))
    if adversarial.get("stats"):
        ads = adversarial["stats"]
        report_lines.extend([
            "## 🔬 对抗验证统计",
            f"",
            f"- 确认漏洞: {ads.get('confirmed', 0)}",
            f"- 降级漏洞: {ads.get('downgraded', 0)}",
            f"- 误报过滤: {ads.get('false_positive', 0)}",
            f"",
        ])

    # 写入报告
    report_text = "\n".join(report_lines)
    with open(args.output_report, "w", encoding="utf-8") as fh:
        fh.write(report_text)

    # ---- CI/CD 质量门禁 ----
    fail_on_level = SEVERITY_ORDER.get(args.fail_on, 99)

    print(f"\n📊 扫描统计:")
    print(f"   漏洞总数: {stats['total']}")
    print(f"   严重: {stats['critical']}  高危: {stats['high']}  中危: {stats['medium']}")
    if score_info:
        print(f"   SmartAttack Score: {score_info.get('score', '?')}/100 ({score_info.get('grade', '?')})")
    print(f"   质量门禁: fail-on >= {args.fail_on}")

    # 检查是否失败
    failed = False
    for severity, count in stats.items():
        level = SEVERITY_ORDER.get(severity, 0)
        if level >= fail_on_level and count > 0:
            print(f"   ❌ 发现 {severity.upper()} 漏洞 {count} 个 — CI/CD 门禁不通过！")
            failed = True

    if not failed:
        print(f"   ✅ 未发现 {args.fail_on.upper()} 及以上漏洞，CI/CD 门禁通过！")
    else:
        print(f"\n💡 请优先修复高危和严重漏洞后重新提交。")
        print(f"   报告已生成: {args.output_report}")
        sys.exit(1)

    print(f"\n📄 报告已生成: {args.output_report}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
