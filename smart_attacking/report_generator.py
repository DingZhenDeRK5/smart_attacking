"""
智攻 (SmartAttack) — PDF 报告生成器（中文版）
==============================================
基于 reportlab 生成专业中文安全测试报告。

修复内容：
- 注册系统中文字体（微软雅黑/黑体/宋体 fallback），消除黑色方块
- 全部文案中文化
- 封面排版优化
"""

import json
import logging
import os
from datetime import datetime
from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

logger = logging.getLogger("smart_attack.report_generator")

# ======================================================================
# 中文字体注册
# ======================================================================
_FONT_REGISTERED = False
_CN_FONT = "Helvetica"           # 正文（fallback）
_CN_FONT_BOLD = "Helvetica-Bold" # 粗体（fallback）


def _register_chinese_fonts():
    """扫描系统中文字体并注册到 ReportLab。"""
    global _FONT_REGISTERED, _CN_FONT, _CN_FONT_BOLD

    if _FONT_REGISTERED:
        return

    # Windows / Linux / macOS 常见中文字体路径
    candidates = [
        # 微软雅黑（首选，现代美观）
        ("C:/Windows/Fonts/msyh.ttc", "C:/Windows/Fonts/msyhbd.ttc"),
        ("C:/Windows/Fonts/msyh.ttf", "C:/Windows/Fonts/msyhbd.ttf"),
        # 黑体
        ("C:/Windows/Fonts/simhei.ttf", "C:/Windows/Fonts/simhei.ttf"),
        # macOS
        ("/System/Library/Fonts/PingFang.ttc", "/System/Library/Fonts/PingFang.ttc"),
        ("/Library/Fonts/Arial Unicode.ttf", "/Library/Fonts/Arial Unicode.ttf"),
        # Linux
        ("/usr/share/fonts/truetype/droid/DroidSansFallbackFull.ttf",
         "/usr/share/fonts/truetype/droid/DroidSansFallbackFull.ttf"),
        ("/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
         "/usr/share/fonts/opentype/noto/NotoSansCJK-Bold.ttc"),
        ("/usr/share/fonts/truetype/wqy/wqy-zenhei.ttc",
         "/usr/share/fonts/truetype/wqy/wqy-zenhei.ttc"),
    ]

    for regular_path, bold_path in candidates:
        if os.path.isfile(regular_path):
            try:
                pdfmetrics.registerFont(TTFont("SmartCN", regular_path, subfontIndex=0))
                _CN_FONT = "SmartCN"
                _CN_FONT_BOLD = "SmartCN"
                # 尝试注册粗体
                if os.path.isfile(bold_path) and bold_path != regular_path:
                    try:
                        pdfmetrics.registerFont(TTFont("SmartCNBold", bold_path, subfontIndex=0))
                        _CN_FONT_BOLD = "SmartCNBold"
                    except Exception:
                        pass
                _FONT_REGISTERED = True
                logger.info("中文字体注册成功: %s", regular_path)
                return
            except Exception as e:
                logger.debug("字体 %s 注册失败: %s", regular_path, e)

    # 全部失败
    _FONT_REGISTERED = True  # 避免反复尝试
    logger.warning("未找到中文字体，PDF 中文字符可能显示为方块！")


# ======================================================================
# 颜色常量
# ======================================================================
COLOR_CRITICAL = colors.HexColor("#8B0000")
COLOR_HIGH = colors.HexColor("#DC2626")
COLOR_MEDIUM = colors.HexColor("#D97706")
COLOR_LOW = colors.HexColor("#059669")
COLOR_INFO = colors.HexColor("#0891B2")
COLOR_ACCENT = colors.HexColor("#3B82F6")
COLOR_DARK = colors.HexColor("#1E293B")
COLOR_GRAY = colors.HexColor("#64748B")
COLOR_LIGHT_BG = colors.HexColor("#F1F5F9")
COLOR_WHITE = colors.white

SEVERITY_COLORS = {
    "critical": COLOR_CRITICAL,
    "high": COLOR_HIGH,
    "medium": COLOR_MEDIUM,
    "low": COLOR_LOW,
    "info": COLOR_INFO,
}

# 严重等级中文标签
SEVERITY_LABELS_ZH = {
    "critical": "严重",
    "high": "高危",
    "medium": "中危",
    "low": "低危",
    "info": "信息",
}

# 防御水平中文标签
DEFENSE_LABELS_ZH = {
    "none": "无防护",
    "weak": "弱防护",
    "moderate": "中等防护",
    "strong": "强防护",
}

# 判定中文标签
VERDICT_LABELS_ZH = {
    "hit": "命中",
    "partial": "部分命中",
    "miss": "未命中",
    "error": "错误",
}


def _severity_color(severity: str):
    return SEVERITY_COLORS.get(severity, COLOR_GRAY)


def _sev_label(severity: str) -> str:
    return SEVERITY_LABELS_ZH.get(severity, severity)


# ======================================================================
# 样式定义
# ======================================================================
def _build_styles():
    _register_chinese_fonts()

    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        "CoverTitle", parent=styles["Title"],
        fontName=_CN_FONT_BOLD, fontSize=26, textColor=COLOR_DARK,
        alignment=TA_CENTER, spaceAfter=8, leading=36,
    ))
    styles.add(ParagraphStyle(
        "CoverSubtitle", parent=styles["Normal"],
        fontName=_CN_FONT, fontSize=12, textColor=COLOR_GRAY,
        alignment=TA_CENTER, spaceAfter=6, leading=18,
    ))
    styles.add(ParagraphStyle(
        "SectionH1", parent=styles["Heading1"],
        fontName=_CN_FONT_BOLD, fontSize=16, textColor=COLOR_DARK,
        spaceBefore=14, spaceAfter=8, leading=24,
    ))
    styles.add(ParagraphStyle(
        "SectionH2", parent=styles["Heading2"],
        fontName=_CN_FONT_BOLD, fontSize=13, textColor=COLOR_DARK,
        spaceBefore=10, spaceAfter=6, leading=20,
    ))
    styles.add(ParagraphStyle(
        "SectionH3", parent=styles["Heading3"],
        fontName=_CN_FONT_BOLD, fontSize=11, textColor=COLOR_DARK,
        spaceBefore=8, spaceAfter=4, leading=16,
    ))
    styles.add(ParagraphStyle(
        "BodyText2", parent=styles["Normal"],
        fontName=_CN_FONT, fontSize=10, textColor=COLOR_DARK, leading=16,
    ))
    styles.add(ParagraphStyle(
        "Meta", parent=styles["Normal"],
        fontName=_CN_FONT, fontSize=9, textColor=COLOR_GRAY, leading=14,
    ))
    styles.add(ParagraphStyle(
        "RatingBig", fontName=_CN_FONT_BOLD, fontSize=48, alignment=TA_CENTER,
        leading=56,
    ))
    return styles


# ======================================================================
# 页面模板回调
# ======================================================================
def _page_header_footer(canvas, doc):
    canvas.saveState()

    # 页眉
    canvas.setFont(_CN_FONT_BOLD if _FONT_REGISTERED else "Helvetica-Bold", 8)
    canvas.setFillColor(COLOR_ACCENT)
    canvas.drawString(2 * cm, A4[1] - 1.5 * cm, "SmartAttack 安全测试报告")

    canvas.setFont(_CN_FONT if _FONT_REGISTERED else "Helvetica", 7)
    canvas.setFillColor(COLOR_GRAY)
    canvas.drawRightString(A4[0] - 2 * cm, A4[1] - 1.5 * cm, "机密")

    # 页脚分割线
    canvas.setStrokeColor(COLOR_LIGHT_BG)
    canvas.setLineWidth(0.5)
    canvas.line(2 * cm, 2 * cm, A4[0] - 2 * cm, 2 * cm)

    # 页码
    canvas.setFont(_CN_FONT if _FONT_REGISTERED else "Helvetica", 7)
    canvas.setFillColor(COLOR_GRAY)
    canvas.drawCentredString(A4[0] / 2, 1.3 * cm, f"第 {doc.page} 页")

    canvas.restoreState()


# ======================================================================
# 公开 API
# ======================================================================
def generate_pdf_report(scan_record: dict) -> bytes:
    """根据扫描记录生成中文 PDF 报告。

    Args:
        scan_record: get_scan() 返回的扫描记录字典

    Returns:
        PDF 文件的字节数据
    """
    _register_chinese_fonts()

    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=2 * cm,
        rightMargin=2 * cm,
        topMargin=2.5 * cm,
        bottomMargin=2.5 * cm,
    )
    styles = _build_styles()
    story = []

    # ---- 解析数据 ----
    data = scan_record.get("data", scan_record)
    scan_id = scan_record.get("scan_id", "unknown")
    target_url = scan_record.get("target_url", data.get("target_url", "unknown"))
    created_at = scan_record.get("created_at", "")
    stats = scan_record.get("stats", data.get("stats", {}))
    security_assessment = data.get("security_assessment", {})
    business_analysis = data.get("business_analysis", {})
    result_analysis = data.get("result_analysis", {})
    execution_results = data.get("execution_results", [])
    followup_execution = data.get("followup_execution", [])

    overall_rating = security_assessment.get("overall_rating", "unknown").lower()
    rating_color = (
        COLOR_HIGH if overall_rating == "high"
        else COLOR_MEDIUM if overall_rating == "medium"
        else COLOR_LOW
    )
    rating_zh = {"high": "高危", "medium": "中危", "low": "低危"}.get(overall_rating, "未知")

    # ==================================================================
    # 封面
    # ==================================================================
    story.append(Spacer(1, 2.5 * cm))

    # 标题
    story.append(Paragraph("SmartAttack", styles["CoverTitle"]))
    story.append(Paragraph("智攻 — API 自动化渗透测试系统", styles["CoverSubtitle"]))
    story.append(Spacer(1, 0.8 * cm))
    story.append(Paragraph("安全评估报告", styles["CoverTitle"]))
    story.append(Spacer(1, 1.5 * cm))

    # 评级
    story.append(Paragraph(
        f'<font size="48" color="{rating_color}"><b>{rating_zh}</b></font>',
        styles["RatingBig"],
    ))
    story.append(Paragraph("综合安全评级", styles["CoverSubtitle"]))
    story.append(Spacer(1, 1.8 * cm))

    # 元信息
    short_url = target_url if len(target_url) <= 60 else target_url[:57] + "..."
    meta_data = [
        ["目标地址", short_url],
        ["扫描编号", scan_id],
        ["扫描时间", created_at[:19] if created_at else "N/A"],
        ["使用模型", scan_record.get("model_used", stats.get("ai_model", "N/A"))],
    ]
    meta_table = Table(meta_data, colWidths=[3.5 * cm, 10.5 * cm])
    meta_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), _CN_FONT_BOLD),
        ("FONTNAME", (1, 0), (1, -1), _CN_FONT),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("TEXTCOLOR", (0, 0), (0, -1), COLOR_DARK),
        ("TEXTCOLOR", (1, 0), (1, -1), COLOR_GRAY),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("ALIGN", (0, 0), (0, -1), "RIGHT"),
        ("RIGHTPADDING", (0, 0), (0, -1), 8),
    ]))
    story.append(meta_table)

    story.append(Spacer(1, 2 * cm))
    story.append(Paragraph(
        f'<font size="9" color="{COLOR_GRAY}">本报告由 SmartAttack AI 引擎自动生成 · 仅供参考</font>',
        ParagraphStyle("Disclaimer", fontName=_CN_FONT, fontSize=9,
                       textColor=COLOR_GRAY, alignment=TA_CENTER, leading=14),
    ))
    story.append(PageBreak())

    # ==================================================================
    # 1. 执行摘要
    # ==================================================================
    story.append(Paragraph("一、执行摘要", styles["SectionH1"]))

    summary_text = security_assessment.get("summary",
                    result_analysis.get("summary", "暂无摘要信息。"))
    defense_level = result_analysis.get("defense_level", "unknown")
    defense_zh = DEFENSE_LABELS_ZH.get(defense_level, defense_level)
    vulns_found = _extract_vulns(security_assessment, result_analysis, scan_record)

    story.append(Paragraph(f"<b>评估结论：</b>{summary_text}", styles["BodyText2"]))
    story.append(Spacer(1, 0.5 * cm))

    # 统计表
    stats_data = [
        ["统计项", "数值"],
        ["第一阶段生成攻击方案", str(stats.get("phase1_plan_count", 0)) + " 组"],
        ["第一阶段执行攻击请求", str(stats.get("phase1_executed", 0)) + " 次"],
        ["第二阶段后续攻击方案", str(stats.get("phase2_plan_count", 0)) + " 组"],
        ["第二阶段执行攻击请求", str(stats.get("phase2_executed", 0)) + " 次"],
        ["确认漏洞数量", str(len(vulns_found)) + " 个"],
        ["目标防御水平", defense_zh],
        ["综合安全评级", rating_zh],
    ]
    stats_table = Table(stats_data, colWidths=[7 * cm, 7 * cm])
    stats_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), COLOR_DARK),
        ("TEXTCOLOR", (0, 0), (-1, 0), COLOR_WHITE),
        ("FONTNAME", (0, 0), (-1, 0), _CN_FONT_BOLD),
        ("FONTNAME", (0, 1), (-1, -1), _CN_FONT),
        ("FONTNAME", (0, 1), (0, -1), _CN_FONT_BOLD),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [COLOR_WHITE, COLOR_LIGHT_BG]),
        ("GRID", (0, 0), (-1, -1), 0.5, COLOR_LIGHT_BG),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(stats_table)
    story.append(PageBreak())

    # ==================================================================
    # 2. 漏洞详情
    # ==================================================================
    story.append(Paragraph("二、漏洞详情", styles["SectionH1"]))

    if vulns_found:
        story.append(Paragraph(
            f"本次扫描共确认 <font color='{COLOR_HIGH}'><b>{len(vulns_found)}</b></font> 个漏洞，详情如下：",
            styles["BodyText2"],
        ))
        story.append(Spacer(1, 0.4 * cm))
        for i, vuln in enumerate(vulns_found, 1):
            _add_vuln_detail(story, styles, i, vuln)
            if i < len(vulns_found):
                story.append(Spacer(1, 0.3 * cm))
    else:
        story.append(Paragraph("本次扫描未确认任何漏洞。", styles["BodyText2"]))

    story.append(PageBreak())

    # ==================================================================
    # 3. OWASP Top 10 映射
    # ==================================================================
    story.append(Paragraph("三、OWASP Top 10 (2021) 覆盖情况", styles["SectionH1"]))
    _add_owasp_section(story, styles, vulns_found)
    story.append(PageBreak())

    # ==================================================================
    # 4. 攻击执行汇总
    # ==================================================================
    story.append(Paragraph("四、攻击执行汇总", styles["SectionH1"]))
    all_exec = list(execution_results) + list(followup_execution)
    _add_execution_table(story, styles, all_exec)
    story.append(PageBreak())

    # ==================================================================
    # 5. 业务分析（附录）
    # ==================================================================
    if business_analysis:
        story.append(Paragraph("五、附录：业务逻辑分析", styles["SectionH1"]))
        _add_business_analysis_appendix(story, styles, business_analysis)

    # ==================================================================
    # 6. 修复建议
    # ==================================================================
    remediation = security_assessment.get("remediation_advice", "")
    if remediation:
        story.append(Spacer(1, 0.5 * cm))
        story.append(Paragraph("六、修复建议", styles["SectionH1"]))
        story.append(Paragraph(remediation, styles["BodyText2"]))

    # ---- 生成 PDF ----
    doc.build(story, onFirstPage=_page_header_footer, onLaterPages=_page_header_footer)
    pdf_bytes = buffer.getvalue()
    buffer.close()

    logger.info("PDF 中文报告已生成: %s (%d bytes)", scan_id, len(pdf_bytes))
    return pdf_bytes


def build_report_data(scan_record: dict) -> dict:
    """将扫描记录转换为结构化报告数据（JSON 格式，供前端预览）。"""
    data = scan_record.get("data", scan_record)
    security_assessment = data.get("security_assessment", {})
    result_analysis = data.get("result_analysis", {})
    business_analysis = data.get("business_analysis", {})

    vulns_found = _extract_vulns(security_assessment, result_analysis, scan_record)

    try:
        from owasp import get_owasp_summary
    except ImportError:
        from .owasp import get_owasp_summary
    owasp_summary = get_owasp_summary(vulns_found)

    return {
        "scan_id": scan_record.get("scan_id", ""),
        "target_url": scan_record.get("target_url", data.get("target_url", "")),
        "created_at": scan_record.get("created_at", ""),
        "overall_rating": security_assessment.get("overall_rating", "unknown"),
        "summary": security_assessment.get("summary", result_analysis.get("summary", "")),
        "defense_level": result_analysis.get("defense_level", "unknown"),
        "stats": scan_record.get("stats", data.get("stats", {})),
        "vulnerabilities": vulns_found,
        "owasp_coverage": {k: {"name": v["name"], "name_zh": v["name_zh"], "count": v["count"]}
                           for k, v in owasp_summary.items()},
        "remediation_advice": security_assessment.get("remediation_advice", ""),
        "business_analysis_domain": business_analysis.get("domain", ""),
        "model_used": scan_record.get("model_used", ""),
    }


# ======================================================================
# 内部辅助 — 漏洞详情
# ======================================================================
def _add_vuln_detail(story, styles, index: int, vuln: dict):
    """添加单个漏洞的详情区域。"""
    severity = vuln.get("severity", "medium")
    vuln_type = vuln.get("vulnerability_type", vuln.get("vuln_type", "unknown"))
    owasp = vuln.get("owasp_category", "N/A")
    cvss = vuln.get("cvss_score", "N/A")
    endpoint = vuln.get("endpoint", "N/A")
    finding = vuln.get("finding", vuln.get("description", "暂无描述"))
    recommendation = vuln.get("recommendation", "暂无修复建议")

    sev_color = _severity_color(severity)
    sev_zh = _sev_label(severity)

    # 漏洞类型中文映射
    vuln_type_zh = {
        "bola": "越权访问 (BOLA/IDOR)",
        "idor": "越权访问 (IDOR)",
        "privilege_escalation": "权限提升",
        "auth_bypass": "认证绕过",
        "mass_assignment": "批量赋值",
        "param_tampering": "参数篡改",
        "logic_bypass": "业务逻辑绕过",
        "info_leak": "信息泄露",
        "injection": "注入攻击",
        "sql_injection": "SQL 注入",
        "command_injection": "命令注入",
        "ssrf": "服务端请求伪造 (SSRF)",
        "jwt_weakness": "JWT/Token 弱点",
        "brute_force": "暴力破解",
        "security_misconfig": "安全配置错误",
        "unknown": "未知类型",
    }.get(vuln_type, vuln_type.replace("_", " ").title())

    # 标题行
    title = (
        f'<b>#{index}</b> &nbsp; '
        f'<font color="{sev_color}">[{sev_zh}]</font> &nbsp; '
        f'{vuln_type_zh}'
    )
    story.append(Paragraph(title, styles["SectionH2"]))

    # 元信息
    meta_parts = []
    meta_parts.append(f"<b>OWASP:</b> {owasp}")
    meta_parts.append(f"<b>CVSS:</b> {cvss}")
    meta_parts.append(f"<b>端点:</b> {endpoint}")
    story.append(Paragraph(" &nbsp;|&nbsp; ".join(meta_parts), styles["Meta"]))
    story.append(Spacer(1, 0.2 * cm))

    # 发现描述
    story.append(Paragraph("<b>漏洞描述：</b>", styles["SectionH3"]))
    story.append(Paragraph(finding, styles["BodyText2"]))

    # 修复建议
    story.append(Paragraph("<b>修复建议：</b>", styles["SectionH3"]))
    story.append(Paragraph(recommendation, styles["BodyText2"]))

    # 分隔线
    story.append(Spacer(1, 0.3 * cm))
    story.append(Table([[""]], colWidths=[A4[0] - 4 * cm], style=[
        ("LINEBELOW", (0, 0), (0, 0), 0.5, COLOR_LIGHT_BG),
    ]))


def _add_owasp_section(story, styles, vulns_found: list):
    """添加 OWASP Top 10 覆盖汇总表。"""
    try:
        from owasp import get_owasp_summary
    except ImportError:
        from .owasp import get_owasp_summary

    owasp = get_owasp_summary(vulns_found)

    if not owasp:
        story.append(Paragraph("未映射到 OWASP 分类（未发现漏洞）。", styles["BodyText2"]))
        return

    story.append(Paragraph(
        "下表展示了本次扫描发现的漏洞在 OWASP Top 10 (2021) 框架中的分布：",
        styles["BodyText2"],
    ))
    story.append(Spacer(1, 0.3 * cm))

    data = [["OWASP 编号", "分类名称", "数量"]]
    for cat_id in sorted(owasp.keys()):
        info = owasp[cat_id]
        data.append([cat_id, f"{info['name']}（{info['name_zh']}）", str(info["count"])])

    table = Table(data, colWidths=[3 * cm, 8 * cm, 3 * cm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), COLOR_DARK),
        ("TEXTCOLOR", (0, 0), (-1, 0), COLOR_WHITE),
        ("FONTNAME", (0, 0), (-1, 0), _CN_FONT_BOLD),
        ("FONTNAME", (0, 1), (-1, -1), _CN_FONT),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [COLOR_WHITE, COLOR_LIGHT_BG]),
        ("GRID", (0, 0), (-1, -1), 0.5, COLOR_LIGHT_BG),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(table)


def _add_execution_table(story, styles, results: list):
    """添加攻击执行结果汇总表。"""
    if not results:
        story.append(Paragraph("本次扫描未记录攻击执行结果。", styles["BodyText2"]))
        return

    data = [["序号", "方法", "路径", "状态码", "判定"]]
    for i, r in enumerate(results, 1):
        method = r.get("payload", {}).get("method", r.get("method", "GET"))
        path = r.get("payload", {}).get("path", r.get("path", "/"))
        code = str(r.get("status_code", "N/A"))
        sc = r.get("status_code", 0)
        if sc == 0:
            verdict = "错误"
        elif 200 <= sc < 300:
            verdict = "命中"
        elif sc >= 500:
            verdict = "错误"
        else:
            verdict = "未命中"
        data.append([str(i), method, path[:70], code, verdict])

    col_widths = [1.2 * cm, 1.8 * cm, 7.5 * cm, 1.8 * cm, 2 * cm]
    table = Table(data, colWidths=col_widths)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), COLOR_DARK),
        ("TEXTCOLOR", (0, 0), (-1, 0), COLOR_WHITE),
        ("FONTNAME", (0, 0), (-1, 0), _CN_FONT_BOLD),
        ("FONTNAME", (0, 1), (-1, -1), _CN_FONT),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("FONTNAME", (2, 1), (2, -1), "Courier"),
        ("FONTSIZE", (2, 1), (2, -1), 7),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [COLOR_WHITE, COLOR_LIGHT_BG]),
        ("GRID", (0, 0), (-1, -1), 0.5, COLOR_LIGHT_BG),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(table)


def _add_business_analysis_appendix(story, styles, analysis: dict):
    """附录：业务分析摘要。"""
    domain = analysis.get("domain", "N/A")
    auth_model = analysis.get("auth_model", "N/A")
    summary = analysis.get("attack_surface_summary", "")

    story.append(Paragraph(f"<b>业务领域：</b>{domain}", styles["BodyText2"]))
    story.append(Paragraph(f"<b>鉴权模型：</b>{auth_model}", styles["BodyText2"]))

    entities = analysis.get("entities", [])
    if entities:
        story.append(Spacer(1, 0.2 * cm))
        story.append(Paragraph("<b>核心实体：</b>", styles["SectionH3"]))
        for e in entities:
            name = e.get("name", "?")
            idp = e.get("id_pattern", "")
            story.append(Paragraph(
                f"  • {name} <font color='gray'>（ID模式: {idp}）</font>",
                styles["BodyText2"],
            ))

    vuln_surface = analysis.get("vulnerability_surface", [])
    if vuln_surface:
        story.append(Spacer(1, 0.2 * cm))
        story.append(Paragraph("<b>攻击面识别：</b>", styles["SectionH3"]))
        for v in vuln_surface:
            story.append(Paragraph(
                f"  • [{v.get('risk', 'UNKNOWN')}] {v.get('endpoint', '?')} — {v.get('detail', '')}",
                styles["BodyText2"],
            ))

    if summary:
        story.append(Spacer(1, 0.2 * cm))
        story.append(Paragraph(f"<b>攻击面总结：</b>{summary}", styles["BodyText2"]))


def _extract_vulns(security_assessment: dict, result_analysis: dict,
                   scan_record: dict) -> list:
    """从多个来源提取漏洞列表。"""
    vulns = security_assessment.get("vulnerabilities_found", [])
    if vulns:
        return vulns

    vulns = result_analysis.get("confirmed_vulnerabilities", [])
    if vulns:
        result = []
        for v in vulns:
            if isinstance(v, str):
                result.append({"vulnerability_type": "unknown", "finding": v})
            else:
                result.append(v)
        return result

    return []
