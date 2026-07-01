"""
智攻 (SmartAttack) — JSON 解析工具 v3.5
=======================================
从 AI 模型输出中稳健提取和规范化 JSON 数据。
v3.5: 增加 JSON Repair（自动修复常见 AI 输出格式错误）
"""

import json
import re
import logging

logger = logging.getLogger("smart_attack.parser")


def _repair_json(text: str) -> str:
    """尝试修复 AI 输出中常见的 JSON 格式错误。

    修复策略（由简到繁）：
    1. 移除尾随逗号（最常见错误）
    2. 修复缺失的逗号（两行之间）
    3. 修复未转义的控制字符
    4. 截断到最后一个完整的顶层键值对
    """
    # 1. 移除尾随逗号: "key": "value",   →  "key": "value"
    text = re.sub(r',(\s*[}\]])', r'\1', text)

    # 2. 修复缺失逗号: 在 "value"\n  "key" 之间插入逗号
    #    "some value"\n    "next_key": → "some value",\n    "next_key":
    text = re.sub(r'(["\d])\s*\n\s*"', r'\1,\n  "', text)

    # 3. 移除未转义的控制字符（保留 \n \t \r）
    # 将裸换行符替换为 \n（在字符串值内）
    # 这个比较复杂，采用保守策略：移除 JSON 字符串外的非法字符

    # 4. 如果 JSON 仍无效，尝试找到最后一个完整的键值对
    # 在最后一个有效的 }, 处截断
    try:
        json.loads(text)
        return text
    except json.JSONDecodeError as e:
        # 尝试在第 e.pos 附近修复
        pos = e.pos
        # 如果错误位置附近是多余字符，移除它们
        before = text[:pos]
        after = text[pos:]
        # 找到 after 中下一个 { 或 "，从那重新开始
        next_good = min(
            (after.find(c) for c in ['{', '"', ']'] if after.find(c) >= 0),
            default=-1
        )
        if next_good > 0:
            # 跳过错误字符
            text = before + after[next_good:]
        elif next_good == -1:
            # 从错误位置截断
            text = before.rstrip().rstrip(',')

    return text


def extract_json(raw: str):
    """从模型输出中稳健地解析出 JSON。

    兼容以下情况：
    - 直接是合法 JSON
    - 被 ```json ... ``` 代码块围栏包裹
    - JSON 前后混入了说明性文字
    - AI 产生的轻微 JSON 格式错误（尾随逗号、缺失逗号等）
    """
    text = (raw or "").strip()

    # 移除 markdown 代码围栏
    if "```" in text:
        text = re.sub(r"^```[a-zA-Z]*\n?", "", text)
        text = re.sub(r"\n?```$", "", text).strip()

    # 尝试 1: 直接解析
    try:
        return json.loads(text)
    except json.JSONDecodeError as e1:
        logger.debug("直接 JSON 解析失败: %s", e1)

    # 尝试 2: 提取 {...} 再解析
    start, end = text.find("{"), text.rfind("}")
    if start != -1 and end > start:
        snippet = text[start:end + 1]
        try:
            return json.loads(snippet)
        except json.JSONDecodeError as e2:
            logger.debug("花括号提取 JSON 也失败: %s", e2)

    # 尝试 3: 修复后再解析
    for repair_round in range(3):
        try:
            text = _repair_json(text)
            start, end = text.find("{"), text.rfind("}")
            if start != -1 and end > start:
                snippet = text[start:end + 1]
                return json.loads(snippet)
        except json.JSONDecodeError as e3:
            logger.debug("JSON 修复第 %d 轮失败: %s", repair_round + 1, e3)
        except Exception:
            break

    # 尝试 4: 最后手段 — 只提取第一个完整的顶层对象
    try:
        # 使用简单状态机找到第一个完整 JSON 对象
        depth = 0
        obj_start = -1
        for i, ch in enumerate(text):
            if ch == '{':
                if depth == 0:
                    obj_start = i
                depth += 1
            elif ch == '}':
                depth -= 1
                if depth == 0 and obj_start >= 0:
                    return json.loads(text[obj_start:i + 1])
        # 如果深度不为 0，说明 JSON 不完整，在最后补 }
        if obj_start >= 0 and depth > 0:
            patched = text[obj_start:] + ('}' * depth)
            return json.loads(patched)
    except json.JSONDecodeError:
        pass

    # 最后记录原始文本前 500 字符用于调试
    logger.error("JSON 解析彻底失败。原始文本前 500 字符:\n%s", (raw or "")[:500])
    raise ValueError("无法从模型输出中解析出合法的 JSON")


def chat_json(provider, system_prompt: str, user_prompt: str, *,
              temperature: float = 0.3, max_tokens: int = 8000,
              retries: int = 2) -> dict:
    """调用 LLM 并稳健解析 JSON，解析失败自动重试。

    这是消除"时多时少"的核心：单次 JSON 格式抖动不再让整轮结果清零。
    每次失败后追加一句强约束提示再重试，最多 retries 次；全失败返回 {}。

    Args:
        provider: 任意实现了 chat(system_prompt, user_prompt, temperature, max_tokens) 的 Provider
        system_prompt / user_prompt: 提示词
        temperature / max_tokens: 透传给 provider.chat
        retries: 解析失败后的额外重试次数（默认 2，即最多请求 3 次）

    Returns:
        解析出的 dict；全部失败时返回空 dict（调用方应做降级处理）
    """
    cur_user = user_prompt
    last_raw = ""
    for attempt in range(retries + 1):
        try:
            raw = provider.chat(
                system_prompt=system_prompt,
                user_prompt=cur_user,
                temperature=temperature,
                max_tokens=max_tokens,
            )
        except Exception as e:
            logger.warning("chat_json: LLM 调用失败 (第 %d 次): %s", attempt + 1, e)
            continue

        last_raw = raw or ""
        try:
            return extract_json(raw)
        except ValueError:
            if attempt < retries:
                logger.warning(
                    "chat_json: 第 %d 次输出非合法 JSON，追加强约束后重试", attempt + 1
                )
                cur_user = (
                    user_prompt
                    + "\n\n## 严格要求\n你上一次的输出无法被解析为合法 JSON。"
                    "请只输出一个严格合法的 JSON 对象，不要任何解释文字、不要 markdown 代码围栏、不要尾随逗号。"
                )

    logger.error("chat_json: 重试 %d 次后仍无法解析 JSON，返回空结果。原始前300字符: %s",
                 retries + 1, last_raw[:300])
    return {}


def normalize_plans(parsed):
    """将模型输出统一成 list[plan]，并过滤掉缺少 request 字段的非法项。"""
    if isinstance(parsed, dict):
        for key in ("plans", "attacks", "data", "results", "attack_plans", "followup_attacks"):
            if isinstance(parsed.get(key), list):
                parsed = parsed[key]
                break
        else:
            parsed = [parsed]

    if not isinstance(parsed, list):
        raise ValueError("攻击方案必须是 JSON 数组")

    valid = [p for p in parsed if isinstance(p, dict) and isinstance(p.get("request"), dict)]
    if not valid:
        raise ValueError("模型未返回任何包含 request 字段的有效攻击方案")
    return valid
