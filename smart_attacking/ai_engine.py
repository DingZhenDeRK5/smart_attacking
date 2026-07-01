"""
智攻 (SmartAttack) — AI 分析引擎 v3.5
====================================
Phase 1: 业务逻辑分析 + 攻击方案生成（增强版：更激进、更全面）
Phase 3: 响应分析 + 后续攻击方案 + 安全评估
"""

import json
import logging

try:
    from models.llm_provider import create_llm_provider, get_cached_provider
    from parser import extract_json, normalize_plans, chat_json
except ImportError:
    from .models.llm_provider import create_llm_provider, get_cached_provider
    from .parser import extract_json, normalize_plans, chat_json

logger = logging.getLogger("smart_attack.ai_engine")

# ---- 默认 AI 客户端 ----
try:
    _default_provider = get_cached_provider()
    logger.info("AI 引擎已初始化: %s", _default_provider.model)
except Exception as e:
    logger.warning("AI 引擎初始化失败（将在首次调用时重试）: %s", e)
    _default_provider = None


def _resolve_provider(provider_override: str = None, model_override: str = None,
                     base_url_override: str = None):
    if provider_override or model_override or base_url_override:
        return create_llm_provider(
            provider=provider_override,
            model=model_override,
            base_url=base_url_override,
        )
    if _default_provider is not None:
        return _default_provider
    return get_cached_provider()


# ======================================================================
# Phase 1: AI 业务逻辑深度分析 + 攻击方案生成（增强版）
# ======================================================================


def analyze_and_generate_plans(swagger_content: str,
                               provider_override: str = None,
                               model_override: str = None,
                               base_url_override: str = None):
    """让 AI 深度分析 API 业务逻辑，并基于业务理解生成针对性攻击方案。"""
    provider = _resolve_provider(provider_override, model_override, base_url_override)

    system_prompt = """你是一个世界顶级的 API 渗透测试专家，专精于发现 Swagger 文档背后的真实漏洞。你的信条是：**文档只是表面，真实实现一定有意外**。

你的方法论：
1. **文档不可信** — Swagger 写的字段只是冰山一角。POST body 可以任意加字段，GET 返回值可能包含未文档化的敏感数据
2. **先探测再攻击** — 对每个端点先用最简单请求探测实际行为，根据响应调整攻击
3. **每个端点都是攻击面** — 不要跳过任何 GET/POST/PUT/DELETE，即使它看起来"无害"
4. **信息泄露是最常见的漏洞** — 未鉴权的 GET 端点往往会返回远超文档声明的数据
5. **批量赋值是第一优先级的攻击** — 任何 POST/PUT 都要尝试注入 role, admin, is_admin, credit, balance, permission, group 等权限字段"""

    user_prompt = f"""请深度分析以下 Swagger/OpenAPI 文档。你的工作是像一个真正的渗透测试者那样思考和攻击。

## 任务一：业务逻辑分析 → `business_analysis`

1. **业务领域判断**：这是什么系统？
2. **实体清单**：API 涉及哪些实体（User, Book, Order...），ID 是什么格式？
3. **鉴权缺口**：哪些端点标注了 security (bearerAuth)？哪些没有？没有标注的可能就是无需鉴权的！
4. **攻击面识别** — 针对每个端点逐一标注风险：
   - 对每个 GET 端点问：返回值会包含多少未在文档 Schema 中声明的字段？
   - 对每个 POST/PUT 端点问：如果我在 Body 中加 role, admin, credit 字段会发生什么？
   - 对带 {{path_param}} 的端点问：能遍历/枚举吗？
   - 对 DELETE 端点问：真的只有管理员能调用吗？
5. **攻击优先级排序**：哪些端点风险最高？

## 任务二：生成攻击方案 → `attack_plans`

**关键要求：必须生成至少 15 组攻击方案！每一个端点都不能跳过！**

你必须严格执行以下攻击策略，每组都必须不同：

### 策略 A：信息泄露探测（3~5 组）
对 **每个未标注 security 的 GET 端点**，发送不带 Token 的请求，观察响应：
- 响应中是否包含 password, secret, token, credit, role, admin, phone, address 等未在 Swagger Schema 中声明的敏感字段？
- 是否返回了所有用户的数据而不是当前用户的？
- 响应体是否比文档声称的更丰富？

### 策略 B：批量赋值攻击（3~4 组）
对 **每个 POST/PUT 端点**，在 Body 中注入未文档化的权限字段：
- 注入 "role": "admin"
- 注入 "admin": true, "is_admin": true
- 注入 "credit": 99999, "balance": 99999
- 注入 "secret_token": "...", "verified": true
- 同时发送正常字段 + 注入字段

### 策略 C：越权访问（3~4 组）
- 对带 {{path_param}} 的 GET/PUT/DELETE 端点，尝试枚举不同的 ID/username
- 不带 Token 调用标注了 security 的端点
- 尝试访问其他用户的资源（换 ID、换 username）

### 策略 D：暴力破解/弱密码（1~2 组）
- 对 login 端点尝试 admin/admin123, admin/password, test/test123 等常见组合
- 尝试空密码、SQL 注入 payload 作为密码

### 策略 E：方法替换/参数篡改（1~2 组）
- POST 改 GET、DELETE 改 GET
- 将必填参数设空或删除

## 输出格式（严格 JSON，无 markdown 围栏）：

{{
  "business_analysis": {{
    "domain": "系统类型",
    "entities": [{{ "name": "User", "id_pattern": "username 字符串" }}],
    "relationships": [{{ "from": "Book", "to": "User", "type": "belongs_to" }}],
    "auth_model": "描述哪些端点需要鉴权，哪些不需要",
    "trust_assumptions": ["开发者可能做了哪些不安全假设"],
    "vulnerability_surface": [
      {{ "endpoint": "/users/v1", "risk": "info_leak", "detail": "GET 无鉴权，可能返回密码等敏感字段" }}
    ],
    "attack_surface_summary": "一句话总结最大风险"
  }},
  "attack_plans": [
    {{
      "vulnerability_type": "info_leak",
      "reason": "GET /users/v1 端点没有标注 security，Swagger Schema 只声明返回 email 和 username，但实际后端很可能返回更多字段（password, role, credit 等）。直接不带 Token 请求，观察是否泄露敏感数据。",
      "expected_normal_behavior": "应该只返回公开的用户信息，不包含密码",
      "exploit_indicator": "响应中包含 password, secret_token, role, credit 等字段，或返回了超出 Schema 声明的数据",
      "request": {{
        "method": "GET",
        "url_path": "/users/v1",
        "headers": {{}},
        "query_params": null,
        "body": null
      }}
    }}
  ]
}}

## 待分析 API 文档：
{swagger_content}
"""

    parsed = chat_json(
        provider,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        temperature=0.3,   # 降温提升 run-to-run 一致性（覆盖面稳定）
        max_tokens=16000,  # 增大 token 上限确保生成足够的攻击方案
        retries=2,         # 解析失败自动重试，杜绝整轮 0 方案
    )

    business_analysis = parsed.get("business_analysis", {})
    attack_plans_raw = parsed.get("attack_plans", parsed.get("plans", []))

    if isinstance(attack_plans_raw, dict):
        attack_plans_raw = [attack_plans_raw]

    attack_plans = normalize_plans(attack_plans_raw)

    # 将 vulnerability_type 等字段保留到每个 plan 中
    enriched_plans = []
    for i, plan in enumerate(attack_plans):
        if i < len(attack_plans_raw) and isinstance(attack_plans_raw[i], dict):
            plan["vulnerability_type"] = attack_plans_raw[i].get("vulnerability_type", "unknown")
            plan["expected_normal_behavior"] = attack_plans_raw[i].get("expected_normal_behavior", "")
            plan["exploit_indicator"] = attack_plans_raw[i].get("exploit_indicator", "")
        enriched_plans.append(plan)

    logger.info("Phase 1 完成: %d 组攻击方案", len(enriched_plans))
    return business_analysis, enriched_plans


# ======================================================================
# Phase 3: AI 响应分析 + 后续攻击方案生成（增强版）
# ======================================================================


def analyze_results_and_followup(business_analysis, execution_results, swagger_content,
                                 provider_override: str = None,
                                 model_override: str = None,
                                 base_url_override: str = None):
    """让 AI 分析攻击执行结果 — 增强版：更精准的漏洞识别。"""
    provider = _resolve_provider(provider_override, model_override, base_url_override)

    # 智能筛选：优先发送有异常的结果给 AI 分析（节省 token + 避免输出过长导致 JSON 截断）
    # 规则引擎的结果不发送完整响应体（已由 exploit_indicator 自动判定）
    compact_results = []
    suspicious_first = []
    normal_results = []
    for r in execution_results:
        resp = r.get("response_text", "") or ""
        sc = r.get("status_code", 0)
        item = {
            "round": r.get("round", 0),
            "attack_type": r.get("vulnerability_type", "unknown"),
            "method": r.get("payload", {}).get("method", r.get("method", "GET")),
            "path": r.get("payload", {}).get("path", r.get("path", "/")),
            "payload": r.get("payload", {}).get("injected_data", ""),
            "status_code": sc,
            "elapsed_ms": r.get("elapsed_ms", 0),       # 时间盲注信号（>3000ms 高度可疑）
            "response_len": r.get("response_len", len(resp)),  # 响应体积信号
            "response_body": resp[:1800],  # 扩大窗口，确保命中证据不被截断
            "source": r.get("source", "ai"),
        }
        # 规则引擎的结果已有 exploit_indicator 自动判定，给较短但足够的摘要
        if r.get("source") == "rules_engine":
            item["response_body"] = resp[:600]
            item["auto_verdict"] = "hit" if (200 <= sc < 300 and "unauthorized" not in resp.lower()) else "check"

        if sc >= 500 or sc == 0:
            suspicious_first.append(item)
        elif sc >= 400 or sc == 200:
            suspicious_first.append(item)
        else:
            normal_results.append(item)

    # 优先发送可疑结果，限制总数避免 AI 输出过长
    compact_results = suspicious_first + normal_results
    # 最多 120 条送 AI 分析（覆盖所有命中 + 异常，避免有效证据被采样丢弃）
    compact_results = compact_results[:120]

    system_prompt = """你是一个世界顶级的渗透测试结果分析专家。你的任务是**从攻击响应中找出漏洞证据**。

关键判断标准：
1. **信息泄露判定**：响应中包含 password, secret, token, credit, role, phone, address, internal, debug, config, admin_panel, db_host, SECRET_KEY, DB_PASSWORD 等任一关键词 → 标记为信息泄露漏洞
2. **批量赋值成功判定**：响应返回的 user/order 对象中，包含了你在请求中注入的 role, admin, credit 等字段 → 标记为批量赋值漏洞
3. **越权成功判定**：不带 Token 或带错误 Token 访问了应该鉴权的端点，且返回了 200 和数据 → 标记为认证绕过
4. **IDOR 判定**：遍历不同 ID 成功获取了不同用户的资源 → 标记为越权漏洞
5. **即使状态码非 200（如 500 错误），如果响应中包含 SQL 错误、堆栈跟踪、内部路径 → 也标记为信息泄露**
6. **不要因为响应是"成功"的就忽略！成功响应中暴露的敏感数据才是最有价值的发现！**
7. **时间盲注判定**：注意每条结果的 elapsed_ms。如果一个注入了 SLEEP/pg_sleep/WAITFOR 等延时 payload 的请求 elapsed_ms 明显偏高（如 >3000ms），而正常请求只有几十毫秒 → 高度疑似时间盲注成功
8. **异常响应体积**：response_len 远大于同端点正常响应 → 可能批量返回了不该返回的数据"""

    user_prompt = f"""## 业务背景
{json.dumps(business_analysis, ensure_ascii=False, indent=2)[:2000]}

## 攻击执行结果（共 {len(compact_results)} 组）
{json.dumps(compact_results, ensure_ascii=False, indent=2)}

## 你的任务

### Part 1: 逐条分析 → `result_analysis.per_attack_analysis`
对每一条攻击结果，判断 verdict：
- **success**：攻击明确成功。响应中包含了：
  * 敏感数据（密码、token、密钥、内部配置等）
  * 被注入的权限字段（role: admin 等）
  * 本不该访问到的其他用户数据
  * SQL 错误或堆栈跟踪
- **partial**：响应泄露了部分有用信息（如用户枚举、内部 ID、路径结构）
- **failed**：未发现任何异常

### Part 2: 确认的漏洞 → `result_analysis.confirmed_vulnerabilities`
将所有 success 和值得关注的 partial 结果汇总为漏洞列表。每个漏洞至少包含 vulnerability_type, endpoint, finding 描述。

常见漏洞类型：info_leak, mass_assignment, bola, idor, auth_bypass, privilege_escalation, logic_bypass, injection

**重要：即使只有一个 success，也要在 confirmed_vulnerabilities 中列出！**

### Part 3: 泄露的信息 → `result_analysis.information_leaked`
列出响应中发现的所有敏感数据片段（截取关键部分即可）。

### Part 4: 防御评估 → `result_analysis.defense_level`
- **none**：所有端点都无需鉴权即可访问敏感数据
- **weak**：有基本鉴权但存在越权和信息泄露
- **moderate**：部分端点有防护但仍有可利用漏洞
- **strong**：大部分攻击被有效阻止

### Part 5: 后续攻击 → `followup_attacks`
基于第一轮发现，生成 3~5 组精炼攻击：
- 如果发现了信息泄露，尝试用泄露的 token/secret 访问鉴权端点
- 如果批量赋值成功，尝试提升到更高权限
- 如果某个端点有异常响应，深入挖掘
- 尝试组合攻击（先登录获取 token → 用 token 越权访问其他资源）

### Part 6: 安全评估 → `security_assessment`
- overall_rating: high（发现高危漏洞）/ medium / low
- vulnerabilities_found: 漏洞列表（与 Part 2 一致）
- remediation_advice: 针对性的修复建议

## 输出格式（严格 JSON，无 markdown 围栏）：
{{
  "result_analysis": {{
    "per_attack_analysis": [
      {{ "round": 1, "verdict": "success", "finding": "响应中包含所有用户的明文密码和角色信息", "why": "GET /users/v1 无需鉴权且返回了 password 和 role 字段" }}
    ],
    "confirmed_vulnerabilities": [
      {{ "vulnerability_type": "info_leak", "endpoint": "/users/v1", "finding": "未鉴权的 /users/v1 端点返回了所有用户的 password 和 secret_token" }}
    ],
    "information_leaked": ["所有用户密码明文", "内部 secret_token", "用户角色信息"],
    "defense_level": "weak",
    "summary": "发现了 3 个确认漏洞，系统安全评级为高危"
  }},
  "followup_attacks": [
    {{
      "vulnerability_type": "privilege_escalation",
      "reason": "已获取 admin 用户的密码，尝试登录后访问需要管理员权限的 DELETE /users/v1/{{username}} 接口",
      "expected_normal_behavior": "普通用户无法删除其他用户",
      "exploit_indicator": "成功删除指定用户",
      "request": {{
        "method": "DELETE",
        "url_path": "/users/v1/testuser",
        "headers": {{ "Authorization": "Bearer <obtained_token>" }},
        "query_params": null,
        "body": null
      }}
    }}
  ],
  "security_assessment": {{
    "overall_rating": "high",
    "vulnerabilities_found": [{{ "vulnerability_type": "info_leak", "endpoint": "/users/v1", "finding": "...", "recommendation": "..." }}],
    "remediation_advice": "1. 对所有端点添加鉴权... 2. 移除响应中的敏感字段..."
  }}
}}
"""

    parsed = chat_json(
        provider,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        temperature=0.2,  # 降温：漏洞判定需要可复现，而非创造性
        max_tokens=8000,  # 配合更大的证据窗口
        retries=2,        # 解析失败自动重试，杜绝整轮 0 漏洞
    )

    result_analysis = parsed.get("result_analysis", {})
    followup_plans_raw = parsed.get("followup_attacks", parsed.get("followup_plans", []))
    security_assessment = parsed.get("security_assessment", {})

    followup_plans = normalize_plans(followup_plans_raw) if followup_plans_raw else []

    return result_analysis, followup_plans, security_assessment


# ======================================================================
# 影子 API 安全分析
# ======================================================================


def _run_shadow_analysis(base_url: str, shadow_apis: list,
                         provider_override: str = None,
                         model_override: str = None):
    provider = _resolve_provider(provider_override, model_override)

    api_summary = "\n".join(
        f"  {api['method']} {api['path']} (风险: {api.get('risk', 'unknown')})"
        for api in shadow_apis
    )

    system_prompt = """你是一个 API 安全审计专家。你正在审查一组"影子 API"——这些端点在实际流量中被发现，但在 Swagger/OpenAPI 文档中完全未声明。

影子 API 的高风险特征：
- 未经过安全审查，可能完全缺少鉴权
- 可能是调试/测试端点遗留在生产环境
- 可能暴露内部管理功能
- 写操作 (POST/PUT/DELETE) 尤其危险"""

    user_prompt = f"""## 目标基础地址
{base_url}

## 发现的影子 API 列表
{api_summary}

## 你的任务

### 1. 业务逻辑分析 → `business_analysis`
推断这些影子 API 的业务功能和风险等级。

### 2. 攻击方案 → `attack_plans`
针对每个影子 API 生成 1~2 组攻击，优先测试：
- **无鉴权访问**：不带任何 Token 直接请求
- **信息泄露**：观察返回值是否暴露内部信息
- **越权操作**：POST/PUT/DELETE 尝试操作敏感资源

## 输出格式（严格 JSON，无 markdown 围栏）：
{{
  "business_analysis": {{
    "domain": "推断的系统类型",
    "entities": [],
    "relationships": [],
    "auth_model": "推断...",
    "trust_assumptions": [],
    "vulnerability_surface": [],
    "attack_surface_summary": "..."
  }},
  "attack_plans": [
    {{
      "vulnerability_type": "auth_bypass",
      "reason": "该影子 API 完全未在文档中声明，极有可能缺少鉴权",
      "expected_normal_behavior": "应该返回 401 或 404",
      "exploit_indicator": "返回 200 且有实际数据",
      "request": {{
        "method": "GET",
        "url_path": "/api/shadow/endpoint",
        "headers": {{}},
        "query_params": null,
        "body": null
      }}
    }}
  ]
}}"""

    parsed = chat_json(
        provider,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        temperature=0.3,
        max_tokens=6000,
        retries=2,
    )
    business_analysis = parsed.get("business_analysis", {})
    attack_plans_raw = parsed.get("attack_plans", parsed.get("plans", []))

    if isinstance(attack_plans_raw, dict):
        attack_plans_raw = [attack_plans_raw]

    attack_plans = normalize_plans(attack_plans_raw)

    enriched_plans = []
    for i, plan in enumerate(attack_plans):
        if i < len(attack_plans_raw) and isinstance(attack_plans_raw[i], dict):
            plan["vulnerability_type"] = attack_plans_raw[i].get("vulnerability_type", "unknown")
            plan["expected_normal_behavior"] = attack_plans_raw[i].get("expected_normal_behavior", "")
            plan["exploit_indicator"] = attack_plans_raw[i].get("exploit_indicator", "")
        enriched_plans.append(plan)

    return business_analysis, enriched_plans
