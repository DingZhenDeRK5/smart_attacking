"""
智攻 (SmartAttack) — 多 Agent 协作引擎
======================================
实现规划→专项攻击→裁判→报告的多 Agent 协作扫描架构。

Agent 角色：
- PlannerAgent：分析 Swagger，制定整体攻击策略
- AuthAgent：鉴权/越权专项
- DataAgent：信息泄露/批量赋值专项
- LogicAgent：业务逻辑绕过专项
- JudgeAgent：交叉验证、去误报
- ReportAgent：整合最终报告
"""

import json
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

try:
    from models.llm_provider import get_cached_provider, create_llm_provider
    from parser import extract_json, normalize_plans, chat_json
    from knowledge_base import query_similar_attacks
except ImportError:
    from .models.llm_provider import get_cached_provider, create_llm_provider
    from .parser import extract_json, normalize_plans, chat_json
    from .knowledge_base import query_similar_attacks

logger = logging.getLogger("smart_attack.agents")

# ======================================================================
# Agent 基类
# ======================================================================
class BaseAgent:
    """Agent 基类 — 封装 LLM 调用和 prompt 构造。"""

    def __init__(self, name: str, system_prompt: str, temperature: float = 0.7):
        self.name = name
        self.system_prompt = system_prompt
        self.temperature = temperature
        self._provider = None

    @property
    def provider(self):
        if self._provider is None:
            self._provider = get_cached_provider()
        return self._provider

    def think(self, user_prompt: str, max_tokens: int = 6000) -> str:
        """调用 LLM 并返回原始输出。"""
        logger.info("[%s] 正在分析...", self.name)
        raw = self.provider.chat(
            system_prompt=self.system_prompt,
            user_prompt=user_prompt,
            temperature=self.temperature,
            max_tokens=max_tokens,
        )
        logger.info("[%s] 分析完成 (%d 字符)", self.name, len(raw or ""))
        return raw

    def think_json(self, user_prompt: str, max_tokens: int = 6000) -> dict:
        """调用 LLM 并稳健解析 JSON（解析失败自动重试，杜绝单次抖动清零）。"""
        logger.info("[%s] 正在分析...", self.name)
        result = chat_json(
            self.provider,
            system_prompt=self.system_prompt,
            user_prompt=user_prompt,
            temperature=self.temperature,
            max_tokens=max_tokens,
            retries=2,
        )
        if not result:
            logger.warning("[%s] JSON 解析失败（已重试），返回空结果", self.name)
        return result


# ======================================================================
# 1. 规划 Agent
# ======================================================================
class PlannerAgent(BaseAgent):
    """分析 Swagger 文档，制定全局攻击策略和分工方案。"""

    def __init__(self):
        super().__init__(
            name="规划Agent",
            system_prompt="""你是一个 API 安全审计的总指挥。你的工作是：
1. 阅读 Swagger/OpenAPI 文档，理解整个 API 的业务逻辑
2. 识别所有攻击面（鉴权缺口、数据暴露点、越权可能、注入点等）
3. 制定攻击策略——哪些端点由哪种专项 Agent 负责
4. 输出结构化的攻击计划

你不需要生成具体的 HTTP 请求，而是制定「谁负责什么」的分工方案。""",
            temperature=0.3,
        )

    def plan(self, swagger_content: str) -> dict:
        """分析 Swagger 并制定攻击计划。"""
        prompt = f"""分析以下 Swagger/OpenAPI 文档，制定攻击策略。

## 你的输出格式（严格 JSON）：
{{
  "business_analysis": {{
    "domain": "业务领域",
    "entities": [{{ "name": "...", "id_pattern": "..." }}],
    "auth_model": "鉴权机制描述",
    "trust_assumptions": ["开发者可能做的不安全假设"],
    "attack_surface_summary": "一句话总结最大风险"
  }},
  "attack_plan": {{
    "auth_agent_tasks": [
      {{ "priority": 1, "endpoint": "/users/v1/{{username}}", "method": "GET",
         "target_vuln": "bola", "reason": "用户名参数可枚举，需测试越权访问" }}
    ],
    "data_agent_tasks": [
      {{ "priority": 1, "endpoint": "/users/v1", "method": "GET",
         "target_vuln": "info_leak", "reason": "无鉴权的 GET 可能返回敏感字段" }}
    ],
    "logic_agent_tasks": [
      {{ "priority": 2, "endpoint": "/users/v1/register", "method": "POST",
         "target_vuln": "mass_assignment", "reason": "POST body 可能接受未声明的权限字段" }}
    ],
    "injection_agent_tasks": [
      {{ "priority": 2, "endpoint": "/users/v1/{{username}}", "method": "GET",
         "target_vuln": "injection", "reason": "path 参数可能直接拼接到数据库查询" }}
    ]
  }}
}}

要求：
1. 覆盖文档中 **每一个** 端点，不要遗漏任何 GET/POST/PUT/DELETE
2. 每个端点至少分配给 2 个不同的 Agent（确保多角度测试）
3. auth_agent_tasks 至少 3 个任务，data_agent_tasks 至少 3 个
4. logic_agent_tasks 至少 2 个，injection_agent_tasks 至少 2 个
5. 标注 priority：1=最高优先级（无鉴权端点/写操作），2=中等，3=低优先级
6. auth_agent_tasks 关注鉴权和越权问题
7. data_agent_tasks 关注信息泄露和批量赋值
8. logic_agent_tasks 关注业务逻辑绕过
9. injection_agent_tasks 关注 SQL/命令注入

## API 文档：
{swagger_content}
"""
        return self.think_json(prompt, max_tokens=12000)  # 增大 token 确保覆盖全


# ======================================================================
# 2. 专项攻击 Agent
# ======================================================================
class AuthAgent(BaseAgent):
    """鉴权/越权专项 Agent：BOLA, IDOR, 权限提升, 认证绕过。"""

    def __init__(self):
        super().__init__(
            name="鉴权Agent",
            system_prompt="""你是 API 鉴权漏洞专家。你专精于发现：
- BOLA/IDOR：通过修改/枚举资源 ID 访问他人的数据
- 权限提升：普通用户执行管理员操作
- 认证绕过：不带 Token 或带伪造 Token 访问受保护端点
- JWT 弱点：alg=none、弱签名密钥、Token 跨用户复用

你的攻击思路：
1. 对每个端点，先不带 Token 请求一次（探测是否需要鉴权）
2. 带明显错误的 Token 请求一次（探测鉴权是否只是"检查是否存在"）
3. 枚举资源 ID（数字：1,2,3,100,1000；字符串：admin, test, root）
4. 对 DELETE/PUT 等管理操作，尝试用普通用户的 Token
5. 检查 JWT Token 是否可以篡改（改 Header/Playload/Signature）""",
            temperature=0.4,
        )

    def generate_attacks(self, tasks: list[dict], swagger_content: str,
                         rag_examples: str = "") -> list[dict]:
        """根据分配给 Auth Agent 的任务生成具体攻击 payload。"""
        if not tasks:
            logger.info("[鉴权Agent] 无分配任务，跳过")
            return []

        tasks_text = json.dumps(tasks, ensure_ascii=False, indent=2)
        rag_section = ""
        if rag_examples:
            rag_section = f"""
## 历史相似攻击案例（RAG 增强）
以下是从知识库中检索到的历史成功攻击，请参考其 payload 和思路：
{rag_examples}
"""

        prompt = f"""根据以下任务清单，为每个任务生成 1~2 组具体的攻击请求。

{rag_section}
## 你的任务清单：
{tasks_text}

## 参考 API 文档：
{swagger_content[:5000]}

## 攻击生成要求：
- **必须生成至少 5 组不同的攻击方案**，覆盖每一个分配给你的端点
- 每组攻击必须包含具体的 HTTP request（method, url_path, headers, query_params, body）
- 对每个端点至少用 2 种不同的攻击手法测试
- reason 字段详细说明攻击原理
- exploit_indicator 字段说明成功时响应中会有什么特征
- vulnerability_type 使用：bola, idor, privilege_escalation, auth_bypass, jwt_weakness

## 输出格式（严格 JSON，无 markdown 围栏）：
{{
  "attack_plans": [
    {{
      "vulnerability_type": "bola",
      "reason": "...",
      "expected_normal_behavior": "...",
      "exploit_indicator": "...",
      "request": {{
        "method": "GET",
        "url_path": "/users/v1/admin",
        "headers": {{}},
        "query_params": null,
        "body": null
      }}
    }}
  ]
}}
"""
        result = self.think_json(prompt, max_tokens=8000)
        return result.get("attack_plans", [])


class DataAgent(BaseAgent):
    """数据安全专项 Agent：信息泄露、批量赋值、敏感数据暴露。"""

    def __init__(self):
        super().__init__(
            name="数据Agent",
            system_prompt="""你是数据安全漏洞专家。你专精于发现：
- 信息泄露：API 响应中包含了密码、Token、密钥、内部配置等未文档化的敏感字段
- 批量赋值 (Mass Assignment)：客户端可以通过 POST/PUT body 注入 role, admin, credit 等特权字段
- 过度暴露：列表接口返回了远超需要的字段（如用户列表返回了所有人的手机号和地址）
- Debug 端点：未关闭的调试端点泄露内部信息
- 错误信息泄露：500 错误或异常响应中包含堆栈跟踪、数据库结构、内网 IP

你的信条：**文档 Schema 只是声明，实际返回值一定包含更多字段**。

你的攻击思路：
1. 对每个 GET 端点，不带 Token 直接请求 → 观察返回值包含哪些未声明的字段
2. 对每个 POST/PUT 端点，注入 role, admin, is_admin, credit, balance, verified, permission_level 等字段
3. 对用户相关端点，特别注意是否返回 password, secret_token, phone, address
4. 尝试访问 /debug, /admin, /internal, /actuator, /metrics 等常见调试端点
5. 对错误响应进行分析——500 错误中是否包含 SQL 语句、文件路径、IP 地址""",
            temperature=0.4,
        )

    def generate_attacks(self, tasks: list[dict], swagger_content: str,
                         rag_examples: str = "") -> list[dict]:
        if not tasks:
            logger.info("[数据Agent] 无分配任务，跳过")
            return []

        tasks_text = json.dumps(tasks, ensure_ascii=False, indent=2)
        rag_section = ""
        if rag_examples:
            rag_section = f"""
## 历史相似攻击案例（RAG 增强）
{rag_examples}
"""

        prompt = f"""根据以下任务清单，为每个任务生成 1~2 组数据安全攻击。

{rag_section}
## 你的任务清单：
{tasks_text}

## 参考 API 文档：
{swagger_content[:5000]}

## 关键攻击策略：
1. 对所有无鉴权 GET 端点 → 直接请求，仔细观察返回值中是否有 password, secret, token, credit, role, phone 等字段
2. 对所有 POST/PUT 端点 → 在 body 中注入 {{"role":"admin","credit":99999,"admin":true}}
3. 尝试常见的未文档化端点：/debug, /admin, /.env, /actuator/health
4. **必须生成至少 5 组不同的攻击方案**，每个端点至少用 2 种手法测试

vulnerability_type 使用：info_leak, mass_assignment, security_misconfig

## 输出格式（严格 JSON，无 markdown 围栏）：
{{
  "attack_plans": [
    {{
      "vulnerability_type": "info_leak",
      "reason": "...",
      "expected_normal_behavior": "...",
      "exploit_indicator": "响应体中包含 password, secret_token 等未在 Schema 中声明的敏感字段",
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
"""
        result = self.think_json(prompt, max_tokens=8000)
        return result.get("attack_plans", [])


class LogicAgent(BaseAgent):
    """业务逻辑专项 Agent：逻辑绕过、参数篡改、工作流滥用。"""

    def __init__(self):
        super().__init__(
            name="逻辑Agent",
            system_prompt="""你是业务逻辑漏洞专家。你专精于发现：
- 逻辑绕过：跳过中间步骤直接调用关键 API
- 参数篡改：修改 price, quantity, discount 等业务参数导致异常行为
- 竞态条件：并发请求导致的状态不一致
- 负值/零值注入：price=-100, quantity=0 等非预期值
- 类型混淆：数字字段传字符串、字符串字段传数组
- HTTP 方法替换：POST 改 GET、DELETE 改 PUT 等

你的攻击思路：
1. 对创建订单/交易类接口，尝试 price=0, price=-1, quantity=99999
2. 尝试跳过"添加购物车"直接调用"下单"接口
3. 对密码重置接口，尝试不提供旧密码直接设置新密码
4. 修改请求方法（POST→GET→PUT→DELETE）观察是否绕过限制""",
            temperature=0.4,
        )

    def generate_attacks(self, tasks: list[dict], swagger_content: str,
                         rag_examples: str = "") -> list[dict]:
        if not tasks:
            logger.info("[逻辑Agent] 无分配任务，跳过")
            return []

        tasks_text = json.dumps(tasks, ensure_ascii=False, indent=2)
        rag_section = ""
        if rag_examples:
            rag_section = f"""
## 历史相似攻击案例（RAG 增强）
{rag_examples}
"""

        prompt = f"""根据以下任务清单，生成业务逻辑攻击方案。

{rag_section}
## 你的任务清单：
{tasks_text}

## 参考 API 文档：
{swagger_content[:5000]}

vulnerability_type 使用：logic_bypass, param_tampering, business_logic
**必须生成至少 4 组不同的攻击方案**

## 输出格式（严格 JSON，无 markdown 围栏）：
{{
  "attack_plans": [
    {{
      "vulnerability_type": "logic_bypass",
      "reason": "...",
      "expected_normal_behavior": "...",
      "exploit_indicator": "...",
      "request": {{
        "method": "POST",
        "url_path": "/orders/create",
        "headers": {{ "Content-Type": "application/json" }},
        "query_params": null,
        "body": {{ "price": -100, "quantity": 1 }}
      }}
    }}
  ]
}}
"""
        result = self.think_json(prompt, max_tokens=8000)
        return result.get("attack_plans", [])


class InjectionAgent(BaseAgent):
    """注入攻击专项 Agent：SQL 注入、命令注入、XSS 等。"""

    def __init__(self):
        super().__init__(
            name="注入Agent",
            system_prompt="""你是注入攻击专家。你专精于发现：
- SQL 注入：在 path/query/body 参数中注入 SQL payload
- 命令注入：在系统命令参数中注入 shell 命令
- NoSQL 注入：MongoDB 等非关系型数据库注入
- LDAP/XPath 注入
- Server-Side Template Injection (SSTI)

你的攻击 payload 库：
- SQL: ' OR '1'='1, ' OR 1=1--, admin'--, '; DROP TABLE users;--, ' UNION SELECT 1,2,3--
- 命令注入: ; ls, | whoami, `id`, $(cat /etc/passwd)
- NoSQL: {"$gt": ""}, {"$ne": null}, {"$where": "sleep(5000)"}
- 路径遍历: ../../../etc/passwd, ..\\..\\..\\windows\\system32

对所有接受字符串的参数（path param, query param, body 字段），都必须测试注入！""",
            temperature=0.4,
        )

    def generate_attacks(self, tasks: list[dict], swagger_content: str,
                         rag_examples: str = "") -> list[dict]:
        if not tasks:
            logger.info("[注入Agent] 无分配任务，跳过")
            return []

        tasks_text = json.dumps(tasks, ensure_ascii=False, indent=2)
        rag_section = ""
        if rag_examples:
            rag_section = f"""
## 历史相似攻击案例（RAG 增强）
{rag_examples}
"""

        prompt = f"""根据以下任务清单，生成注入攻击方案。

{rag_section}
## 你的任务清单：
{tasks_text}

## 参考 API 文档：
{swagger_content[:5000]}

vulnerability_type 使用：injection, sql_injection, command_injection

对每个接受字符串参数的端点，至少尝试 3 种不同的注入 payload（单引号测试 + 永真注入 + UNION 查询）。
**必须生成至少 5 组不同的攻击方案**

## 输出格式（严格 JSON，无 markdown 围栏）：
{{
  "attack_plans": [
    {{
      "vulnerability_type": "sql_injection",
      "reason": "...",
      "expected_normal_behavior": "应该返回正常数据或参数错误",
      "exploit_indicator": "返回 SQL 语法错误、数据库信息、或异常数据",
      "request": {{
        "method": "GET",
        "url_path": "/users/v1/' OR '1'='1",
        "headers": {{}},
        "query_params": null,
        "body": null
      }}
    }}
  ]
}}
"""
        result = self.think_json(prompt, max_tokens=8000)
        return result.get("attack_plans", [])


# ======================================================================
# 3. 裁判 Agent
# ======================================================================
class JudgeAgent(BaseAgent):
    """交叉验证攻击结果，判定哪些是真实漏洞。"""

    def __init__(self):
        super().__init__(
            name="裁判Agent",
            system_prompt="""你是渗透测试结果的终审法官。你的使命是：
1. 逐一审查每个攻击的执行结果
2. 判断攻击是否真正成功（而非误报）
3. 对成功攻击进行交叉验证——如果多个 Agent 从不同角度发现了同一问题，可信度更高
4. 给出最终的漏洞确认列表和整体安全评级

你的判定标准（严格但公正）：
- 响应中包含未文档化的敏感数据（password, token, key, secret...）→ 确认信息泄露
- 注入的 role/admin 字段在响应中生效 → 确认批量赋值
- 不带 Token 访问了有鉴权的端点且返回数据 → 确认认证绕过
- 遍历 ID 成功获取了不同用户数据 → 确认越权
- 只是一般性的错误信息 → 不算漏洞""",
            temperature=0.4,
        )

    def judge(self, business_analysis: dict, all_results: list[dict],
              agent_plans: dict) -> dict:
        """综合审查所有攻击结果。"""
        # 精简结果
        compact = []
        for r in all_results:
            if not isinstance(r, dict):
                continue
            compact.append({
                "round": r.get("round"),
                "vuln_type": r.get("vulnerability_type", "unknown"),
                "method": (r.get("payload") or {}).get("method", "?"),
                "path": (r.get("payload") or {}).get("path", "?"),
                "status_code": r.get("status_code"),
                "response": (r.get("response_text") or "")[:2000],
                "reason": r.get("reason", ""),
                "exploit_indicator": r.get("exploit_indicator", ""),
            })

        prompt = f"""## 业务背景
{json.dumps(business_analysis, ensure_ascii=False, indent=2)[:2000]}

## 攻击执行结果（共 {len(compact)} 组）
{json.dumps(compact, ensure_ascii=False, indent=2)}

## 你的任务

### 1. 逐条判定 → per_attack_analysis
对每个结果判定 verdict：success（确认漏洞）/ partial（有信息泄露）/ failed（无发现）

### 2. 确认漏洞 → confirmed_vulnerabilities
汇总所有 success 的结果，每个漏洞必须包含：
- vulnerability_type, endpoint, severity (critical/high/medium/low)
- finding（漏洞描述，中文）
- recommendation（修复建议，中文）

### 3. 安全评估 → security_assessment
- overall_rating: high/medium/low
- defense_level: none/weak/moderate/strong
- summary: 一句话总结
- remediation_advice: 修复建议摘要

## 输出格式（严格 JSON，无 markdown 围栏）：
{{
  "result_analysis": {{
    "per_attack_analysis": [{{ "round": 1, "verdict": "success", "finding": "...", "why": "..." }}],
    "confirmed_vulnerabilities": [{{ "vulnerability_type": "info_leak", "endpoint": "/users/v1", "severity": "high", "finding": "...", "recommendation": "..." }}],
    "information_leaked": [],
    "defense_level": "weak",
    "summary": "..."
  }},
  "security_assessment": {{
    "overall_rating": "high",
    "vulnerabilities_found": [],
    "remediation_advice": "..."
  }}
}}
"""
        return self.think_json(prompt, max_tokens=8000)


# ======================================================================
# 4. 多 Agent 编排器
# ======================================================================
def run_multi_agent_scan(swagger_content: str) -> dict:
    """执行完整的多 Agent 协作扫描流程。

    Returns:
        {
            "business_analysis": {...},
            "attack_plans": [...],         # 所有 Agent 的攻击方案合并
            "agent_report": {
                "planner": {...},
                "auth_agent": {...},
                "data_agent": {...},
                "logic_agent": {...},
                "injection_agent": {...},
            }
        }
    """
    logger.info("=" * 60)
    logger.info("多 Agent 协作扫描启动")
    logger.info("=" * 60)

    # ---- Step 1: 规划 Agent 分析 Swagger ----
    planner = PlannerAgent()
    plan = planner.plan(swagger_content)
    business_analysis = plan.get("business_analysis", {})
    attack_plan = plan.get("attack_plan", {})

    logger.info("规划完成: 鉴权任务 %d | 数据任务 %d | 逻辑任务 %d | 注入任务 %d",
                len(attack_plan.get("auth_agent_tasks", [])),
                len(attack_plan.get("data_agent_tasks", [])),
                len(attack_plan.get("logic_agent_tasks", [])),
                len(attack_plan.get("injection_agent_tasks", [])))

    # ---- Step 2: 并行运行 4 个专项 Agent ----
    agents_config = [
        ("auth_agent_tasks", AuthAgent()),
        ("data_agent_tasks", DataAgent()),
        ("logic_agent_tasks", LogicAgent()),
        ("injection_agent_tasks", InjectionAgent()),
    ]

    all_attack_plans = []
    agent_results = {}

    def _run_agent(task_key: str, agent: BaseAgent, tasks: list[dict]):
        """在独立线程中运行一个 Agent。"""
        # 为 Agent 的任务检索 RAG 增强
        rag_examples_str = ""
        for task in tasks[:3]:  # 只为前 3 个高优先级任务检索
            ep = task.get("endpoint", "")
            if ep:
                similar = query_similar_attacks(ep, task.get("method"))
                if similar:
                    rag_examples_str += json.dumps(
                        similar[:2], ensure_ascii=False, indent=2
                    ) + "\n"

        plans = agent.generate_attacks(tasks, swagger_content, rag_examples_str)
        # 零产出兜底：有任务却没生成方案（多半是单次 JSON 抖动），用更大 token 重试一次
        if not plans and tasks:
            logger.warning("[%s] 首次生成 0 组方案，提高 token 上限重试一次", agent.name)
            try:
                plans = agent.generate_attacks(tasks, swagger_content, rag_examples_str)
            except Exception as e:
                logger.warning("[%s] 重试仍失败: %s", agent.name, e)
        return task_key, plans, agent.name

    logger.info("并行启动 %d 个专项 Agent...", len(agents_config))
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = [
            pool.submit(_run_agent, key, agent, attack_plan.get(key, []))
            for key, agent in agents_config
        ]
        for future in as_completed(futures):
            try:
                task_key, plans, agent_name = future.result()
                agent_results[task_key] = {
                    "agent": agent_name,
                    "task_count": len(attack_plan.get(task_key, [])),
                    "plan_count": len(plans),
                }
                all_attack_plans.extend(plans)
                logger.info("[%s] 生成 %d 组攻击", agent_name, len(plans))
            except Exception as e:
                logger.error("Agent 执行失败: %s", e)

    # ---- Step 3: 去重与排序 ----
    enriched = []
    for i, plan in enumerate(all_attack_plans):
        if not isinstance(plan, dict) or not isinstance(plan.get("request"), dict):
            continue
        enriched.append(plan)

    logger.info("多 Agent 协作完成: 共生成 %d 组攻击方案 (4 个 Agent)", len(enriched))

    return {
        "business_analysis": business_analysis,
        "attack_plans": enriched,
        "agent_report": agent_results,
    }


# ======================================================================
# RAG 增强：为攻击生成注入历史知识
# ======================================================================
def build_rag_context(attack_plans: list[dict]) -> str:
    """为一组攻击方案构建 RAG 上下文（从知识库检索相似案例）。

    在 Phase 3（分析结果）时使用，帮助 AI 判定漏洞时参考历史。
    """
    if not attack_plans:
        return ""

    # 为前 5 个攻击方案检索相似端点
    contexts = []
    seen = set()
    for plan in attack_plans[:5]:
        req = plan.get("request", {})
        ep = req.get("url_path", "")
        if not ep or ep in seen:
            continue
        seen.add(ep)

        similar = query_similar_attacks(ep)
        if similar:
            contexts.append(f"端点 {ep}: {len(similar)} 条历史相似案例")
            for s in similar[:2]:
                contexts.append(
                    f"  - [{s['vuln_type']}] {s['method']} {s['endpoint']} "
                    f"(相似度 {s.get('similarity', 0):.0%})"
                )

    return "\n".join(contexts) if contexts else ""
