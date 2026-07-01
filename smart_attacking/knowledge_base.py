"""
智攻 (SmartAttack) — 漏洞知识图谱 + RAG 引擎
============================================
基于向量数据库的漏洞知识积累与检索系统。

核心功能：
1. 扫描完成后，将成功的攻击案例存入向量数据库
2. 新扫描时，检索历史相似端点上的成功攻击，作为 few-shot 注入 AI prompt
3. 越扫描越精准 — 形成数据飞轮

存储引擎：
- 优先 ChromaDB（向量语义检索）
- 降级 SQLite（关键词匹配），确保零依赖环境下也能工作
"""

import json
import logging
import os
import hashlib
from typing import Optional

logger = logging.getLogger("smart_attack.knowledge_base")

# ======================================================================
# 存储后端选择
# ======================================================================
_chroma_available = False
try:
    import chromadb
    from chromadb.config import Settings as ChromaSettings

    _chroma_available = True
except ImportError:
    logger.info("ChromaDB 未安装，使用 SQLite 关键词检索模式")
    logger.info("安装 ChromaDB 以获得更好的检索效果: pip install chromadb")


# ======================================================================
# ChromaDB 后端
# ======================================================================
class ChromaKnowledgeStore:
    """基于 ChromaDB 的向量知识库。"""

    def __init__(self, persist_dir: str):
        self._client = chromadb.PersistentClient(
            path=persist_dir,
            settings=ChromaSettings(anonymized_telemetry=False),
        )
        self._collection = self._client.get_or_create_collection(
            name="vulnerability_knowledge",
            metadata={"description": "SmartAttack 漏洞攻击知识库"},
        )
        logger.info("ChromaDB 知识库已初始化: %s (%d 条记录)",
                     persist_dir, self._collection.count())

    def add(self, endpoint: str, method: str, vuln_type: str,
            payload: dict, response_snippet: str, success: bool, scan_id: str):
        """添加一条攻击记录到知识库。"""
        if not success:
            return  # 只存储成功的攻击，避免噪声

        # 构造文档
        doc_text = (
            f"Endpoint: {method} {endpoint}\n"
            f"Vulnerability: {vuln_type}\n"
            f"Payload: {json.dumps(payload, ensure_ascii=False)}\n"
            f"Response: {response_snippet[:1000]}"
        )

        # 生成唯一 ID
        doc_id = hashlib.md5(
            f"{scan_id}:{method}:{endpoint}:{vuln_type}".encode()
        ).hexdigest()[:16]

        try:
            self._collection.upsert(
                ids=[doc_id],
                documents=[doc_text],
                metadatas=[{
                    "endpoint": endpoint,
                    "endpoint_pattern": _patternize_path(endpoint),
                    "method": method,
                    "vuln_type": vuln_type,
                    "scan_id": scan_id,
                    "payload_json": json.dumps(payload, ensure_ascii=False),
                    "response_snippet": response_snippet[:500],
                }],
            )
            logger.debug("知识库已存入: %s %s [%s]", method, endpoint, vuln_type)
            return doc_id
        except Exception as e:
            logger.warning("知识库写入失败: %s", e)
            return None

    def query(self, endpoint: str, method: str = None, top_k: int = 5) -> list[dict]:
        """检索最相似的历史攻击案例。"""
        try:
            pattern = _patternize_path(endpoint)
            query_text = f"{method or 'GET'} {endpoint} ({pattern})"

            results = self._collection.query(
                query_texts=[query_text],
                n_results=min(top_k, self._collection.count()),
            )

            if not results or not results.get("ids") or not results["ids"][0]:
                return []

            cases = []
            for i, doc_id in enumerate(results["ids"][0]):
                meta = results["metadatas"][0][i] if results.get("metadatas") else {}
                doc = results["documents"][0][i] if results.get("documents") else ""
                cases.append({
                    "id": doc_id,
                    "endpoint": meta.get("endpoint", ""),
                    "method": meta.get("method", ""),
                    "vuln_type": meta.get("vuln_type", ""),
                    "payload": json.loads(meta.get("payload_json", "{}")),
                    "response_snippet": meta.get("response_snippet", ""),
                    "similarity": _simple_similarity(endpoint, meta.get("endpoint", "")),
                })

            # 按相似度排序
            cases.sort(key=lambda c: c["similarity"], reverse=True)
            return cases[:top_k]

        except Exception as e:
            logger.warning("知识库查询失败: %s", e)
            return []

    def count(self) -> int:
        try:
            return self._collection.count()
        except Exception:
            return 0

    def get_all_vuln_types(self) -> list[str]:
        """获取知识库中所有漏洞类型。"""
        try:
            if self._collection.count() == 0:
                return []
            results = self._collection.get()
            types = set()
            for meta in (results.get("metadatas") or []):
                if meta and meta.get("vuln_type"):
                    types.add(meta["vuln_type"])
            return sorted(types)
        except Exception:
            return []


# ======================================================================
# SQLite 降级后端（关键词匹配）
# ======================================================================
class SQLiteKnowledgeStore:
    """基于 SQLite 的简易知识库（无需额外依赖）。"""

    def __init__(self, persist_dir: str):
        import sqlite3

        os.makedirs(persist_dir, exist_ok=True)
        db_path = os.path.join(persist_dir, "knowledge.db")
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS knowledge (
                id TEXT PRIMARY KEY,
                endpoint TEXT NOT NULL,
                endpoint_pattern TEXT NOT NULL,
                method TEXT NOT NULL,
                vuln_type TEXT NOT NULL,
                payload_json TEXT,
                response_snippet TEXT,
                scan_id TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        self._conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_knowledge_pattern
            ON knowledge(endpoint_pattern, vuln_type)
        """)
        self._conn.commit()
        logger.info("SQLite 知识库已初始化: %s (%d 条记录)",
                     db_path, self.count())

    def add(self, endpoint: str, method: str, vuln_type: str,
            payload: dict, response_snippet: str, success: bool, scan_id: str):
        if not success:
            return

        doc_id = hashlib.md5(
            f"{scan_id}:{method}:{endpoint}:{vuln_type}".encode()
        ).hexdigest()[:16]

        try:
            self._conn.execute(
                """INSERT OR REPLACE INTO knowledge
                   (id, endpoint, endpoint_pattern, method, vuln_type,
                    payload_json, response_snippet, scan_id)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (doc_id, endpoint, _patternize_path(endpoint), method,
                 vuln_type, json.dumps(payload, ensure_ascii=False),
                 response_snippet[:500], scan_id),
            )
            self._conn.commit()
            return doc_id
        except Exception as e:
            logger.warning("SQLite 知识库写入失败: %s", e)
            return None

    def query(self, endpoint: str, method: str = None, top_k: int = 5) -> list[dict]:
        pattern = _patternize_path(endpoint)

        # 路径分段匹配
        segments = [s for s in pattern.split("/") if s]
        conditions = []
        params = []
        for seg in segments:
            conditions.append("endpoint_pattern LIKE ?")
            params.append(f"%{seg}%")

        where = " OR ".join(conditions) if conditions else "1=1"
        if method:
            where = f"({where}) AND method = ?"
            params.append(method.upper())

        rows = self._conn.execute(
            f"""SELECT id, endpoint, method, vuln_type, payload_json,
                       response_snippet, endpoint_pattern
                FROM knowledge
                WHERE {where}
                ORDER BY created_at DESC
                LIMIT ?""",
            params + [top_k * 2],
        ).fetchall()

        cases = []
        for row in rows:
            try:
                payload = json.loads(row[4]) if row[4] else {}
            except json.JSONDecodeError:
                payload = {}
            cases.append({
                "id": row[0],
                "endpoint": row[1],
                "method": row[2],
                "vuln_type": row[3],
                "payload": payload,
                "response_snippet": row[5] or "",
                "similarity": _simple_similarity(endpoint, row[1]),
            })

        cases.sort(key=lambda c: c["similarity"], reverse=True)
        # 去重（同类型漏洞只保留最高相似度的一条）
        seen_types = set()
        deduped = []
        for c in cases:
            if c["vuln_type"] not in seen_types:
                deduped.append(c)
                seen_types.add(c["vuln_type"])
        return deduped[:top_k]

    def count(self) -> int:
        row = self._conn.execute("SELECT COUNT(*) FROM knowledge").fetchone()
        return row[0] if row else 0

    def get_all_vuln_types(self) -> list[str]:
        rows = self._conn.execute(
            "SELECT DISTINCT vuln_type FROM knowledge ORDER BY vuln_type"
        ).fetchall()
        return [r[0] for r in rows]


# ======================================================================
# 统一接口
# ======================================================================
def _patternize_path(path: str) -> str:
    """将路径参数化：/users/v1/admin → /users/v1/{username}"""
    import re
    segments = path.split("/")
    result = []
    for seg in segments:
        if not seg:
            continue
        if seg.isdigit():
            result.append("{id}")
        elif re.match(r'^[0-9a-f]{8,}$', seg, re.I):
            result.append("{hash}")
        elif re.match(r'^[0-9a-f-]{32,}$', seg, re.I):
            result.append("{uuid}")
        else:
            result.append(seg.lower())
    return "/" + "/".join(result)


def _simple_similarity(path_a: str, path_b: str) -> float:
    """简单的路径相似度计算。"""
    seg_a = set(path_a.lower().split("/"))
    seg_b = set(path_b.lower().split("/"))
    if not seg_a or not seg_b:
        return 0.0
    intersection = seg_a & seg_b
    union = seg_a | seg_b
    return len(intersection) / len(union) if union else 0.0


# ======================================================================
# 知识库单例
# ======================================================================
_kb_instance: Optional[object] = None


def get_knowledge_base() -> object:
    """获取知识库实例（单例，自动选择 ChromaDB 或 SQLite）。"""
    global _kb_instance

    if _kb_instance is not None:
        return _kb_instance

    # 存储目录
    try:
        from config import STORAGE_DIR as _base
    except ImportError:
        from .config import STORAGE_DIR as _base
    kb_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "storage", "knowledge_base")

    os.makedirs(kb_dir, exist_ok=True)

    if _chroma_available:
        try:
            _kb_instance = ChromaKnowledgeStore(kb_dir)
            return _kb_instance
        except Exception as e:
            logger.warning("ChromaDB 初始化失败，降级到 SQLite: %s", e)

    _kb_instance = SQLiteKnowledgeStore(kb_dir)
    return _kb_instance


# ======================================================================
# 便捷函数
# ======================================================================
def store_scan_knowledge(scan_result: dict):
    """从完整扫描结果中提取成功攻击并存入知识库。

    严格过滤（v3.5 修复）：只存入被对抗验证确认为真实漏洞的攻击结果。
    避免噪声数据污染知识库，防止 AI 被错误的"历史经验"带偏。
    """
    kb = get_knowledge_base()
    data = scan_result.get("data", scan_result)
    scan_id = scan_result.get("scan_id", "unknown")

    # 收集所有执行结果
    all_results = []
    all_results.extend(data.get("execution_results", []))
    all_results.extend(data.get("followup_execution", []))

    # 获取已确认的漏洞（从安全评估 + 对抗验证中提取）
    confirmed_vulns = []  # 存储 (endpoint, method, vuln_type, severity)
    assessment = data.get("security_assessment", {})
    for v in assessment.get("vulnerabilities_found", []):
        vt = v.get("vulnerability_type") or v.get("vuln_type", "")
        ep = v.get("endpoint", "")
        method = v.get("method", "GET")
        sev = v.get("severity", "medium")
        if vt and ep:
            confirmed_vulns.append((ep, method.upper(), vt, sev))

    result_analysis = data.get("result_analysis", {})
    for v in result_analysis.get("confirmed_vulnerabilities", []):
        if isinstance(v, dict):
            vt = v.get("vulnerability_type") or v.get("type", "")
            ep = v.get("endpoint", "")
            method = v.get("method", "GET")
            sev = v.get("severity", "medium")
            if vt and ep:
                confirmed_vulns.append((ep, method.upper(), vt, sev))

    stored = 0
    stored_keys = set()  # 防止同一端点+漏洞类型重复存储
    max_per_scan = 20     # 每次扫描最多存 20 条

    for r in all_results:
        if not isinstance(r, dict):
            continue
        if stored >= max_per_scan:
            break

        vuln_type = r.get("vulnerability_type", "unknown")
        payload = r.get("payload", {})
        endpoint = payload.get("path", "")
        method = payload.get("method", "GET")
        code = r.get("status_code", 0)
        resp = r.get("response_text", "") or ""

        if not endpoint:
            continue

        # ====== 严格的三层过滤 ======

        # 第一层：必须是已确认漏洞类型，且该结果在确认列表中
        is_confirmed = any(
            cv[0] == endpoint and cv[1] == method.upper() and cv[2] == vuln_type
            for cv in confirmed_vulns
        )

        # 第二层：响应中必须包含真实敏感数据证据（不是空壳 200）
        has_evidence = (
            code == 200 and
            len(resp) > 80 and
            "unauthorized" not in resp.lower() and
            "not found" not in resp.lower()
        )

        # 第三层：检查 exploit_indicator 是否匹配（更精准的自动判定）
        indicator = r.get("exploit_indicator", "")
        indicator_hit = False
        if isinstance(indicator, dict):
            patterns = indicator.get("patterns", [])
            for pat in patterns:
                import re
                try:
                    if re.search(pat, resp, re.IGNORECASE):
                        indicator_hit = True
                        break
                except re.error:
                    pass

        # 必须同时满足：已确认 AND 有证据 AND (有 indicator 命中 或 是已确认漏洞)
        should_store = has_evidence and (is_confirmed or indicator_hit)

        if not should_store:
            continue

        # 防止重复
        key = (method, endpoint, vuln_type)
        if key in stored_keys:
            continue
        stored_keys.add(key)

        kb.add(
            endpoint=endpoint,
            method=method,
            vuln_type=vuln_type,
            payload=payload.get("injected_data", {}),
            response_snippet=resp[:500],
            success=True,  # 此时已确认是真实漏洞
            scan_id=scan_id,
        )
        stored += 1

    if stored > 0:
        logger.info("已从扫描 %s 中提取 %d 条高质量攻击知识 (共 %d 条)",
                     scan_id, stored, kb.count())
    else:
        logger.info("扫描 %s 未产生符合质量标准的漏洞知识（过滤了 %d 条候选结果）",
                     scan_id, len(all_results))


def query_similar_attacks(endpoint: str, method: str = None,
                          top_k: int = 5) -> list[dict]:
    """检索历史相似端点上的成功攻击案例（RAG 检索）。"""
    kb = get_knowledge_base()
    return kb.query(endpoint, method, top_k)


def get_knowledge_stats() -> dict:
    """获取知识库统计信息。"""
    kb = get_knowledge_base()
    return {
        "total_records": kb.count(),
        "vuln_types": kb.get_all_vuln_types(),
        "engine": "ChromaDB" if _chroma_available and isinstance(kb, ChromaKnowledgeStore)
                  else "SQLite",
    }
