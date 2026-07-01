"""
智攻 (SmartAttack) — 扫描历史持久化
==================================
基于 JSON 文件的轻量级存储，每个扫描保存为一个独立文件。
"""

import json
import logging
import os
import uuid
from datetime import datetime, timezone

from config import STORAGE_DIR

logger = logging.getLogger("smart_attack.storage")


def _ensure_storage_dir():
    """确保存储目录存在。"""
    os.makedirs(STORAGE_DIR, exist_ok=True)


def save_scan(result_dict: dict) -> str:
    """保存一次完整扫描结果，返回 scan_id。

    result_dict 应为 /start_scan 返回的完整响应体。
    """
    _ensure_storage_dir()

    scan_id = uuid.uuid4().hex[:12]
    timestamp = datetime.now(timezone.utc).isoformat()

    record = {
        "scan_id": scan_id,
        "created_at": timestamp,
        "target_url": result_dict.get("target_url", ""),
        "stats": result_dict.get("stats", {}),
        "data": result_dict,
    }

    file_path = os.path.join(STORAGE_DIR, f"{scan_id}.json")
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(record, f, ensure_ascii=False, indent=2)

    logger.info("扫描记录已保存: %s → %s", scan_id, file_path)
    return scan_id


def list_scans(limit: int = 20) -> list:
    """列出最近的扫描记录（摘要，不含完整响应数据）。

    返回按创建时间倒序排列的摘要列表。
    """
    _ensure_storage_dir()

    files = sorted(
        [f for f in os.listdir(STORAGE_DIR) if f.endswith(".json")],
        reverse=True,
    )

    summaries = []
    for filename in files[:limit]:
        file_path = os.path.join(STORAGE_DIR, filename)
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                record = json.load(f)
            summaries.append({
                "scan_id": record.get("scan_id"),
                "created_at": record.get("created_at"),
                "target_url": record.get("target_url", ""),
                "stats": record.get("stats", {}),
                "overall_rating": (
                    record.get("data", {})
                    .get("security_assessment", {})
                    .get("overall_rating", "unknown")
                ),
            })
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("跳过损坏的扫描记录 %s: %s", filename, e)

    return summaries


def get_scan(scan_id: str) -> dict | None:
    """获取单次扫描的完整记录。"""
    _ensure_storage_dir()

    file_path = os.path.join(STORAGE_DIR, f"{scan_id}.json")
    if not os.path.isfile(file_path):
        return None

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logger.warning("读取扫描记录失败 %s: %s", scan_id, e)
        return None
