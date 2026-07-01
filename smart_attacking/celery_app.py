"""
智攻 (SmartAttack) v3.5 — Celery 异步任务队列
============================================
生产级任务队列，支持 Worker 横向扩展、任务优先级、失败重试。

启用方式：
  1. 设置环境变量 CELERY_BROKER_URL=redis://localhost:6379/0
  2. 启动 Worker: celery -A smart_attacking.celery_app worker -Q scan_queue --concurrency=4
  3. 后端自动检测 Celery 可用性，不可用时降级到 threading 模式

架构：
  Flask API → Celery Task → Worker 执行扫描 → 结果写入 DB
  WebSocket 通过 Redis pub/sub 跨 Worker 推送实时更新
"""

import logging
import os

logger = logging.getLogger("smart_attack.celery")

# ---------------------------------------------------------------------------
# 配置 — 从环境变量读取
# ---------------------------------------------------------------------------
CELERY_BROKER_URL = os.getenv("CELERY_BROKER_URL", os.getenv("REDIS_URL", "redis://localhost:6379/0"))
CELERY_RESULT_BACKEND = os.getenv("CELERY_RESULT_BACKEND", CELERY_BROKER_URL)
CELERY_ENABLED = os.getenv("CELERY_ENABLED", "auto").lower()  # auto | true | false


def is_celery_available() -> bool:
    """检测 Celery + Redis 是否可用。"""
    if CELERY_ENABLED == "false":
        return False
    if CELERY_ENABLED == "true":
        return True
    # auto 模式：尝试连接 Redis
    try:
        import redis
        r = redis.Redis.from_url(CELERY_BROKER_URL, socket_connect_timeout=2)
        r.ping()
        r.close()
        logger.info("Celery/Redis 可用，将使用异步任务队列")
        return True
    except Exception:
        logger.info("Celery/Redis 不可用，降级到 threading 模式")
        return False


# ---------------------------------------------------------------------------
# Celery 应用实例（延迟初始化）
# ---------------------------------------------------------------------------
_celery_app = None


def get_celery_app():
    """延迟获取 Celery 应用实例。"""
    global _celery_app
    if _celery_app is not None:
        return _celery_app

    if not is_celery_available():
        return None

    try:
        from celery import Celery

        _celery_app = Celery(
            "smart_attack",
            broker=CELERY_BROKER_URL,
            backend=CELERY_RESULT_BACKEND,
        )

        _celery_app.conf.update(
            task_serializer="json",
            accept_content=["json"],
            result_serializer="json",
            timezone="UTC",
            enable_utc=True,
            task_track_started=True,
            task_acks_late=True,           # 任务完成后才确认（防止 Worker 崩溃丢失任务）
            worker_prefetch_multiplier=1,   # 每次只取一个任务（公平分发）
            task_soft_time_limit=600,       # 10 分钟软超时
            task_time_limit=900,            # 15 分钟硬超时
            result_expires=3600,            # 结果 1 小时后过期
            task_routes={
                "smart_attacking.celery_app.run_scan_task": {"queue": "scan_queue"},
                "smart_attacking.celery_app.run_shadow_scan_task": {"queue": "scan_queue"},
            },
            task_default_priority=5,
        )

        logger.info("Celery 应用已初始化: broker=%s", CELERY_BROKER_URL)
        return _celery_app
    except ImportError:
        logger.warning("celery 包未安装，Celery 模式不可用")
        return None
    except Exception as e:
        logger.warning("Celery 初始化失败: %s", e)
        return None


# ---------------------------------------------------------------------------
# Celery Tasks（定义任务签名，实际逻辑委托给 task_runner）
# ---------------------------------------------------------------------------


def submit_celery_scan(scan_id: str, target_url: str, model_provider: str = None,
                       model_name: str = None, auth_config: dict = None,
                       custom_base_url: str = None) -> bool:
    """通过 Celery 提交异步扫描任务。

    Returns:
        True 如果成功提交到 Celery，False 如果 Celery 不可用。
    """
    celery = get_celery_app()
    if celery is None:
        return False

    try:
        # 委托给 task_runner 中的实际执行函数
        from task_runner import _execute_scan_logic
        celery.send_task(
            "smart_attacking.celery_app.run_scan_task",
            args=(scan_id, target_url, model_provider, model_name, auth_config, custom_base_url),
            queue="scan_queue",
        )
        logger.info("Celery 任务已提交: scan_id=%s", scan_id)
        return True
    except Exception as e:
        logger.warning("Celery 任务提交失败: %s", e)
        return False


# 注册 Celery 任务（由 Worker 执行）
def _register_tasks():
    """注册 Celery 任务。在 Worker 启动时调用。"""
    celery = get_celery_app()
    if celery is None:
        return

    @celery.task(name="smart_attacking.celery_app.run_scan_task", bind=True, max_retries=2)
    def run_scan_task(self, scan_id: str, target_url: str, model_provider=None,
                      model_name=None, auth_config=None, custom_base_url=None):
        """Celery 任务：执行完整扫描流水线。"""
        try:
            from task_runner import _execute_scan_logic
            _execute_scan_logic(scan_id, target_url, model_provider, model_name,
                                auth_config, custom_base_url)
            return {"scan_id": scan_id, "status": "completed"}
        except Exception as e:
            logger.error("Celery 扫描任务失败 [%s]: %s", scan_id, e)
            # 自动重试（最多 2 次）
            if self.request.retries < self.max_retries:
                raise self.retry(exc=e, countdown=30)
            return {"scan_id": scan_id, "status": "failed", "error": str(e)}

    @celery.task(name="smart_attacking.celery_app.run_shadow_scan_task", bind=True, max_retries=1)
    def run_shadow_scan_task(self, scan_id: str, base_url: str, shadow_apis: list,
                             model_provider=None, model_name=None):
        """Celery 任务：执行影子 API 扫描。"""
        try:
            from task_runner import _execute_shadow_scan_logic
            _execute_shadow_scan_logic(scan_id, base_url, shadow_apis, model_provider, model_name)
            return {"scan_id": scan_id, "status": "completed"}
        except Exception as e:
            logger.error("Celery 影子扫描任务失败 [%s]: %s", scan_id, e)
            if self.request.retries < self.max_retries:
                raise self.retry(exc=e, countdown=30)
            return {"scan_id": scan_id, "status": "failed", "error": str(e)}

    logger.info("Celery 任务已注册: run_scan_task, run_shadow_scan_task")


# 模块加载时注册任务
try:
    _register_tasks()
except Exception:
    pass
