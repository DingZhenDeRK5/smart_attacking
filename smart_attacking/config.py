"""
智攻 (SmartAttack) — 集中配置管理
==============================
所有可调参数通过环境变量控制，支持 .env 文件加载。
"""

import logging
import os

logger = logging.getLogger("smart_attack.config")

# ---------------------------------------------------------------------------
# 尝试加载 .env 文件（python-dotenv 为可选依赖）
# ---------------------------------------------------------------------------
try:
    from dotenv import load_dotenv

    _env_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if os.path.isfile(_env_file):
        load_dotenv(_env_file)
        logger.info("已加载 .env 配置文件: %s", _env_file)
except ImportError:
    pass  # python-dotenv 未安装时静默跳过

# ---------------------------------------------------------------------------
# LLM 提供者配置（通用，向后兼容旧 DEEPSEEK_* 变量）
# ---------------------------------------------------------------------------
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "deepseek")  # deepseek | openai | anthropic | custom
LLM_API_KEY = os.getenv("LLM_API_KEY") or os.getenv("DEEPSEEK_API_KEY")
LLM_MODEL = os.getenv("LLM_MODEL") or os.getenv("DEEPSEEK_MODEL", "deepseek-chat")
LLM_BASE_URL = os.getenv("LLM_BASE_URL", "")  # 自定义 OpenAI 兼容端点（仅 custom provider）

# 向后兼容别名（旧代码可能引用）
API_KEY = LLM_API_KEY
BASE_URL = LLM_BASE_URL or os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
MODEL = LLM_MODEL

if not LLM_API_KEY:
    logger.warning("⚠️  未检测到 LLM_API_KEY 或 DEEPSEEK_API_KEY 环境变量！")
    logger.warning("   请设置环境变量或在 smart_attacking/.env 文件中配置。")
    logger.warning("   例如: LLM_API_KEY=sk-xxxxxxxxxxxxxxxx")

# ---------------------------------------------------------------------------
# 扫描器服务配置
# ---------------------------------------------------------------------------
HOST = os.getenv("SCANNER_HOST", "127.0.0.1")
try:
    PORT = int(os.getenv("SCANNER_PORT", "8888"))
except ValueError:
    PORT = 8888
    logger.warning("SCANNER_PORT 值无效，使用默认 8888")

DEBUG_MODE = os.getenv("FLASK_DEBUG", "false").lower() == "true"

# ---------------------------------------------------------------------------
# 攻击执行参数
# ---------------------------------------------------------------------------
HTTP_TIMEOUT = int(os.getenv("SCANNER_HTTP_TIMEOUT", "8"))
MAX_WORKERS = int(os.getenv("SCANNER_MAX_WORKERS", "5"))
ENABLE_FOLLOWUP = os.getenv("SCANNER_FOLLOWUP", "true").lower() == "true"

# ---------------------------------------------------------------------------
# 存储配置
# ---------------------------------------------------------------------------
STORAGE_DIR = os.getenv(
    "SCANNER_STORAGE_DIR",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "storage", "scans"),
)

# 数据库 URL（SQLite 默认，可切换 PostgreSQL）
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    f"sqlite:///{os.path.join(os.path.dirname(os.path.abspath(__file__)), 'storage', 'smartattack.db')}",
)
