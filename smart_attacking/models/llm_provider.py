"""
智攻 (SmartAttack) — LLM 提供者抽象层
=====================================
支持多种大模型后端，可切换、可扩展。
当前支持：DeepSeek、OpenAI、Anthropic Claude、自定义 OpenAI 兼容端点。

设计原则：
- 统一接口：所有 Provider 实现相同的 chat() 方法
- 工厂模式：create_llm_provider() 根据配置返回对应实例
- 可选依赖：Anthropic SDK 仅在需要时才导入
"""

import logging

from openai import OpenAI

try:
    from config import LLM_API_KEY, LLM_BASE_URL, LLM_MODEL, LLM_PROVIDER
except ImportError:
    from smart_attacking.config import LLM_API_KEY, LLM_BASE_URL, LLM_MODEL, LLM_PROVIDER

logger = logging.getLogger("smart_attack.llm_provider")


# ======================================================================
# 抽象基类
# ======================================================================


class LLMProvider:
    """LLM 提供者抽象基类。"""

    def __init__(self, api_key: str, model: str):
        if not api_key:
            raise ValueError(f"未配置 API Key（provider={self.__class__.__name__}）")
        self.api_key = api_key
        self.model = model

    def chat(self, system_prompt: str, user_prompt: str,
             temperature: float = 0.7, max_tokens: int = 8000) -> str:
        """发送对话请求，返回模型文本响应。"""
        raise NotImplementedError


# ======================================================================
# DeepSeek Provider
# ======================================================================


class DeepSeekProvider(LLMProvider):
    """DeepSeek API（OpenAI 兼容接口）。"""

    def __init__(self, api_key: str, model: str = "deepseek-chat"):
        super().__init__(api_key, model)
        self.client = OpenAI(
            api_key=api_key,
            base_url="https://api.deepseek.com",
            timeout=120,
        )

    def chat(self, system_prompt: str, user_prompt: str,
             temperature: float = 0.7, max_tokens: int = 8000) -> str:
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=temperature,
            max_tokens=max_tokens,
        )
        return response.choices[0].message.content


# ======================================================================
# OpenAI Provider
# ======================================================================


class OpenAIProvider(LLMProvider):
    """OpenAI 官方 API。"""

    def __init__(self, api_key: str, model: str = "gpt-4o"):
        super().__init__(api_key, model)
        self.client = OpenAI(api_key=api_key, timeout=120)

    def chat(self, system_prompt: str, user_prompt: str,
             temperature: float = 0.7, max_tokens: int = 8000) -> str:
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=temperature,
            max_tokens=max_tokens,
        )
        return response.choices[0].message.content


# ======================================================================
# Anthropic Claude Provider
# ======================================================================


class AnthropicProvider(LLMProvider):
    """Anthropic Claude API。

    需要安装: pip install anthropic
    """

    def __init__(self, api_key: str, model: str = "claude-sonnet-4-20250514"):
        super().__init__(api_key, model)
        try:
            import anthropic

            self.client = anthropic.Anthropic(api_key=api_key, timeout=120)
        except ImportError:
            raise ImportError(
                "使用 Anthropic provider 需要安装 anthropic 包。\n"
                "请运行: pip install anthropic"
            )

    def chat(self, system_prompt: str, user_prompt: str,
             temperature: float = 0.7, max_tokens: int = 8000) -> str:
        response = self.client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
            temperature=temperature,
        )
        return response.content[0].text


# ======================================================================
# 自定义 OpenAI 兼容 Provider（Ollama / vLLM / LM Studio 等）
# ======================================================================


class CustomOpenAICompatibleProvider(LLMProvider):
    """任意 OpenAI 兼容端点（本地模型、第三方代理等）。"""

    def __init__(self, api_key: str, base_url: str, model: str):
        if not base_url:
            raise ValueError("使用自定义 provider 需要设置 LLM_BASE_URL")
        super().__init__(api_key, model)
        self.client = OpenAI(api_key=api_key, base_url=base_url, timeout=120)

    def chat(self, system_prompt: str, user_prompt: str,
             temperature: float = 0.7, max_tokens: int = 8000) -> str:
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=temperature,
            max_tokens=max_tokens,
        )
        return response.choices[0].message.content


# ======================================================================
# 工厂函数
# ======================================================================

# 模块级缓存
_provider_cache: dict = {}


def create_llm_provider(provider: str = None, model: str = None,
                        api_key: str = None, base_url: str = None) -> LLMProvider:
    """根据参数创建 LLM Provider 实例。

    Args:
        provider: deepseek | openai | anthropic | custom（默认用 config 中的 LLM_PROVIDER）
        model: 模型名称（默认用 config 中的 LLM_MODEL）
        api_key: API Key（默认用 config 中的 LLM_API_KEY）
        base_url: 自定义端点 URL（仅 custom provider 需要）

    Returns:
        LLMProvider 实例
    """
    _provider = provider or LLM_PROVIDER
    _model = model or LLM_MODEL
    _api_key = api_key or LLM_API_KEY
    _base_url = base_url or LLM_BASE_URL

    # 缓存键（同一配置复用实例）
    cache_key = f"{_provider}:{_model}:{_api_key[:8] if _api_key else ''}"
    if cache_key in _provider_cache:
        return _provider_cache[cache_key]

    if _provider == "deepseek":
        instance = DeepSeekProvider(_api_key, _model)
    elif _provider == "openai":
        instance = OpenAIProvider(_api_key, _model)
    elif _provider == "anthropic":
        instance = AnthropicProvider(_api_key, _model)
    elif _provider == "custom":
        instance = CustomOpenAICompatibleProvider(_api_key, _base_url, _model)
    else:
        raise ValueError(
            f"未知的 LLM_PROVIDER: {_provider}。"
            f"支持: deepseek, openai, anthropic, custom"
        )

    _provider_cache[cache_key] = instance
    logger.info("LLM Provider 已初始化: %s / %s", _provider, _model)
    return instance


def get_cached_provider() -> LLMProvider:
    """获取默认配置的 LLM Provider（首次调用时创建并缓存）。"""
    return create_llm_provider()
