"""
LLM 大模型集成模块

支持多提供商:
- OpenAI (GPT-4/GPT-5)
- Anthropic (Claude)
- 本地模型 (Ollama)
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Dict, Any, Optional, List
import os


@dataclass
class LLMResponse:
    """LLM 响应结构"""
    content: str
    model: str
    tokens_used: int
    cost_usd: float
    metadata: Dict[str, Any]


class LLMProvider(ABC):
    """LLM 提供商基类"""

    def __init__(self, model: Optional[str] = None):
        self.model = model or self._default_model()

    @abstractmethod
    def _default_model(self) -> str:
        """返回默认模型名称"""
        pass

    @abstractmethod
    async def chat(self, messages: List[Dict[str, str]], **kwargs) -> LLMResponse:
        """
        对话接口

        Args:
            messages: [{"role": "system"/"user"/"assistant", "content": "..."}]
            **kwargs: 额外参数 (temperature, max_tokens 等)

        Returns:
            LLMResponse 对象
        """
        pass

    @abstractmethod
    def estimate_cost(self, input_tokens: int, output_tokens: int) -> float:
        """估算成本 (USD)"""
        pass


class OpenAIProvider(LLMProvider):
    """OpenAI GPT 接口"""

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        if not self.api_key:
            raise ValueError("OpenAI API key required. Set OPENAI_API_KEY env var.")

        super().__init__(model)

        try:
            import openai
            self.client = openai.AsyncOpenAI(api_key=self.api_key)
        except ImportError:
            raise ImportError("OpenAI package not installed. Run: pip install openai")

    def _default_model(self) -> str:
        return "gpt-4"

    async def chat(self, messages: List[Dict[str, str]], **kwargs) -> LLMResponse:
        import openai

        try:
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=kwargs.get("temperature", 0.3),
                max_tokens=kwargs.get("max_tokens", 4000),
            )

            content = response.choices[0].message.content
            tokens_in = response.usage.prompt_tokens
            tokens_out = response.usage.completion_tokens

            return LLMResponse(
                content=content,
                model=self.model,
                tokens_used=tokens_in + tokens_out,
                cost_usd=self.estimate_cost(tokens_in, tokens_out),
                metadata={"finish_reason": response.choices[0].finish_reason}
            )
        except openai.APIError as e:
            raise RuntimeError(f"OpenAI API error: {e}")

    def estimate_cost(self, input_tokens: int, output_tokens: int) -> float:
        """估算成本 (USD) - GPT-4 价格"""
        prices = {
            "gpt-4": (0.03, 0.06),  # input, output per 1K tokens
            "gpt-4-turbo": (0.01, 0.03),
            "gpt-3.5-turbo": (0.0005, 0.0015),
        }
        input_price, output_price = prices.get(self.model, (0.03, 0.06))
        return (input_tokens / 1000 * input_price) + (output_tokens / 1000 * output_price)


class ClaudeProvider(LLMProvider):
    """Anthropic Claude 接口"""

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        if not self.api_key:
            raise ValueError("Anthropic API key required. Set ANTHROPIC_API_KEY env var.")

        super().__init__(model)

        try:
            import anthropic
            self.client = anthropic.AsyncAnthropic(api_key=self.api_key)
        except ImportError:
            raise ImportError("Anthropic package not installed. Run: pip install anthropic")

    def _default_model(self) -> str:
        return "claude-3-opus-20240229"

    async def chat(self, messages: List[Dict[str, str]], **kwargs) -> LLMResponse:
        # 转换消息格式为 Claude 格式
        system_msg = ""
        user_msgs = []

        for msg in messages:
            if msg["role"] == "system":
                system_msg = msg["content"]
            elif msg["role"] == "user":
                user_msgs.append({"role": "user", "content": msg["content"]})
            elif msg["role"] == "assistant":
                user_msgs.append({"role": "assistant", "content": msg["content"]})

        try:
            response = await self.client.messages.create(
                model=self.model,
                max_tokens=kwargs.get("max_tokens", 4000),
                temperature=kwargs.get("temperature", 0.3),
                system=system_msg,
                messages=user_msgs,
            )

            content = response.content[0].text
            tokens_in = response.usage.input_tokens
            tokens_out = response.usage.output_tokens

            return LLMResponse(
                content=content,
                model=self.model,
                tokens_used=tokens_in + tokens_out,
                cost_usd=self.estimate_cost(tokens_in, tokens_out),
                metadata={}
            )
        except Exception as e:
            raise RuntimeError(f"Claude API error: {e}")

    def estimate_cost(self, input_tokens: int, output_tokens: int) -> float:
        """估算成本 (USD) - Claude 3 Opus 价格"""
        prices = {
            "claude-3-opus-20240229": (0.015, 0.075),
            "claude-3-sonnet-20240229": (0.003, 0.015),
            "claude-3-haiku-20240307": (0.00025, 0.00125),
        }
        input_price, output_price = prices.get(self.model, (0.015, 0.075))
        return (input_tokens / 1000 * input_price) + (output_tokens / 1000 * output_price)


class LLMFactory:
    """LLM 提供商工厂"""

    @staticmethod
    def create(provider: str, **kwargs) -> LLMProvider:
        """
        创建 LLM 提供商实例

        Args:
            provider: "openai", "claude", "ollama"
            **kwargs: 传递给提供商构造函数的参数

        Returns:
            LLMProvider 实例
        """
        providers = {
            "openai": OpenAIProvider,
            "claude": ClaudeProvider,
            
        }

        if provider not in providers:
            raise ValueError(f"Unknown provider: {provider}. Available: {list(providers.keys())}")

        return providers[provider](**kwargs)
