# LLM Provider - 大模型集成

import os
import json
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Dict, Any, Optional


@dataclass
class LLMResponse:
    """LLM 响应"""
    content: str
    model: str
    tokens_used: int = 0
    cost: float = 0.0


class LLMProvider(ABC):
    """LLM 提供商基类"""
    
    @abstractmethod
    def chat(self, messages: List[Dict], **kwargs) -> LLMResponse:
        pass
    
    @abstractmethod
    def analyze_patch(self, patch: str, context: Dict) -> Dict[str, Any]:
        pass


class OpenAIProvider(LLMProvider):
    """OpenAI GPT 接口"""
    
    def __init__(self, api_key: str = None, model: str = "gpt-4o", base_url: str = None):
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY")
        self.model = model
        self.base_url = base_url or os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1")
    
    def chat(self, messages: List[Dict], **kwargs) -> LLMResponse:
        try:
            from openai import OpenAI
        except ImportError:
            raise ImportError("openai package not installed: pip install openai")
        
        client = OpenAI(api_key=self.api_key, base_url=self.base_url)
        
        response = client.chat.completions.create(
            model=self.model,
            messages=messages,
            temperature=kwargs.get("temperature", 0.3),
            max_tokens=kwargs.get("max_tokens", 4000),
        )
        
        content = response.choices[0].message.content
        tokens = response.usage.total_tokens if response.usage else 0
        
        # 估算成本 (GPT-4o: $5/1M input, $15/1M output)
        cost = tokens * 5 / 1_000_000
        
        return LLMResponse(
            content=content,
            model=self.model,
            tokens_used=tokens,
            cost=cost
        )
    
    def analyze_patch(self, patch: str, context: Dict) -> Dict[str, Any]:
        """使用 LLM 分析 patch"""
        
        system_prompt = """你是一个 Linux 内核安全专家，擅长分析内核 patch 的影响。

请分析以下 patch，输出 JSON 格式的分析结果。

输出格式:
{
    "summary": "一句话概括这个 patch 修复了什么",
    "functional_impact": {
        "level": "high/medium/low",
        "description": "功能影响描述",
        "affected_components": ["受影响的组件列表"]
    },
    "performance_impact": {
        "level": "high/medium/low", 
        "description": "性能影响描述",
        "concerns": ["可能的性能问题"]
    },
    "security_impact": {
        "level": "high/medium/low",
        "description": "安全影响描述",
        "cve_fixes": ["CVE-XXXX-XXXX 如果有"],
        "vulnerability_type": "漏洞类型 (如果有)"
    },
    "compatibility_impact": {
        "level": "high/medium/low",
        "description": "兼容性影响描述",
        "breaking_changes": ["破坏性变更 (如果有)"]
    },
    "recommendation": {
        "action": "merge/review/defer",
        "reason": "建议理由",
        "confidence": 0.0-1.0,
        "requires_expertise_review": true/false
    },
    "risk_factors": ["风险因素列表"],
    "business_impact": "对业务的具体影响描述"
}"""

        knowledge_context = ""
        if context.get("knowledge_matches"):
            knowledge_context += "\n\n知识库约束:\n"
            for m in context["knowledge_matches"]:
                knowledge_context += f"- [{m.get('severity')}] {m.get('title')}: {m.get('description', '')[:100]}\n"

        user_prompt = f"""请分析以下 Linux 内核 patch:

## Patch 内容
```
{patch[:8000]}
```

## 基础分析结果 (仅供参考)
- 变更文件: {context.get('files_changed', [])}
- 代码行: +{context.get('lines_added', 0)} -{context.get('lines_deleted', 0)}
- 提交: {context.get('commit', 'N/A')}

{knowledge_context}

请给出专业的分析和建议。"""

        response = self.chat([
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ])

        # 解析 JSON 响应
        try:
            # 尝试提取 JSON
            content = response.content.strip()
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0]
            elif "```" in content:
                content = content.split("```")[1].split("```")[0]
            
            result = json.loads(content)
            result["_llm_metadata"] = {
                "model": response.model,
                "tokens": response.tokens_used,
                "cost": response.cost
            }
            return result
        except json.JSONDecodeError:
            return {
                "error": "Failed to parse LLM response",
                "raw_response": response.content,
                "_llm_metadata": {
                    "model": response.model,
                    "tokens": response.tokens_used,
                    "cost": response.cost
                }
            }


class ClaudeProvider(LLMProvider):
    """Anthropic Claude 接口"""
    
    def __init__(self, api_key: str = None, model: str = "claude-sonnet-4-20250514"):
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        self.model = model
    
    def chat(self, messages: List[Dict], **kwargs) -> LLMResponse:
        try:
            from anthropic import Anthropic
        except ImportError:
            raise ImportError("anthropic package not installed: pip install anthropic")
        
        client = Anthropic(api_key=self.api_key)
        
        # 转换消息格式
        system = ""
        claude_messages = []
        for msg in messages:
            if msg["role"] == "system":
                system = msg["content"]
            else:
                claude_messages.append(msg)
        
        response = client.messages.create(
            model=self.model,
            max_tokens=kwargs.get("max_tokens", 4000),
            temperature=kwargs.get("temperature", 0.3),
            system=system,
            messages=claude_messages
        )
        
        content = response.content[0].text
        tokens = response.usage.input_tokens + response.usage.output_tokens
        
        # 估算成本 (Claude Sonnet: $3/1M input, $15/1M output)
        cost = response.usage.input_tokens * 3 / 1_000_000 + response.usage.output_tokens * 15 / 1_000_000
        
        return LLMResponse(
            content=content,
            model=self.model,
            tokens_used=tokens,
            cost=cost
        )
    
    def analyze_patch(self, patch: str, context: Dict) -> Dict[str, Any]:
        """使用 Claude 分析 patch"""
        # 实现类似 OpenAI 的逻辑
        # 为简洁起见，复用类似的 prompt
        return {}


class OllamaProvider(LLMProvider):
    """本地 Ollama 接口"""
    
    def __init__(self, host: str = "http://localhost:11434", model: str = "llama3"):
        self.host = host
        self.model = model
    
    def chat(self, messages: List[Dict], **kwargs) -> LLMResponse:
        import requests
        
        url = f"{self.host}/api/chat"
        
        response = requests.post(url, json={
            "model": self.model,
            "messages": messages,
            "temperature": kwargs.get("temperature", 0.3),
        })
        
        if response.status_code != 200:
            raise Exception(f"Ollama error: {response.text}")
        
        data = response.json()
        
        return LLMResponse(
            content=data["message"]["content"],
            model=self.model,
            tokens_used=0,
            cost=0.0
        )
    
    def analyze_patch(self, patch: str, context: Dict) -> Dict[str, Any]:
        """使用 Ollama 分析 patch"""
        # Ollama 不一定能很好地解析 JSON，所以返回文本
        system_prompt = """你是一个 Linux 内核安全专家。分析以下 patch，简洁说明：
1. 修复了什么问题
2. 对业务的影响
3. 是否建议合入"""

        response = self.chat([
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"Patch:\n{patch[:5000]}"}
        ])
        
        return {
            "summary": response.content,
            "_llm_metadata": {"model": self.model},
            "_raw": True
        }


# Provider 工厂
class LLMFactory:
    """LLM 工厂类"""
    
    _providers = {
        "openai": OpenAIProvider,
        "claude": ClaudeProvider,
        "ollama": OllamaProvider,
    }
    
    @classmethod
    def create(cls, provider: str = "openai", **kwargs) -> LLMProvider:
        """创建 LLM Provider"""
        provider_class = cls._providers.get(provider.lower())
        if not provider_class:
            raise ValueError(f"Unknown provider: {provider}. Available: {list(cls._providers.keys())}")
        
        return provider_class(**kwargs)
    
    @classmethod
    def list_providers(cls) -> List[str]:
        """列出可用的 provider"""
        return list(cls._providers.keys())


def get_default_provider() -> Optional[LLMProvider]:
    """获取默认 provider"""
    # 按优先级尝试
    for provider_name in ["openai", "claude", "ollama"]:
        try:
            provider = LLMFactory.create(provider_name)
            # 简单测试
            if provider.api_key or provider_name == "ollama":
                return provider
        except Exception:
            continue
    return None
