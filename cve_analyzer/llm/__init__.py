"""
LLM 大模型集成模块

提供智能 CVE 分析、报告生成等功能
"""

from cve_analyzer.llm.base import (
    LLMProvider,
    LLMResponse,
    OpenAIProvider,
    ClaudeProvider,
    OllamaProvider,
    LLMFactory,
)

from cve_analyzer.llm.analyzer import (
    LLMVulnerabilityAnalyzer,
    LLMReportGenerator,
)

from cve_analyzer.llm.cache import LLMCache

__all__ = [
    'LLMProvider',
    'LLMResponse',
    'OpenAIProvider',
    'ClaudeProvider',
    'OllamaProvider',
    'LLMFactory',
    'LLMVulnerabilityAnalyzer',
    'LLMReportGenerator',
    'LLMCache',
]
