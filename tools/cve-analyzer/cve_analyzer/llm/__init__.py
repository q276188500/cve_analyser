"""
LLM 大模型集成模块

提供智能 CVE 分析、报告生成等功能
"""

from cve_analyzer.llm.base import (
    LLMProvider,
    LLMResponse,
    OpenAIProvider,
    ClaudeProvider,
    MinimaxProvider,
    LLMFactory,
)

from cve_analyzer.llm.analyzer import (
    LLMVulnerabilityAnalyzer,
    LLMReportGenerator,
)

from cve_analyzer.llm.cache import LLMCache

from cve_analyzer.llm.agent import analyze_patch_sync

__all__ = [
    'LLMProvider',
    'LLMResponse',
    'OpenAIProvider',
    'ClaudeProvider',
    'MinimaxProvider',
    'LLMFactory',
    'LLMVulnerabilityAnalyzer',
    'LLMReportGenerator',
    'LLMCache',
    'analyze_patch_sync',
]
