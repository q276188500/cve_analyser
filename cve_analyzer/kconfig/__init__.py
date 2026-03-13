"""
Kconfig 分析模块

分析漏洞触发的内核配置依赖
"""

from cve_analyzer.kconfig.base import (
    KconfigAnalyzer,
    AnalysisResult,
    ConfigItem,
    RiskAssessment,
    ConfigStatus,
    RiskLevel,
)
from cve_analyzer.kconfig.parser import KconfigParser
from cve_analyzer.kconfig.loader import RuleLoader
from cve_analyzer.kconfig.graph import DependencyGraph
from cve_analyzer.kconfig.analyzer import KconfigAnalyzer as KconfigAnalyzerImpl

# 默认导出实现类
KconfigAnalyzer = KconfigAnalyzerImpl

__all__ = [
    "KconfigAnalyzer",
    "AnalysisResult",
    "ConfigItem",
    "RiskAssessment",
    "ConfigStatus",
    "RiskLevel",
    "KconfigParser",
    "RuleLoader",
    "DependencyGraph",
]
