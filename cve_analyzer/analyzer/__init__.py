"""
补丁分析器核心模块

提供 CVE 补丁分析和版本影响分析功能
"""

from cve_analyzer.analyzer.core import Analyzer, AnalysisResult, VersionImpact
from cve_analyzer.analyzer.extractor import PatchExtractor
from cve_analyzer.analyzer.parser import CommitParser
from cve_analyzer.analyzer.version_impact import VersionImpactAnalyzer


__all__ = [
    "Analyzer",
    "PatchExtractor",
    "CommitParser",
    "VersionImpactAnalyzer",
    "AnalysisResult",
    "VersionImpact",
]