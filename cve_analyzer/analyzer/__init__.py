"""
补丁分析器核心模块

提供 CVE 补丁分析和版本影响分析功能
"""

from cve_analyzer.analyzer.core import Analyzer
from cve_analyzer.analyzer.extractor import PatchExtractor
from cve_analyzer.analyzer.parser import CommitParser
from cve_analyzer.analyzer.version_impact import VersionImpactAnalyzer
from dataclasses import dataclass
from typing import List


@dataclass
class AnalysisResult:
    """分析结果"""
    cve: "CVE"
    patches: List["Patch"]
    affected_files: List[str]
    affected_functions: List[str]
    version_impact: "VersionImpact"


@dataclass
class VersionImpact:
    """版本影响分析结果"""
    mainline_affected: List[str]      # 受影响的主线版本
    stable_affected: List[str]        # 受影响的 stable 版本
    longterm_affected: List[str]      # 受影响的 longterm 版本
    backported_to: List[str]          # 已回溯到的版本
    not_backported_to: List[str]      # 未回溯的版本


__all__ = [
    "Analyzer",
    "PatchExtractor",
    "CommitParser",
    "VersionImpactAnalyzer",
    "AnalysisResult",
    "VersionImpact",
]
