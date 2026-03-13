"""
补丁状态检测模块

检测 CVE 修复补丁在目标代码中的应用状态
"""

from cve_analyzer.patchstatus.base import (
    PatchDetector,
    DetectionResult,
    TargetCode,
    PatchStatusEnum,
    DetectionMethod,
)
from cve_analyzer.patchstatus.detector import (
    CommitHashDetector,
    FileHashDetector,
    RevertDetector,
)
from cve_analyzer.patchstatus.matcher import ContentMatcher
from cve_analyzer.patchstatus.core import MultiStrategyDetector

# 默认导出多策略检测器
PatchDetector = MultiStrategyDetector

__all__ = [
    "PatchDetector",
    "DetectionResult",
    "TargetCode",
    "PatchStatusEnum",
    "DetectionMethod",
    "CommitHashDetector",
    "FileHashDetector",
    "RevertDetector",
    "ContentMatcher",
    "MultiStrategyDetector",
]
