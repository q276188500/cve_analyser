"""
补丁历史追踪模块

追踪 CVE 修复补丁后的修改历史，包括:
- Fixup commits (修复补丁的修正)
- Revert commits (补丁被回退)
- Refactor commits (代码重构)
- Follow-up commits (后续相关修改)
"""

from cve_analyzer.history.base import (
    HistoryTracker,
    TrackedChange,
    ChangeType,
    HistoryResult,
)
from cve_analyzer.history.tracker import GitHistoryTracker
from cve_analyzer.history.analyzer import HistoryAnalyzer

# 默认导出
HistoryTracker = GitHistoryTracker

__all__ = [
    "HistoryTracker",
    "TrackedChange",
    "ChangeType",
    "HistoryResult",
    "GitHistoryTracker",
    "HistoryAnalyzer",
]
