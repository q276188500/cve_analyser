"""
补丁历史追踪基础定义
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Optional, Dict, Any


class ChangeType(Enum):
    """变更类型"""
    FIXUP = "fixup"           # 修复补丁的修正
    REVERT = "revert"         # 回退补丁
    REFACTOR = "refactor"     # 代码重构
    FOLLOW_UP = "follow_up"   # 后续相关修改
    BACKPORT = "backport"     # 回溯移植
    CONFLICT_FIX = "conflict_fix"  # 冲突修复
    UNKNOWN = "unknown"       # 未知类型


@dataclass
class TrackedChange:
    """追踪到的变更"""
    commit_hash: str
    commit_subject: str
    author: str
    author_email: str
    commit_date: datetime
    change_type: ChangeType
    parent_commit: Optional[str] = None
    related_commits: List[str] = field(default_factory=list)
    files_changed: List[str] = field(default_factory=list)
    stats: Dict[str, Any] = field(default_factory=dict)
    description: Optional[str] = None
    confidence: float = 0.0   # 类型判断置信度


@dataclass
class HistoryResult:
    """历史追踪结果"""
    cve_id: str
    patch_commit: str
    original_subject: str
    changes: List[TrackedChange] = field(default_factory=list)
    summary: Dict[str, int] = field(default_factory=dict)
    analysis: Dict[str, Any] = field(default_factory=dict)
    
    def get_changes_by_type(self, change_type: ChangeType) -> List[TrackedChange]:
        """按类型获取变更"""
        return [c for c in self.changes if c.change_type == change_type]
    
    def has_revert(self) -> bool:
        """检查是否有回退"""
        return any(c.change_type == ChangeType.REVERT for c in self.changes)
    
    def has_fixups(self) -> bool:
        """检查是否有修复修正"""
        return any(c.change_type == ChangeType.FIXUP for c in self.changes)
    
    def get_latest_status(self) -> str:
        """获取补丁最新状态"""
        if not self.changes:
            return "original"
        
        # 按时间排序
        sorted_changes = sorted(self.changes, key=lambda c: c.commit_date, reverse=True)
        latest = sorted_changes[0]
        
        if latest.change_type == ChangeType.REVERT:
            return "reverted"
        elif latest.change_type == ChangeType.FIXUP:
            return "fixed"
        elif latest.change_type == ChangeType.REFACTOR:
            return "refactored"
        else:
            return "modified"


class HistoryTracker(ABC):
    """历史追踪器接口"""
    
    @abstractmethod
    def track(self, patch_commit: str, cve_id: Optional[str] = None) -> HistoryResult:
        """
        追踪补丁的历史
        
        Args:
            patch_commit: 补丁的 commit hash
            cve_id: 可选的 CVE ID
        
        Returns:
            历史追踪结果
        """
        pass
    
    @abstractmethod
    def find_related_commits(
        self, 
        patch_commit: str,
        look_ahead: int = 100
    ) -> List[Dict[str, Any]]:
        """
        查找补丁后的相关 commits
        
        Args:
            patch_commit: 补丁 commit hash
            look_ahead: 向后查找的 commit 数量
        
        Returns:
            相关 commit 列表
        """
        pass
