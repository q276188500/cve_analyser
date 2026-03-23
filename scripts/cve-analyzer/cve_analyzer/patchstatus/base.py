"""
补丁状态检测模块

检测 CVE 修复补丁在目标代码中的应用状态
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


class PatchStatusEnum(str, Enum):
    """补丁状态枚举"""
    APPLIED = "APPLIED"          # 已应用
    PENDING = "PENDING"          # 未应用 (存在漏洞)
    MODIFIED = "MODIFIED"        # 已修改 (不是原补丁)
    REVERTED = "REVERTED"        # 已回退
    UNKNOWN = "UNKNOWN"          # 未知


class DetectionMethod(str, Enum):
    """检测方法枚举"""
    COMMIT_HASH = "commit_hash"      # Commit hash 精确匹配
    FILE_HASH = "file_hash"          # 文件哈希匹配
    CONTENT = "content_match"        # 代码内容特征匹配
    AST = "ast_match"                # AST 特征匹配


@dataclass
class TargetCode:
    """目标代码信息"""
    version: str                           # 内核版本号
    path: str                              # 代码路径
    repo: Optional[Any] = None             # Git 仓库 (GitRepository)
    config: Optional[Any] = None           # 配置分析结果


@dataclass
class DetectionResult:
    """检测结果"""
    cve_id: str
    target_version: str
    status: PatchStatusEnum
    confidence: float                      # 置信度 (0-1)
    detection_method: DetectionMethod
    matched_commit: Optional[str] = None
    expected_hash: Optional[str] = None
    actual_hash: Optional[str] = None
    diff_summary: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    checked_at: datetime = field(default_factory=datetime.utcnow)


class PatchDetector(ABC):
    """补丁检测器基类"""
    
    @abstractmethod
    def detect(self, patch: Any, target: TargetCode) -> DetectionResult:
        """
        检测补丁在目标代码中的状态
        
        Args:
            patch: 补丁对象 (PatchData)
            target: 目标代码信息
        
        Returns:
            检测结果
        """
        pass
    
    def detect_batch(self, cve_ids: List[str], target: TargetCode) -> List[DetectionResult]:
        """
        批量检测
        
        Args:
            cve_ids: CVE ID 列表
            target: 目标代码信息
        
        Returns:
            检测结果列表
        """
        results = []
        for cve_id in cve_ids:
            # 从数据库获取补丁信息
            patch = self._get_patch_for_cve(cve_id)
            if patch:
                result = self.detect(patch, target)
                results.append(result)
        return results
    
    def _get_patch_for_cve(self, cve_id: str) -> Optional[Any]:
        """从数据库获取 CVE 的补丁"""
        # 这里需要实现数据库查询
        # 简化版本返回 None
        return None
