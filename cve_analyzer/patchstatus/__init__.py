"""
补丁状态检测模块
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any

from cve_analyzer.core.models import PatchStatus, KconfigAnalysis
from cve_analyzer.utils.git import GitRepository


class PatchStatusEnum(str, Enum):
    """补丁状态枚举"""
    APPLIED = "APPLIED"      # 已应用
    PENDING = "PENDING"      # 未应用 (存在漏洞)
    MODIFIED = "MODIFIED"    # 已修改 (不是原补丁)
    REVERTED = "REVERTED"    # 已回退
    UNKNOWN = "UNKNOWN"      # 未知


class DetectionMethod(str, Enum):
    """检测方法枚举"""
    COMMIT_HASH = "commit_hash"    # Commit hash 精确匹配
    FILE_HASH = "file_hash"        # 文件哈希匹配
    CONTENT = "content_match"      # 代码内容特征匹配
    AST = "ast_match"              # AST 特征匹配


@dataclass
class TargetCode:
    """目标代码信息"""
    version: str                           # 内核版本号
    path: str                              # 代码路径
    repo: Optional[GitRepository] = None   # Git 仓库
    config: Optional[KconfigAnalysis] = None  # 配置分析结果


@dataclass
class DetectionResult:
    """检测结果"""
    cve_id: str
    target_version: str
    status: PatchStatusEnum
    confidence: float                      # 置信度 (0-1)
    detection_method: DetectionMethod
    matched_commit: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)


class PatchDetector(ABC):
    """补丁状态检测器基类"""
    
    @abstractmethod
    def detect(self, cve_id: str, target: TargetCode) -> DetectionResult:
        """
        检测补丁在目标代码中的状态
        
        Args:
            cve_id: CVE ID
            target: 目标代码信息
        
        Returns:
            检测结果
        """
        pass
    
    @abstractmethod
    def detect_batch(self, cve_ids: List[str], target: TargetCode) -> List[DetectionResult]:
        """
        批量检测
        
        Args:
            cve_ids: CVE ID 列表
            target: 目标代码信息
        
        Returns:
            检测结果列表
        """
        pass
