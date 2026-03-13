"""
补丁分析模块
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Optional

from cve_analyzer.core.models import CVE, Patch
from cve_analyzer.utils.git import GitRepository


@dataclass
class AnalysisResult:
    """分析结果"""
    cve: CVE
    patches: List[Patch]
    affected_files: List[str]
    affected_functions: List[str]
    version_impact: "VersionImpact"


@dataclass
class VersionImpact:
    """版本影响分析结果"""
    mainline_affected: List[str]  # 受影响的主线版本
    stable_affected: List[str]    # 受影响的 stable 版本
    longterm_affected: List[str]  # 受影响的 longterm 版本
    backported_to: List[str]      # 已回溯到的版本
    not_backported_to: List[str]  # 未回溯的版本


class Analyzer(ABC):
    """补丁分析器基类"""
    
    @abstractmethod
    def analyze(self, cve: CVE) -> AnalysisResult:
        """
        分析 CVE 补丁
        
        Args:
            cve: CVE 对象
        
        Returns:
            分析结果
        """
        pass
    
    @abstractmethod
    def extract_patches(self, cve: CVE) -> List[Patch]:
        """
        从 CVE 提取补丁信息
        
        Args:
            cve: CVE 对象
        
        Returns:
            补丁列表
        """
        pass
    
    @abstractmethod
    def analyze_version_impact(self, patch: Patch) -> VersionImpact:
        """
        分析版本影响范围
        
        Args:
            patch: 补丁对象
        
        Returns:
            版本影响分析结果
        """
        pass


class PatchExtractor(ABC):
    """补丁提取器基类"""
    
    @abstractmethod
    def extract_from_commit(self, repo: GitRepository, commit_hash: str) -> Patch:
        """从 Git commit 提取补丁"""
        pass
    
    @abstractmethod
    def extract_from_url(self, url: str) -> Patch:
        """从 URL 提取补丁"""
        pass
    
    @abstractmethod
    def extract_from_mbox(self, content: str) -> List[Patch]:
        """从 mbox 格式提取补丁"""
        pass
