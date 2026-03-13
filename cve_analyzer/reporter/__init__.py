"""
报告生成模块
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List

from cve_analyzer.core.models import CVE, Patch


class ReportFormat(str, Enum):
    """报告格式枚举"""
    JSON = "json"
    MARKDOWN = "markdown"
    HTML = "html"
    CSV = "csv"


@dataclass
class Statistics:
    """统计信息"""
    total_cves: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    patched_count: int = 0
    pending_count: int = 0


@dataclass
class ReportData:
    """报告数据"""
    title: str
    generated_at: str
    cves: List[CVE]
    patches: List[Patch]
    statistics: Statistics
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ReporterOptions:
    """报告选项"""
    include_patches: bool = True
    include_diffs: bool = False
    include_history: bool = False
    include_kconfig: bool = False
    template_path: Optional[str] = None


class Reporter(ABC):
    """报告生成器基类"""
    
    @abstractmethod
    def generate(self, data: ReportData, format: ReportFormat) -> str:
        """
        生成报告
        
        Args:
            data: 报告数据
            format: 报告格式
        
        Returns:
            报告内容或文件路径
        """
        pass
    
    @abstractmethod
    def generate_batch(self, data: List[ReportData], format: ReportFormat) -> str:
        """
        批量生成报告
        
        Args:
            data: 报告数据列表
            format: 报告格式
        
        Returns:
            报告内容或文件路径
        """
        pass
