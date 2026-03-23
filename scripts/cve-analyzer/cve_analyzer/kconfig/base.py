"""
Kconfig 分析模块

分析漏洞触发的内核配置依赖
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class ConfigStatus(str, Enum):
    """配置状态枚举"""
    VULNERABLE = "VULNERABLE"      # 配置存在漏洞
    PATCHED = "PATCHED"            # 已修复
    NOT_APPLICABLE = "NOT_APPLICABLE"  # 不适用
    UNKNOWN = "UNKNOWN"            # 未知


class RiskLevel(str, Enum):
    """风险等级枚举"""
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class ConfigItem:
    """配置项"""
    name: str              # CONFIG_XXX
    value: str             # y/m/n/数值
    description: str = ""  # 配置描述
    dependencies: List[str] = field(default_factory=list)  # 依赖的配置
    selected_by: List[str] = field(default_factory=list)   # 被谁选中


@dataclass
class RiskAssessment:
    """风险评估"""
    risk_level: RiskLevel
    exploitable: bool
    required_enabled: List[str] = field(default_factory=list)
    required_disabled: List[str] = field(default_factory=list)
    optional_enabled: List[str] = field(default_factory=list)


@dataclass
class AnalysisResult:
    """Kconfig 分析结果"""
    cve: "CVE"
    kernel_version: str
    config_status: ConfigStatus
    required_configs: List[ConfigItem] = field(default_factory=list)
    active_configs: List[ConfigItem] = field(default_factory=list)
    missing_configs: List[ConfigItem] = field(default_factory=list)
    risk_level: RiskLevel = RiskLevel.LOW
    exploitable: bool = False
    exploit_conditions: str = ""
    mitigation_configs: List[str] = field(default_factory=list)
    suggested_config: str = ""


class KconfigAnalyzer(ABC):
    """Kconfig 分析器基类"""
    
    @abstractmethod
    def analyze(self, cve_id: str, kernel_version: str, config_path: str) -> AnalysisResult:
        """
        分析 CVE 的 Kconfig 依赖
        
        Args:
            cve_id: CVE ID
            kernel_version: 内核版本
            config_path: .config 文件路径
        
        Returns:
            分析结果
        """
        pass
    
    @abstractmethod
    def parse_config(self, config_path: str) -> Dict[str, str]:
        """
        解析 .config 文件
        
        Args:
            config_path: .config 文件路径
        
        Returns:
            配置字典 {CONFIG_XXX: value}
        """
        pass
    
    @abstractmethod
    def evaluate_risk(self, cve_id: str, config: Dict[str, str]) -> RiskAssessment:
        """
        评估配置风险
        
        Args:
            cve_id: CVE ID
            config: 配置字典
        
        Returns:
            风险评估结果
        """
        pass
