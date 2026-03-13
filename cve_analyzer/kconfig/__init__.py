"""
Kconfig 分析模块
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional

from cve_analyzer.core.models import CVE, KconfigRule, KconfigAnalysis


class ConfigStatus(str, Enum):
    """Kconfig 状态枚举"""
    VULNERABLE = "VULNERABLE"
    PATCHED = "PATCHED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    UNKNOWN = "UNKNOWN"


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
    dependencies: List[str] = None  # 依赖的配置
    selected_by: List[str] = None   # 被谁选中


@dataclass
class RiskAssessment:
    """风险评估"""
    risk_level: RiskLevel
    exploitable: bool
    required_enabled: List[str]   # 必需且已启用的配置
    required_disabled: List[str]  # 必需但未启用的配置
    optional_enabled: List[str]   # 可选但已启用的配置


@dataclass
class AnalysisResult:
    """Kconfig 分析结果"""
    cve: CVE
    kernel_version: str
    config_status: ConfigStatus
    required_configs: List[ConfigItem]
    active_configs: List[ConfigItem]
    missing_configs: List[ConfigItem]
    risk_level: RiskLevel
    exploitable: bool
    exploit_conditions: str
    mitigation_configs: List[str]
    suggested_config: str


class KconfigAnalyzer(ABC):
    """Kconfig 分析器基类"""
    
    @abstractmethod
    def analyze(
        self,
        cve_id: str,
        kernel_version: str,
        config_path: Optional[str] = None,
    ) -> AnalysisResult:
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


class RuleLoader(ABC):
    """规则加载器基类"""
    
    @abstractmethod
    def load_rule(self, cve_id: str) -> Optional[KconfigRule]:
        """加载指定 CVE 的规则"""
        pass
    
    @abstractmethod
    def load_all_rules(self) -> List[KconfigRule]:
        """加载所有规则"""
        pass
    
    @abstractmethod
    def save_rule(self, rule: KconfigRule) -> None:
        """保存规则"""
        pass
