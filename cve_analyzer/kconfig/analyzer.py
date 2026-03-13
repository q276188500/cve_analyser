"""
Kconfig 分析器实现
"""

from typing import Dict, List, Optional

from cve_analyzer.kconfig.base import (
    KconfigAnalyzer as KconfigAnalyzerInterface,
    AnalysisResult, ConfigItem, RiskAssessment,
    ConfigStatus, RiskLevel
)
from cve_analyzer.kconfig.parser import KconfigParser
from cve_analyzer.kconfig.loader import RuleLoader


class KconfigAnalyzer(KconfigAnalyzerInterface):
    """Kconfig 分析器实现"""
    
    def __init__(self):
        self.parser = KconfigParser()
        self.loader = RuleLoader()
    
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
        # 1. 解析配置
        config = self.parse_config(config_path)
        
        # 2. 加载规则
        rule = self._load_rule(cve_id)
        
        if not rule:
            # 没有规则，返回未知
            return AnalysisResult(
                cve=None,  # 简化处理
                kernel_version=kernel_version,
                config_status=ConfigStatus.UNKNOWN,
                risk_level=RiskLevel.LOW,
            )
        
        # 3. 评估风险
        risk = self.evaluate_risk(cve_id, config)
        
        # 4. 确定配置状态
        config_status = self._determine_config_status(config, rule, risk)
        
        # 5. 生成建议配置
        suggested_config = self._generate_suggestion(config, rule)
        
        # 6. 构建配置项列表
        required_configs = self._build_config_items(rule.get("required", []), config)
        active_configs = self._build_config_items(
            [k for k, v in config.items() if v in ['y', 'm']], 
            config
        )
        
        return AnalysisResult(
            cve=None,  # 简化
            kernel_version=kernel_version,
            config_status=config_status,
            required_configs=required_configs,
            active_configs=active_configs,
            risk_level=risk.risk_level,
            exploitable=risk.exploitable,
            mitigation_configs=rule.get("mitigation", {}).get("disable", []),
            suggested_config=suggested_config,
        )
    
    def parse_config(self, config_path: str) -> Dict[str, str]:
        """解析 .config 文件"""
        return self.parser.parse_config_file(config_path)
    
    def evaluate_risk(self, cve_id: str, config: Dict[str, str]) -> RiskAssessment:
        """评估配置风险"""
        # 加载规则
        rule = self._load_rule(cve_id)
        
        if not rule:
            return RiskAssessment(
                risk_level=RiskLevel.LOW,
                exploitable=False,
            )
        
        required = rule.get("required", [])
        vulnerable_if = rule.get("vulnerable_if", {})
        
        # 检查必需配置
        required_enabled = []
        required_disabled = []
        
        for req in required:
            if req in config:
                if config[req] in ['y', 'm']:
                    required_enabled.append(req)
                else:
                    required_disabled.append(req)
        
        # 计算风险
        if vulnerable_if.get("all"):
            # 所有条件必须满足才算漏洞
            all_met = all(
                self._check_condition(cond, config) 
                for cond in vulnerable_if["all"]
            )
            if all_met:
                risk_level = RiskLevel.HIGH
                exploitable = True
            else:
                risk_level = RiskLevel.LOW
                exploitable = False
        else:
            # 简化：根据启用比例判断
            if len(required_enabled) == len(required) and required:
                risk_level = RiskLevel.HIGH
                exploitable = True
            elif required_enabled:
                risk_level = RiskLevel.MEDIUM
                exploitable = True
            else:
                risk_level = RiskLevel.LOW
                exploitable = False
        
        return RiskAssessment(
            risk_level=risk_level,
            exploitable=exploitable,
            required_enabled=required_enabled,
            required_disabled=required_disabled,
        )
    
    def _load_rule(self, cve_id: str) -> Optional[Dict]:
        """加载 CVE 的 Kconfig 规则"""
        return self.loader.load_rule(cve_id)
    
    def _determine_config_status(self, config: Dict[str, str], rule: Dict, 
                                  risk: RiskAssessment) -> ConfigStatus:
        """确定配置状态"""
        required = rule.get("required", [])
        
        # 检查是否有必需配置被禁用
        any_required_disabled = any(
            config.get(req, 'n') == 'n' for req in required
        )
        
        if any_required_disabled:
            return ConfigStatus.PATCHED  # 已修复（通过禁用配置）
        
        if risk.exploitable:
            return ConfigStatus.VULNERABLE
        
        if not required:
            return ConfigStatus.NOT_APPLICABLE
        
        return ConfigStatus.UNKNOWN
    
    def _generate_suggestion(self, config: Dict[str, str], rule: Dict) -> str:
        """生成建议配置"""
        mitigation = rule.get("mitigation", {})
        disable = mitigation.get("disable", [])
        alternative = mitigation.get("alternative", [])
        
        suggestions = []
        
        for cfg in disable:
            current = config.get(cfg, 'n')
            if current in ['y', 'm']:
                suggestions.append(f"# {cfg} is not set")
        
        for alt in alternative:
            suggestions.append(alt)
        
        return "\n".join(suggestions) if suggestions else ""
    
    def _build_config_items(self, config_names: List[str], 
                           config: Dict[str, str]) -> List[ConfigItem]:
        """构建配置项列表"""
        items = []
        for name in config_names:
            items.append(ConfigItem(
                name=name,
                value=config.get(name, 'n'),
            ))
        return items
    
    def _check_condition(self, condition: str, config: Dict[str, str]) -> bool:
        """检查条件是否满足"""
        # 简化：检查 CONFIG_XXX=y/m/n
        match = condition.replace('=', ' ').split()
        if len(match) >= 2:
            cfg_name = match[0]
            expected = match[1] if len(match) > 1 else 'y'
            actual = config.get(cfg_name, 'n')
            return actual == expected
        return False
