"""
Phase 5: Kconfig 分析模块测试 (TDD)
"""

import pytest
from unittest.mock import Mock, patch, MagicMock

from cve_analyzer.kconfig import KconfigAnalyzer, ConfigStatus, RiskLevel
from cve_analyzer.kconfig.base import ConfigItem, RiskAssessment


class TestKconfigParser:
    """Kconfig 解析器测试"""
    
    def test_parse_config_file(self):
        """测试解析 .config 文件"""
        from cve_analyzer.kconfig.parser import KconfigParser
        
        config_text = """
# CONFIG_NETFILTER is not set
CONFIG_NF_TABLES=y
CONFIG_NF_TABLES_INET=y
# CONFIG_NF_TABLES_NETDEV is not set
CONFIG_NETFILTER_XTABLES=m
"""
        
        parser = KconfigParser()
        config = parser.parse_config_text(config_text)
        
        assert config["CONFIG_NETFILTER"] == "n"
        assert config["CONFIG_NF_TABLES"] == "y"
        assert config["CONFIG_NF_TABLES_INET"] == "y"
        assert config["CONFIG_NETFILTER_XTABLES"] == "m"
    
    def test_parse_kconfig_dependencies(self):
        """测试解析 Kconfig 依赖关系"""
        from cve_analyzer.kconfig.parser import KconfigParser
        
        kconfig_text = """
config NF_TABLES
    tristate "Netfilter nf_tables support"
    depends on NETFILTER
    depends on NF_TABLES_INET || NF_TABLES_NETDEV
    help
      This enables the new netfilter packet classification framework.
"""
        
        parser = KconfigParser()
        deps = parser.parse_kconfig_dependencies(kconfig_text)
        
        assert deps["config"] == "NF_TABLES"
        assert "NETFILTER" in deps["depends_on"]
        assert "NF_TABLES_INET" in deps["depends_on"] or "NF_TABLES_NETDEV" in deps["depends_on"]


class TestKconfigAnalyzer:
    """Kconfig 分析器测试"""
    
    @pytest.fixture
    def sample_config(self):
        """示例配置"""
        return {
            "CONFIG_NETFILTER": "y",
            "CONFIG_NF_TABLES": "y",
            "CONFIG_NF_TABLES_INET": "y",
        }
    
    @pytest.fixture
    def sample_rule(self):
        """示例 Kconfig 规则"""
        return {
            "cve_id": "CVE-2024-1234",
            "required": ["CONFIG_NETFILTER", "CONFIG_NF_TABLES"],
            "vulnerable_if": {
                "all": ["CONFIG_NETFILTER=y", "CONFIG_NF_TABLES=y"]
            },
            "mitigation": {
                "disable": ["CONFIG_NF_TABLES"],
                "alternative": ["CONFIG_NF_TABLES=m"]
            }
        }
    
    def test_analyze_vulnerable_config(self, sample_config, sample_rule):
        """测试分析存在漏洞的配置"""
        from cve_analyzer.kconfig.analyzer import KconfigAnalyzer
        
        analyzer = KconfigAnalyzer()
        
        with patch.object(analyzer, '_load_rule', return_value=sample_rule):
            result = analyzer.analyze("CVE-2024-1234", "5.15.100", sample_config)
            
            # 应该识别为漏洞配置
            assert result.config_status == ConfigStatus.VULNERABLE
            assert result.risk_level in [RiskLevel.HIGH, RiskLevel.MEDIUM]
            assert result.exploitable is True
            assert "CONFIG_NETFILTER" in result.required_configs
    
    def test_analyze_patched_config(self, sample_rule):
        """测试分析已修复的配置"""
        from cve_analyzer.kconfig.analyzer import KconfigAnalyzer
        
        # 禁用 NF_TABLES
        config = {
            "CONFIG_NETFILTER": "y",
            "CONFIG_NF_TABLES": "n",
        }
        
        analyzer = KconfigAnalyzer()
        
        with patch.object(analyzer, '_load_rule', return_value=sample_rule):
            result = analyzer.analyze("CVE-2024-1234", "5.15.100", config)
            
            # 应该识别为已修复
            assert result.config_status == ConfigStatus.PATCHED
            assert result.risk_level == RiskLevel.LOW
    
    def test_analyze_partial_config(self, sample_rule):
        """测试分析部分启用的配置"""
        from cve_analyzer.kconfig.analyzer import KconfigAnalyzer
        
        # 只有部分配置
        config = {
            "CONFIG_NETFILTER": "y",
            # CONFIG_NF_TABLES 缺失
        }
        
        analyzer = KconfigAnalyzer()
        
        with patch.object(analyzer, '_load_rule', return_value=sample_rule):
            result = analyzer.analyze("CVE-2024-1234", "5.15.100", config)
            
            # 应该识别为不适用或低风险
            assert result.config_status in [ConfigStatus.NOT_APPLICABLE, ConfigStatus.PATCHED]


class TestRiskAssessment:
    """风险评估测试"""
    
    def test_calculate_risk_high(self):
        """测试高风险计算"""
        from cve_analyzer.kconfig.analyzer import KconfigAnalyzer
        
        analyzer = KconfigAnalyzer()
        
        # 所有必需配置都启用
        config = {
            "CONFIG_VULN_A": "y",
            "CONFIG_VULN_B": "y",
        }
        required = ["CONFIG_VULN_A", "CONFIG_VULN_B"]
        
        risk = analyzer._calculate_risk(config, required)
        
        assert risk.risk_level == RiskLevel.HIGH
        assert risk.exploitable is True
    
    def test_calculate_risk_medium(self):
        """测试中风险计算"""
        from cve_analyzer.kconfig.analyzer import KconfigAnalyzer
        
        analyzer = KconfigAnalyzer()
        
        # 部分配置启用
        config = {
            "CONFIG_VULN_A": "y",
            "CONFIG_VULN_B": "m",  # 模块形式
        }
        required = ["CONFIG_VULN_A", "CONFIG_VULN_B"]
        
        risk = analyzer._calculate_risk(config, required)
        
        assert risk.risk_level == RiskLevel.MEDIUM
    
    def test_calculate_risk_low(self):
        """测试低风险计算"""
        from cve_analyzer.kconfig.analyzer import KconfigAnalyzer
        
        analyzer = KconfigAnalyzer()
        
        # 必需配置都禁用
        config = {
            "CONFIG_VULN_A": "n",
            "CONFIG_VULN_B": "n",
        }
        required = ["CONFIG_VULN_A", "CONFIG_VULN_B"]
        
        risk = analyzer._calculate_risk(config, required)
        
        assert risk.risk_level == RiskLevel.LOW
        assert risk.exploitable is False


class TestKconfigRuleLoader:
    """Kconfig 规则加载测试"""
    
    def test_load_rule_from_database(self):
        """测试从数据库加载规则"""
        from cve_analyzer.kconfig.loader import RuleLoader
        
        loader = RuleLoader()
        
        # 模拟数据库查询
        with patch.object(loader, '_query_db') as mock_query:
            mock_query.return_value = {
                "cve_id": "CVE-2024-1234",
                "required": ["CONFIG_X"],
                "mitigation": {"disable": ["CONFIG_X"]}
            }
            
            rule = loader.load_rule("CVE-2024-1234")
            
            assert rule is not None
            assert rule["cve_id"] == "CVE-2024-1234"
    
    def test_load_rule_not_found(self):
        """测试规则不存在"""
        from cve_analyzer.kconfig.loader import RuleLoader
        
        loader = RuleLoader()
        
        with patch.object(loader, '_query_db', return_value=None):
            rule = loader.load_rule("CVE-NOT-EXIST")
            
            assert rule is None


class TestDependencyGraph:
    """依赖图测试"""
    
    def test_build_dependency_graph(self):
        """测试构建配置依赖图"""
        from cve_analyzer.kconfig.graph import DependencyGraph
        
        graph = DependencyGraph()
        
        # 添加依赖关系
        graph.add_dependency("CONFIG_NF_TABLES", "CONFIG_NETFILTER")
        graph.add_dependency("CONFIG_NF_TABLES_INET", "CONFIG_NF_TABLES")
        
        # 检查依赖
        deps = graph.get_dependencies("CONFIG_NF_TABLES_INET")
        assert "CONFIG_NF_TABLES" in deps
        assert "CONFIG_NETFILTER" in deps  # 传递依赖
    
    def test_find_vulnerable_path(self):
        """测试查找漏洞触发路径"""
        from cve_analyzer.kconfig.graph import DependencyGraph
        
        graph = DependencyGraph()
        
        graph.add_dependency("CONFIG_VULN", "CONFIG_PARENT")
        graph.add_dependency("CONFIG_PARENT", "CONFIG_ROOT")
        
        path = graph.find_path_to("CONFIG_VULN", "CONFIG_ROOT")
        
        assert path == ["CONFIG_ROOT", "CONFIG_PARENT", "CONFIG_VULN"]


class TestKconfigIntegration:
    """集成测试"""
    
    def test_full_analysis_workflow(self):
        """测试完整分析流程"""
        from cve_analyzer.kconfig import KconfigAnalyzer
        
        analyzer = KconfigAnalyzer()
        
        # 模拟完整的配置和规则
        config_text = """
CONFIG_NETFILTER=y
CONFIG_NF_TABLES=y
CONFIG_NF_TABLES_INET=y
"""
        
        rule = {
            "cve_id": "CVE-2024-TEST",
            "required": ["CONFIG_NETFILTER", "CONFIG_NF_TABLES"],
            "vulnerable_if": {"all": ["CONFIG_NF_TABLES=y"]},
            "mitigation": {"disable": ["CONFIG_NF_TABLES"]}
        }
        
        with patch.object(analyzer.parser, 'parse_config_file', return_value={
            "CONFIG_NETFILTER": "y",
            "CONFIG_NF_TABLES": "y",
            "CONFIG_NF_TABLES_INET": "y",
        }):
            with patch.object(analyzer, '_load_rule', return_value=rule):
                result = analyzer.analyze("CVE-2024-TEST", "5.15.100", 
                                         "/path/to/config")
                
                assert result.cve.id == "CVE-2024-TEST"
                assert result.risk_level is not None
                assert result.suggested_config is not None
