"""
配置管理模块测试
"""

import os
from pathlib import Path

import pytest
import yaml

from cve_analyzer.core.config import (
    Settings,
    load_settings,
    get_settings,
    KernelConfig,
    NVDConfig,
)


class TestSettings:
    """Settings 类测试"""
    
    def test_default_values(self):
        """测试默认值"""
        settings = Settings()
        
        assert settings.data_dir == "./data"
        assert settings.log_level == "INFO"
        assert settings.kernel.mode == "user_provided"
        assert settings.kernel.repo_url == "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git"
        assert settings.data_sources.nvd.enabled is True
        assert settings.data_sources.nvd.rate_limit == 6
    
    def test_custom_values(self):
        """测试自定义值"""
        settings = Settings(
            data_dir="/custom/data",
            log_level="DEBUG",
            kernel=KernelConfig(mode="auto_download", auto_download=True),
        )
        
        assert settings.data_dir == "/custom/data"
        assert settings.log_level == "DEBUG"
        assert settings.kernel.mode == "auto_download"
        assert settings.kernel.auto_download is True
    
    def test_model_post_init_creates_directories(self, temp_dir):
        """测试初始化时创建目录"""
        data_dir = temp_dir / "test_data"
        settings = Settings(data_dir=str(data_dir))
        
        assert data_dir.exists()
        assert data_dir.is_dir()
    
    def test_database_path_relative_conversion(self, temp_dir):
        """测试相对数据库路径转换为绝对路径"""
        data_dir = temp_dir / "data"
        settings = Settings(
            data_dir=str(data_dir),
            database_path="cve.db",  # 相对路径
        )
        
        assert Path(settings.database_path).is_absolute()
        assert settings.database_path.endswith("cve.db")


class TestLoadSettings:
    """配置加载测试"""
    
    def test_load_from_yaml_file(self, temp_dir):
        """测试从 YAML 文件加载"""
        config_file = temp_dir / "config.yaml"
        config_data = {
            "data_dir": "/yaml/data",
            "log_level": "DEBUG",
            "kernel": {"mode": "auto_download"},
        }
        
        with open(config_file, "w") as f:
            yaml.dump(config_data, f)
        
        settings = load_settings(str(config_file))
        
        assert settings.data_dir == "/yaml/data"
        assert settings.log_level == "DEBUG"
        assert settings.kernel.mode == "auto_download"
    
    def test_load_with_env_override(self, temp_dir, monkeypatch):
        """测试环境变量覆盖配置"""
        config_file = temp_dir / "config.yaml"
        config_data = {"log_level": "INFO"}
        
        with open(config_file, "w") as f:
            yaml.dump(config_data, f)
        
        # 设置环境变量
        monkeypatch.setenv("CVE_ANALYZER_LOG_LEVEL", "ERROR")
        
        settings = load_settings(str(config_file))
        
        # 环境变量应该覆盖配置文件
        assert settings.log_level == "ERROR"
    
    def test_load_nonexistent_file_uses_defaults(self):
        """测试加载不存在的文件使用默认值"""
        settings = load_settings("/nonexistent/config.yaml")
        
        assert settings.data_dir == "./data"
        assert settings.log_level == "INFO"
    
    def test_load_invalid_yaml_raises_error(self, temp_dir):
        """测试加载无效 YAML 引发错误"""
        config_file = temp_dir / "invalid.yaml"
        
        with open(config_file, "w") as f:
            f.write("invalid: yaml: content: [")
        
        with pytest.raises(yaml.YAMLError):
            load_settings(str(config_file))


class TestGetSettings:
    """全局配置实例测试"""
    
    def test_lazy_loading(self):
        """测试懒加载"""
        # 首次调用应该创建实例
        settings1 = get_settings()
        settings2 = get_settings()
        
        # 应该是同一个实例
        assert settings1 is settings2
    
    def test_after_reset_creates_new_instance(self):
        """测试重置后创建新实例"""
        from cve_analyzer.core.config import reset_settings
        
        settings1 = get_settings()
        reset_settings()
        settings2 = get_settings()
        
        # 应该是不同的实例
        assert settings1 is not settings2


class TestKernelConfig:
    """内核配置测试"""
    
    def test_default_branches(self):
        """测试默认分支列表"""
        config = KernelConfig()
        
        assert "mainline" in config.branches
        assert "stable" in config.branches
        assert "longterm" in config.branches
    
    def test_default_not_auto_download(self):
        """测试默认不自动下载"""
        config = KernelConfig()
        
        assert config.auto_download is False


class TestNVDConfig:
    """NVD 配置测试"""
    
    def test_default_rate_limit(self):
        """测试默认速率限制"""
        config = NVDConfig()
        
        assert config.rate_limit == 6
        assert config.enabled is True
    
    def test_optional_api_key(self):
        """测试 API key 是可选的"""
        config = NVDConfig()
        
        assert config.api_key is None
        
        config_with_key = NVDConfig(api_key="test-key-123")
        assert config_with_key.api_key == "test-key-123"
