"""
配置管理模块
使用 Pydantic Settings 管理配置
"""

from pathlib import Path
from typing import List, Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class KernelConfig(BaseSettings):
    """内核配置"""
    model_config = SettingsConfigDict(env_prefix="KERNEL_")
    
    mode: str = Field(default="user_provided", description="模式: user_provided 或 auto_download")
    path: Optional[str] = Field(default=None, description="用户内核路径")
    repo_url: str = Field(
        default="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git",
        description="内核仓库 URL"
    )
    local_path: str = Field(default="./data/linux", description="本地存储路径")
    auto_download: bool = Field(default=False, description="是否自动下载")
    shallow_depth: int = Field(default=1000, description="浅克隆深度")
    branches: List[str] = Field(default=["mainline", "stable", "longterm"])


class NVDConfig(BaseSettings):
    """NVD 数据源配置"""
    model_config = SettingsConfigDict(env_prefix="NVD_")
    
    enabled: bool = True
    api_key: Optional[str] = None
    rate_limit: int = 6  # NVD 限制每秒 6 请求


class CVEOrgConfig(BaseSettings):
    """CVE.org 数据源配置"""
    model_config = SettingsConfigDict(env_prefix="CVE_ORG_")
    
    enabled: bool = True
    base_url: str = "https://cveawg.mitre.org/api/cve/"


class GitSecurityConfig(BaseSettings):
    """Git Security 数据源配置"""
    model_config = SettingsConfigDict(env_prefix="GIT_SECURITY_")
    
    enabled: bool = True
    url: str = "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git"


class DataSourcesConfig(BaseSettings):
    """数据源配置集合"""
    nvd: NVDConfig = Field(default_factory=NVDConfig)
    cve_org: CVEOrgConfig = Field(default_factory=CVEOrgConfig)
    git_security: GitSecurityConfig = Field(default_factory=GitSecurityConfig)


class PatchDetectionConfig(BaseSettings):
    """补丁检测配置"""
    strategy: str = Field(default="both", description="strict | fuzzy | both")
    min_confidence: float = Field(default=0.7, ge=0.0, le=1.0)


class AnalysisConfig(BaseSettings):
    """分析配置"""
    model_config = SettingsConfigDict(env_prefix="ANALYSIS_")
    
    max_workers: int = 10
    cache_enabled: bool = True
    cache_ttl: str = "24h"
    deep_analysis: bool = False
    patch_detection: PatchDetectionConfig = Field(default_factory=PatchDetectionConfig)


class OutputConfig(BaseSettings):
    """输出配置"""
    model_config = SettingsConfigDict(env_prefix="OUTPUT_")
    
    default_format: str = Field(default="json")  # json | markdown | html
    report_dir: str = "./reports"
    include_patches: bool = True
    include_diffs: bool = False


class Settings(BaseSettings):
    """全局配置"""
    model_config = SettingsConfigDict(
        env_prefix="CVE_ANALYZER_",
        yaml_file="config.yaml",
        yaml_file_encoding="utf-8",
    )
    
    # 基础配置
    data_dir: str = Field(default="./data")
    database_path: str = Field(default="./data/cve-analyzer.db")
    log_level: str = Field(default="INFO")
    
    # 子配置
    kernel: KernelConfig = Field(default_factory=KernelConfig)
    data_sources: DataSourcesConfig = Field(default_factory=DataSourcesConfig)
    analysis: AnalysisConfig = Field(default_factory=AnalysisConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)
    
    def model_post_init(self, __context) -> None:
        """初始化后处理路径"""
        # 确保数据目录存在
        Path(self.data_dir).mkdir(parents=True, exist_ok=True)
        
        # 转换相对路径为绝对路径
        if not Path(self.database_path).is_absolute():
            self.database_path = str(Path(self.data_dir) / Path(self.database_path).name)
        
        # 确保报告目录存在
        Path(self.output.report_dir).mkdir(parents=True, exist_ok=True)


def load_settings(config_path: Optional[str] = None) -> Settings:
    """
    加载配置
    
    优先级: 环境变量 > 配置文件 > 默认值
    
    Args:
        config_path: 配置文件路径，None 则使用默认搜索路径
    
    Returns:
        Settings 配置对象
    """
    import yaml
    
    settings_kwargs = {}
    
    # 尝试加载配置文件
    config_files = []
    if config_path:
        config_files = [config_path]
    else:
        # 默认搜索路径
        config_files = [
            "config.yaml",
            "./configs/config.yaml",
            Path.home() / ".cve-analyzer" / "config.yaml",
            "/etc/cve-analyzer/config.yaml",
        ]
    
    for config_file in config_files:
        path = Path(config_file)
        if path.exists():
            with open(path, "r", encoding="utf-8") as f:
                config_data = yaml.safe_load(f)
                if config_data:
                    settings_kwargs.update(config_data)
            break
    
    return Settings(**settings_kwargs)


# 全局配置实例
_settings: Optional[Settings] = None


def get_settings() -> Settings:
    """获取全局配置实例 (懒加载)"""
    global _settings
    if _settings is None:
        _settings = load_settings()
    return _settings


def reset_settings() -> None:
    """重置配置 (用于测试)"""
    global _settings
    _settings = None
