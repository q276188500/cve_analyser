// Package config 提供配置管理功能
package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/viper"
)

// Config 是全局配置结构
type Config struct {
	// 数据目录
	DataDir string `mapstructure:"data_dir"`
	// 数据库路径
	DatabasePath string `mapstructure:"database_path"`
	// 日志级别
	LogLevel string `mapstructure:"log_level"`

	// 内核配置
	Kernel KernelConfig `mapstructure:"kernel"`
	// 数据源配置
	DataSources DataSourcesConfig `mapstructure:"data_sources"`
	// 分析配置
	Analysis AnalysisConfig `mapstructure:"analysis"`
	// 输出配置
	Output OutputConfig `mapstructure:"output"`
}

// KernelConfig 内核配置
type KernelConfig struct {
	// 模式: user_provided 或 auto_download
	Mode string `mapstructure:"mode"`
	// 用户提供的内核路径 (mode=user_provided 时使用)
	Path string `mapstructure:"path"`
	// 内核仓库 URL (mode=auto_download 时使用)
	RepoURL string `mapstructure:"repo_url"`
	// 本地存储路径 (mode=auto_download 时使用)
	LocalPath string `mapstructure:"local_path"`
	// 是否自动下载
	AutoDownload bool `mapstructure:"auto_download"`
	// 浅克隆深度
	ShallowDepth int `mapstructure:"shallow_depth"`
	// 关注的主线分支
	Branches []string `mapstructure:"branches"`
}

// DataSourcesConfig 数据源配置
type DataSourcesConfig struct {
	NVD      NVDConfig      `mapstructure:"nvd"`
	CVEOrg   CVEOrgConfig   `mapstructure:"cve_org"`
	GitSec   GitSecConfig   `mapstructure:"git_security"`
}

// NVDConfig NVD 数据源配置
type NVDConfig struct {
	Enabled   bool   `mapstructure:"enabled"`
	APIKey    string `mapstructure:"api_key"`
	RateLimit int    `mapstructure:"rate_limit"`
}

// CVEOrgConfig CVE.org 数据源配置
type CVEOrgConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	BaseURL string `mapstructure:"base_url"`
}

// GitSecConfig Git Security 数据源配置
type GitSecConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	URL     string `mapstructure:"url"`
}

// AnalysisConfig 分析配置
type AnalysisConfig struct {
	// 最大并发 worker 数
	MaxWorkers int `mapstructure:"max_workers"`
	// 是否启用缓存
	CacheEnabled bool `mapstructure:"cache_enabled"`
	// 缓存 TTL
	CacheTTL string `mapstructure:"cache_ttl"`
	// 是否启用深度分析
	DeepAnalysis bool `mapstructure:"deep_analysis"`
	// 补丁检测策略
	PatchDetection PatchDetectionConfig `mapstructure:"patch_detection"`
}

// PatchDetectionConfig 补丁检测配置
type PatchDetectionConfig struct {
	// 检测策略: strict(严格哈希) | fuzzy(模糊匹配) | both(两者都用)
	Strategy string `mapstructure:"strategy"`
	// 模糊匹配的最小置信度
	MinConfidence float64 `mapstructure:"min_confidence"`
}

// OutputConfig 输出配置
type OutputConfig struct {
	// 默认输出格式
	DefaultFormat string `mapstructure:"default_format"`
	// 报告输出目录
	ReportDir string `mapstructure:"report_dir"`
	// 是否包含补丁详情
	IncludePatches bool `mapstructure:"include_patches"`
	// 是否包含完整 diff
	IncludeDiffs bool `mapstructure:"include_diffs"`
}

// 默认配置
var defaultConfig = Config{
	DataDir:      "./data",
	DatabasePath: "./data/cve-analyzer.db",
	LogLevel:     "info",
	Kernel: KernelConfig{
		Mode:         "user_provided",
		RepoURL:      "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git",
		LocalPath:    "./data/linux",
		AutoDownload: false,
		ShallowDepth: 1000,
		Branches:     []string{"mainline", "stable", "longterm"},
	},
	DataSources: DataSourcesConfig{
		NVD: NVDConfig{
			Enabled:   true,
			RateLimit: 6,
		},
		CVEOrg: CVEOrgConfig{
			Enabled: true,
			BaseURL: "https://cveawg.mitre.org/api/cve/",
		},
		GitSec: GitSecConfig{
			Enabled: true,
			URL:     "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git",
		},
	},
	Analysis: AnalysisConfig{
		MaxWorkers:   10,
		CacheEnabled: true,
		CacheTTL:     "24h",
		DeepAnalysis: false,
		PatchDetection: PatchDetectionConfig{
			Strategy:      "both",
			MinConfidence: 0.7,
		},
	},
	Output: OutputConfig{
		DefaultFormat:  "json",
		ReportDir:      "./reports",
		IncludePatches: true,
		IncludeDiffs:   false,
	},
}

// Load 加载配置
// 优先级: 环境变量 > 配置文件 > 默认值
func Load() (*Config, error) {
	v := viper.New()

	// 设置默认值
	setDefaults(v)

	// 设置配置文件名和路径
	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath(".")
	v.AddConfigPath("./configs")
	v.AddConfigPath("$HOME/.cve-analyzer")
	v.AddConfigPath("/etc/cve-analyzer")

	// 读取配置文件 (如果存在)
	if err := v.ReadInConfig(); err != nil {
		// 配置文件不存在不是错误，使用默认值
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("读取配置文件失败: %w", err)
		}
	}

	// 绑定环境变量
	v.SetEnvPrefix("CVE_ANALYZER")
	v.AutomaticEnv()

	// 解析配置
	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("解析配置失败: %w", err)
	}

	// 确保数据目录存在
	if err := os.MkdirAll(cfg.DataDir, 0755); err != nil {
		return nil, fmt.Errorf("创建数据目录失败: %w", err)
	}

	// 转换相对路径为绝对路径
	if !filepath.IsAbs(cfg.DatabasePath) {
		cfg.DatabasePath = filepath.Join(cfg.DataDir, filepath.Base(cfg.DatabasePath))
	}

	return &cfg, nil
}

// setDefaults 设置默认配置值
func setDefaults(v *viper.Viper) {
	v.SetDefault("data_dir", defaultConfig.DataDir)
	v.SetDefault("database_path", defaultConfig.DatabasePath)
	v.SetDefault("log_level", defaultConfig.LogLevel)

	v.SetDefault("kernel.mode", defaultConfig.Kernel.Mode)
	v.SetDefault("kernel.repo_url", defaultConfig.Kernel.RepoURL)
	v.SetDefault("kernel.local_path", defaultConfig.Kernel.LocalPath)
	v.SetDefault("kernel.auto_download", defaultConfig.Kernel.AutoDownload)
	v.SetDefault("kernel.shallow_depth", defaultConfig.Kernel.ShallowDepth)
	v.SetDefault("kernel.branches", defaultConfig.Kernel.Branches)

	v.SetDefault("data_sources.nvd.enabled", defaultConfig.DataSources.NVD.Enabled)
	v.SetDefault("data_sources.nvd.rate_limit", defaultConfig.DataSources.NVD.RateLimit)
	v.SetDefault("data_sources.cve_org.enabled", defaultConfig.DataSources.CVEOrg.Enabled)
	v.SetDefault("data_sources.cve_org.base_url", defaultConfig.DataSources.CVEOrg.BaseURL)
	v.SetDefault("data_sources.git_security.enabled", defaultConfig.DataSources.GitSec.Enabled)
	v.SetDefault("data_sources.git_security.url", defaultConfig.DataSources.GitSec.URL)

	v.SetDefault("analysis.max_workers", defaultConfig.Analysis.MaxWorkers)
	v.SetDefault("analysis.cache_enabled", defaultConfig.Analysis.CacheEnabled)
	v.SetDefault("analysis.cache_ttl", defaultConfig.Analysis.CacheTTL)
	v.SetDefault("analysis.deep_analysis", defaultConfig.Analysis.DeepAnalysis)
	v.SetDefault("analysis.patch_detection.strategy", defaultConfig.Analysis.PatchDetection.Strategy)
	v.SetDefault("analysis.patch_detection.min_confidence", defaultConfig.Analysis.PatchDetection.MinConfidence)

	v.SetDefault("output.default_format", defaultConfig.Output.DefaultFormat)
	v.SetDefault("output.report_dir", defaultConfig.Output.ReportDir)
	v.SetDefault("output.include_patches", defaultConfig.Output.IncludePatches)
	v.SetDefault("output.include_diffs", defaultConfig.Output.IncludeDiffs)
}

// SaveDefaultConfig 保存默认配置文件
func SaveDefaultConfig(path string) error {
	v := viper.New()
	setDefaults(v)

	content := `# CVE Analyzer 配置文件
# 更多配置选项请参考文档

# 数据目录
data_dir: "./data"
database_path: "./data/cve-analyzer.db"
log_level: "info"

# 内核配置
kernel:
  # 模式: user_provided (用户指定) 或 auto_download (自动下载)
  mode: "user_provided"
  # 用户内核路径 (mode=user_provided 时使用)
  path: ""
  # 自动下载配置 (mode=auto_download 时使用)
  repo_url: "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git"
  local_path: "./data/linux"
  auto_download: false
  shallow_depth: 1000
  branches:
    - mainline
    - stable
    - longterm

# 数据源配置
data_sources:
  nvd:
    enabled: true
    api_key: ""           # 从 https://nvd.nist.gov/developers/request-an-api-key 获取
    rate_limit: 6         # 每秒请求数 (NVD 限制)
  cve_org:
    enabled: true
    base_url: "https://cveawg.mitre.org/api/cve/"
  git_security:
    enabled: true
    url: "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git"

# 分析配置
analysis:
  max_workers: 10
  cache_enabled: true
  cache_ttl: "24h"
  deep_analysis: false
  patch_detection:
    strategy: "both"      # strict | fuzzy | both
    min_confidence: 0.7   # 模糊匹配最小置信度

# 输出配置
output:
  default_format: "json"  # json | markdown | html
  report_dir: "./reports"
  include_patches: true
  include_diffs: false
`
	return os.WriteFile(path, []byte(content), 0644)
}
