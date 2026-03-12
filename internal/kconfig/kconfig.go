// Package kconfig 提供 Kconfig 分析功能
package kconfig

import (
	"cve-analyzer/pkg/models"
)

// Analyzer 是 Kconfig 分析器接口
type Analyzer interface {
	// Analyze 分析 CVE 的 Kconfig 依赖
	Analyze(cveID string, kernelVersion string, configPath string) (*AnalysisResult, error)
	// ParseConfig 解析 .config 文件
	ParseConfig(configPath string) (map[string]string, error)
	// EvaluateRisk 评估配置风险
	EvaluateRisk(cveID string, config map[string]string) (*RiskAssessment, error)
}

// AnalysisResult Kconfig 分析结果
type AnalysisResult struct {
	CVE              models.CVE
	KernelVersion    string
	ConfigStatus     ConfigStatus
	RequiredConfigs  []ConfigItem    // 必需配置
	ActiveConfigs    []ConfigItem    // 当前启用的配置
	MissingConfigs   []ConfigItem    // 缺失的必要配置
	RiskLevel        RiskLevel
	Exploitable      bool
	ExploitConditions string
	MitigationConfigs []string       // 可缓解的配置项
	SuggestedConfig   string         // 建议的配置修改
}

// ConfigStatus 配置状态
type ConfigStatus string

const (
	ConfigVulnerable      ConfigStatus = "VULNERABLE"       // 配置存在漏洞
	ConfigPatched         ConfigStatus = "PATCHED"          // 已修复
	ConfigNotApplicable   ConfigStatus = "NOT_APPLICABLE"   // 不适用
	ConfigUnknown         ConfigStatus = "UNKNOWN"          // 未知
)

// RiskLevel 风险等级
type RiskLevel string

const (
	RiskHigh   RiskLevel = "HIGH"
	RiskMedium RiskLevel = "MEDIUM"
	RiskLow    RiskLevel = "LOW"
)

// ConfigItem 配置项
type ConfigItem struct {
	Name         string   // CONFIG_XXX
	Value        string   // y/m/n/数值
	Description  string   // 配置描述
	Dependencies []string // 依赖的配置
	SelectedBy   []string // 被谁选中
}

// RiskAssessment 风险评估
type RiskAssessment struct {
	RiskLevel         RiskLevel
	Exploitable       bool
	RequiredEnabled   []string // 必需且已启用的配置
	RequiredDisabled  []string // 必需但未启用的配置
	OptionalEnabled   []string // 可选但已启用的配置
}

// RuleLoader 规则加载器接口
type RuleLoader interface {
	// LoadRule 加载指定 CVE 的规则
	LoadRule(cveID string) (*models.KconfigRule, error)
	// LoadAllRules 加载所有规则
	LoadAllRules() ([]models.KconfigRule, error)
	// SaveRule 保存规则
	SaveRule(rule *models.KconfigRule) error
}
