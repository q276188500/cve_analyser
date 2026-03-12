// Package analyzer 提供补丁和版本分析功能
package analyzer

import (
	"cve-analyzer/internal/git"
	"cve-analyzer/pkg/models"
)

// Analyzer 是补丁分析器接口
type Analyzer interface {
	// Analyze 分析 CVE 补丁
	Analyze(cve *models.CVE) (*AnalysisResult, error)
	// ExtractPatches 从 CVE 提取补丁信息
	ExtractPatches(cve *models.CVE) ([]models.Patch, error)
	// AnalyzeVersionImpact 分析版本影响范围
	AnalyzeVersionImpact(patch *models.Patch) (*VersionImpact, error)
}

// AnalysisResult 分析结果
type AnalysisResult struct {
	CVE            models.CVE
	Patches        []models.Patch
	AffectedFiles  []string
	AffectedFuncs  []string
	VersionImpact  VersionImpact
}

// VersionImpact 版本影响分析结果
type VersionImpact struct {
	MainlineAffected  []string // 受影响的主线版本
	StableAffected    []string // 受影响的 stable 版本
	LongtermAffected  []string // 受影响的 longterm 版本
	BackportedTo      []string // 已回溯到的版本
	NotBackportedTo   []string // 未回溯的版本
}

// PatchExtractor 补丁提取器
type PatchExtractor interface {
	// ExtractFromCommit 从 Git commit 提取补丁
	ExtractFromCommit(repo *git.Repository, commitHash string) (*models.Patch, error)
	// ExtractFromURL 从 URL 提取补丁
	ExtractFromURL(url string) (*models.Patch, error)
	// ExtractFromMbox 从 mbox 格式提取补丁
	ExtractFromMbox(content string) ([]models.Patch, error)
}
