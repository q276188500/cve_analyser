// Package patchstatus 提供补丁状态检测功能
package patchstatus

import (
	"cve-analyzer/internal/git"
	"cve-analyzer/pkg/models"
)

// Detector 是补丁状态检测器接口
type Detector interface {
	// Detect 检测补丁在目标代码中的状态
	Detect(cveID string, target *TargetCode) (*DetectionResult, error)
	// DetectBatch 批量检测
	DetectBatch(cveIDs []string, target *TargetCode) ([]DetectionResult, error)
}

// TargetCode 目标代码信息
type TargetCode struct {
	Version   string           // 内核版本号
	Path      string           // 代码路径
	Repo      *git.Repository  // Git 仓库 (如果可用)
	Config    *models.KconfigAnalysis // 配置分析结果 (可选)
}

// DetectionResult 检测结果
type DetectionResult struct {
	CVEID           string
	TargetVersion   string
	Status          PatchStatus
	Confidence      float64           // 置信度 (0-1)
	DetectionMethod DetectionMethod   // 检测方法
	MatchedCommit   string            // 匹配到的 commit (如果适用)
	Details         map[string]interface{} // 详细结果
}

// PatchStatus 补丁状态
type PatchStatus string

const (
	StatusApplied   PatchStatus = "APPLIED"    // 已应用
	StatusPending   PatchStatus = "PENDING"    // 未应用 (存在漏洞)
	StatusModified  PatchStatus = "MODIFIED"   // 已修改 (不是原补丁)
	StatusReverted  PatchStatus = "REVERTED"   // 已回退
	StatusUnknown   PatchStatus = "UNKNOWN"    // 未知
)

// DetectionMethod 检测方法
type DetectionMethod string

const (
	MethodCommitHash  DetectionMethod = "commit_hash"   // Commit hash 精确匹配
	MethodFileHash    DetectionMethod = "file_hash"     // 文件哈希匹配
	MethodContent     DetectionMethod = "content_match" // 代码内容特征匹配
	MethodAST         DetectionMethod = "ast_match"     // AST 特征匹配
)
