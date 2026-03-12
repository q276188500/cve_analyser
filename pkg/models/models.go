// Package models 定义数据模型
package models

import (
	"time"

	"gorm.io/gorm"
)

// ============================================
// CVE 相关模型
// ============================================

// CVE 漏洞主表
type CVE struct {
	ID              string    `gorm:"primaryKey;size:20"`      // CVE-2024-XXXX
	Description     string    `gorm:"type:text"`               // 漏洞描述
	PublishedDate   time.Time `gorm:"index"`                   // 发布时间
	LastModified    time.Time                                   // 最后修改时间
	Severity        string    `gorm:"size:20;index"`           // 严重程度: CRITICAL/HIGH/MEDIUM/LOW
	CVSSScore       float64   `gorm:"index"`                   // CVSS 分数
	CVSSVector      string    `gorm:"size:100"`                // CVSS 向量
	References      []CVEReference `gorm:"foreignKey:CVEID"`   // 参考链接
	AffectedConfigs []AffectedConfig `gorm:"foreignKey:CVEID"` // 受影响配置
	Patches         []Patch    `gorm:"foreignKey:CVEID"`       // 关联补丁
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// CVEReference CVE 参考链接表
type CVEReference struct {
	ID     uint   `gorm:"primaryKey"`
	CVEID  string `gorm:"index;size:20"` // CVE ID
	URL    string `gorm:"size:500"`      // 参考链接
	Type   string `gorm:"size:50;index"` // 类型: PATCH/ADVISORY/EXPLOIT/GIT_COMMIT/etc
	Source string `gorm:"size:50"`       // 来源: NVD/MITRE/GIT_SECURITY/etc
}

// ============================================
// 补丁相关模型
// ============================================

// Patch 补丁信息表
type Patch struct {
	ID              uint   `gorm:"primaryKey"`
	CVEID           string `gorm:"index;size:20"`     // CVE ID
	CommitHash      string `gorm:"size:40;index"`     // Git commit hash (完整)
	CommitHashShort string `gorm:"size:12"`           // Git commit hash (短)
	Subject         string `gorm:"size:500"`          // Commit message subject
	Body            string `gorm:"type:text"`         // Commit message body
	Author          string `gorm:"size:100"`          // 作者
	AuthorEmail     string `gorm:"size:100"`          // 作者邮箱
	AuthorDate      time.Time                         // 作者日期
	Committer       string `gorm:"size:100"`          // 提交者
	CommitDate      time.Time                         // 提交日期
	FilesChanged    []FileChange `gorm:"foreignKey:PatchID"` // 变更的文件
	Branches        string       `gorm:"type:text"`   // 影响的内核分支 (JSON 数组)
	BackportedTo    string       `gorm:"type:text"`   // 已回溯到的版本 (JSON 数组)
	NotBackportedTo string       `gorm:"type:text"`   // 未回溯的版本 (JSON 数组)
	PatchStatus     []PatchStatus `gorm:"foreignKey:PatchID"` // 补丁状态检测记录
	PatchHistory    []PatchHistory `gorm:"foreignKey:PatchID"` // 补丁历史记录
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// FileChange 文件变更表
type FileChange struct {
	ID           uint     `gorm:"primaryKey"`
	PatchID      uint     `gorm:"index"`
	Filename     string   `gorm:"size:500;index"` // 文件路径
	Status       string   `gorm:"size:20"`        // added/modified/deleted/renamed
	Additions    int                               // 新增行数
	Deletions    int                               // 删除行数
	Functions    string   `gorm:"type:text"`      // 受影响的函数名 (JSON 数组)
	OldFileHash  string   `gorm:"size:64"`        // 变更前文件哈希 (SHA256)
	NewFileHash  string   `gorm:"size:64"`        // 变更后文件哈希 (SHA256)
	PatchContent string   `gorm:"type:text"`      // 补丁内容 (diff)
}

// ============================================
// 补丁状态检测模型
// ============================================

// PatchStatus 补丁在目标代码中的状态
type PatchStatus struct {
	ID              uint      `gorm:"primaryKey"`
	CVEID           string    `gorm:"index;size:20"`   // CVE ID
	PatchID         uint      `gorm:"index"`
	TargetVersion   string    `gorm:"size:50;index"`   // 检测的目标内核版本
	TargetPath      string    `gorm:"size:500"`        // 目标代码路径
	Status          string    `gorm:"size:20;index"`   // 状态: APPLIED/PENDING/MODIFIED/REVERTED/UNKNOWN
	DetectionMethod string    `gorm:"size:50"`         // 检测方法
	MatchedCommit   string    `gorm:"size:40"`         // 匹配到的 commit
	MatchConfidence float64   `gorm:"index"`           // 匹配置信度 (0-1)
	ExpectedHash    string    `gorm:"size:64"`         // 预期文件哈希
	ActualHash      string    `gorm:"size:64"`         // 实际文件哈希
	DiffSummary     string    `gorm:"type:text"`       // 差异摘要
	CheckedAt       time.Time                         // 检测时间
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// PatchHistory 补丁应用历史 (用于追踪后续修改)
type PatchHistory struct {
	ID            uint      `gorm:"primaryKey"`
	CVEID         string    `gorm:"index;size:20"`
	PatchID       uint      `gorm:"index"`
	ChangeType    string    `gorm:"size:30;index"` // ORIGINAL/BACKPORT/FIXUP/REVERT/REFACTOR/CONFLICT
	CommitHash    string    `gorm:"size:40"`       // 修改的 commit hash
	CommitSubject string    `gorm:"size:500"`      // commit message subject
	Author        string    `gorm:"size:100"`      // 作者
	CommitDate    time.Time                       // commit 日期
	ParentCommit  string    `gorm:"size:40"`       // 父 commit
	RelatedTo     string    `gorm:"size:40"`       // 关联的原始补丁 commit
	Description   string    `gorm:"type:text"`     // 变更原因说明
	FilesChanged  string    `gorm:"type:text"`     // 变更的文件列表 (JSON)
	Impact        string    `gorm:"size:50"`       // 影响评估
	CreatedAt     time.Time
}

// ============================================
// 版本配置模型
// ============================================

// AffectedConfig 受影响的内核版本配置
type AffectedConfig struct {
	ID           uint   `gorm:"primaryKey"`
	CVEID        string `gorm:"index;size:20"`
	Vendor       string `gorm:"size:50;index"`  // 厂商: Linux/RedHat/Ubuntu/etc
	Product      string `gorm:"size:100"`       // 产品: Linux Kernel
	VersionStart string `gorm:"size:50"`        // 受影响起始版本
	VersionEnd   string `gorm:"size:50"`        // 受影响结束版本
	VersionExact string `gorm:"size:50"`        // 精确版本
	CPEMatch     string `gorm:"size:200"`       // CPE 匹配字符串
}

// KernelVersion 内核版本追踪
type KernelVersion struct {
	ID          uint      `gorm:"primaryKey"`
	Version     string    `gorm:"uniqueIndex;size:50"` // 版本号: 6.6.1
	Branch      string    `gorm:"size:50;index"`       // 分支: mainline/stable/longterm
	ReleaseDate time.Time                             // 发布日期
	EOLDate     *time.Time                            // 停止维护日期
	IsSupported bool                                  // 是否还在维护
	Source      string    `gorm:"size:50"`           // 来源
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// ============================================
// Kconfig 配置分析模型
// ============================================

// KconfigDependency 漏洞触发的 Kconfig 依赖
type KconfigDependency struct {
	ID             uint   `gorm:"primaryKey"`
	CVEID          string `gorm:"index;size:20"`
	PatchID        uint   `gorm:"index"`
	ConfigName     string `gorm:"size:100;index"` // CONFIG_XXX 名称
	ConfigFile     string `gorm:"size:500"`       // 定义所在的 Kconfig 文件
	Description    string `gorm:"type:text"`      // 配置描述
	DefaultValue   string `gorm:"size:50"`        // 默认值
	DependsOn      string `gorm:"type:text"`      // 依赖的其他 CONFIG (JSON 数组)
	Selects        string `gorm:"type:text"`      // 会选中的 CONFIG (JSON 数组)
	ImpliedBy      string `gorm:"type:text"`      // 反向依赖 (JSON 数组)
	IsVulnerable   bool                           // 启用此配置是否会触发漏洞
	IsRequired     bool                           // 是否是漏洞触发的必要条件
	IsSufficient   bool                           // 是否单独启用就足以触发
	Subsystem      string `gorm:"size:100;index"` // 子系统: networking/fs/mm/etc
	SourceFiles    string `gorm:"type:text"`      // 关联的源码文件 (JSON 数组)
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// KconfigAnalysis 针对特定内核版本的配置分析结果
type KconfigAnalysis struct {
	ID                uint      `gorm:"primaryKey"`
	CVEID             string    `gorm:"index;size:20"`
	KernelVersion     string    `gorm:"size:50;index"` // 分析的内核版本
	ConfigStatus      string    `gorm:"size:30"`       // VULNERABLE/PATCHED/NOT_APPLICABLE/UNKNOWN
	RequiredConfigs   string    `gorm:"type:text"`     // 必需配置 (JSON 数组)
	ActiveConfigs     string    `gorm:"type:text"`     // 当前启用的配置 (JSON 数组)
	MissingConfigs    string    `gorm:"type:text"`     // 缺失的必要配置 (JSON 数组)
	RiskLevel         string    `gorm:"size:20"`       // HIGH/MEDIUM/LOW
	Exploitable       bool                            // 是否可被利用
	ExploitConditions string    `gorm:"type:text"`     // 利用条件说明
	MitigationConfigs string    `gorm:"type:text"`     // 可缓解漏洞的配置项 (JSON)
	SuggestedConfig   string    `gorm:"type:text"`     // 建议的 .config 修改
	AnalyzedAt        time.Time
	CreatedAt         time.Time
}

// KconfigRule Kconfig 规则库条目
type KconfigRule struct {
	ID          uint      `gorm:"primaryKey"`
	CVEID       string    `gorm:"index;size:20"`
	RuleVersion string    `gorm:"size:20"`       // 规则版本
	Required    string    `gorm:"type:text"`     // 必需配置条件 (JSON)
	VulnerableIf string   `gorm:"type:text"`     // 触发漏洞的条件 (JSON)
	Mitigation  string    `gorm:"type:text"`     // 缓解措施 (JSON)
	Source      string    `gorm:"size:50"`       // 规则来源: community/manual/auto
	Author      string    `gorm:"size:100"`      // 规则作者
	Verified    bool                            // 是否已验证
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// ============================================
// 报告相关模型
// ============================================

// Report 报告记录
type Report struct {
	ID          uint      `gorm:"primaryKey"`
	Name        string    `gorm:"size:200"`      // 报告名称
	Type        string    `gorm:"size:50;index"` // 报告类型: cve/summary/audit
	Format      string    `gorm:"size:20"`       // 格式: json/markdown/html
	CVECount    int                             // 包含的 CVE 数量
	FilePath    string    `gorm:"size:500"`      // 报告文件路径
	QueryParams string    `gorm:"type:text"`     // 生成报告的查询参数 (JSON)
	GeneratedAt time.Time
	CreatedAt   time.Time
}

// ============================================
// 同步相关模型
// ============================================

// SyncLog 数据同步日志
type SyncLog struct {
	ID          uint      `gorm:"primaryKey"`
	Source      string    `gorm:"size:50;index"` // 数据源: NVD/CVE_ORG/etc
	Status      string    `gorm:"size:20"`       // SUCCESS/PARTIAL/FAILED
	StartTime   time.Time
	EndTime     time.Time
	TotalCount  int                             // 总 CVE 数
	NewCount    int                             // 新增 CVE 数
	UpdateCount int                             // 更新 CVE 数
	ErrorCount  int                             // 错误数
	Errors      string    `gorm:"type:text"`     // 错误详情 (JSON)
	CreatedAt   time.Time
}

// AllModels 返回所有模型，用于 AutoMigrate
func AllModels() []interface{} {
	return []interface{}{
		&CVE{},
		&CVEReference{},
		&Patch{},
		&FileChange{},
		&PatchStatus{},
		&PatchHistory{},
		&AffectedConfig{},
		&KernelVersion{},
		&KconfigDependency{},
		&KconfigAnalysis{},
		&KconfigRule{},
		&Report{},
		&SyncLog{},
	}
}

// BeforeCreate GORM 钩子 - 自动设置时间戳
func (c *CVE) BeforeCreate(tx *gorm.DB) error {
	if c.CreatedAt.IsZero() {
		c.CreatedAt = time.Now()
	}
	if c.UpdatedAt.IsZero() {
		c.UpdatedAt = time.Now()
	}
	return nil
}

// BeforeUpdate GORM 钩子 - 自动更新时间戳
func (c *CVE) BeforeUpdate(tx *gorm.DB) error {
	c.UpdatedAt = time.Now()
	return nil
}
