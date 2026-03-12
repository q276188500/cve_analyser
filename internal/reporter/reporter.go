// Package reporter 提供报告生成功能
package reporter

import (
	"cve-analyzer/pkg/models"
)

// Reporter 是报告生成器接口
type Reporter interface {
	// Generate 生成报告
	Generate(data ReportData, format Format) (string, error)
	// GenerateBatch 批量生成报告
	GenerateBatch(data []ReportData, format Format) (string, error)
}

// Format 报告格式
type Format string

const (
	FormatJSON     Format = "json"
	FormatMarkdown Format = "markdown"
	FormatHTML     Format = "html"
	FormatCSV      Format = "csv"
)

// ReportData 报告数据
type ReportData struct {
	Title       string
	GeneratedAt string
	CVEs        []models.CVE
	Patches     []models.Patch
	Statistics  Statistics
	Metadata    map[string]interface{}
}

// Statistics 统计信息
type Statistics struct {
	TotalCVEs      int
	CriticalCount  int
	HighCount      int
	MediumCount    int
	LowCount       int
	PatchedCount   int
	PendingCount   int
}

// ReporterOptions 报告选项
type ReporterOptions struct {
	IncludePatches  bool
	IncludeDiffs    bool
	IncludeHistory  bool
	IncludeKconfig  bool
	TemplatePath    string
}
