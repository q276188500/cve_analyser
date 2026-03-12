// Package fetcher 提供 CVE 数据采集功能
package fetcher

import (
	"context"
	"cve-analyzer/pkg/models"
)

// Fetcher 是 CVE 数据采集器接口
type Fetcher interface {
	// Name 返回采集器名称
	Name() string
	// Fetch 获取 CVE 数据
	Fetch(ctx context.Context, since string) ([]models.CVE, error)
	// FetchOne 获取单个 CVE
	FetchOne(ctx context.Context, cveID string) (*models.CVE, error)
}

// FetchResult 采集结果
type FetchResult struct {
	CVEs        []models.CVE
	Total       int
	New         int
	Updated     int
	Failed      int
	Errors      []error
}
