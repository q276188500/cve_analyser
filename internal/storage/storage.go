// Package storage 提供数据库操作功能
package storage

import (
	"cve-analyzer/pkg/models"
	"fmt"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Storage 数据库操作封装
type Storage struct {
	db *gorm.DB
}

// New 创建新的 Storage 实例
func New(dbPath string) (*Storage, error) {
	// 配置 GORM
	config := &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent), // 生产环境可改为 Silent
	}

	// 连接数据库
	db, err := gorm.Open(sqlite.Open(dbPath), config)
	if err != nil {
		return nil, fmt.Errorf("连接数据库失败: %w", err)
	}

	// 设置连接池 (SQLite 不需要太多连接)
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("获取底层数据库失败: %w", err)
	}
	sqlDB.SetMaxOpenConns(1) // SQLite 建议单连接
	sqlDB.SetMaxIdleConns(1)

	return &Storage{db: db}, nil
}

// AutoMigrate 自动迁移数据库模型
func (s *Storage) AutoMigrate() error {
	return s.db.AutoMigrate(models.AllModels()...)
}

// Close 关闭数据库连接
func (s *Storage) Close() error {
	sqlDB, err := s.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

// DB 返回原始 GORM DB 实例 (用于高级查询)
func (s *Storage) DB() *gorm.DB {
	return s.db
}

// ============================================
// CVE 操作
// ============================================

// CreateCVE 创建 CVE 记录
func (s *Storage) CreateCVE(cve *models.CVE) error {
	return s.db.Create(cve).Error
}

// GetCVE 根据 ID 获取 CVE
func (s *Storage) GetCVE(id string) (*models.CVE, error) {
	var cve models.CVE
	err := s.db.Preload("References").Preload("Patches").First(&cve, "id = ?", id).Error
	if err != nil {
		return nil, err
	}
	return &cve, nil
}

// GetCVEWithRelations 获取 CVE 及其所有关联数据
func (s *Storage) GetCVEWithRelations(id string) (*models.CVE, error) {
	var cve models.CVE
	err := s.db.
		Preload("References").
		Preload("AffectedConfigs").
		Preload("Patches.FileChanges").
		Preload("Patches.PatchStatus").
		Preload("Patches.PatchHistory").
		First(&cve, "id = ?", id).Error
	if err != nil {
		return nil, err
	}
	return &cve, nil
}

// UpdateCVE 更新 CVE 记录
func (s *Storage) UpdateCVE(cve *models.CVE) error {
	return s.db.Save(cve).Error
}

// CreateOrUpdateCVE 创建或更新 CVE
func (s *Storage) CreateOrUpdateCVE(cve *models.CVE) error {
	var existing models.CVE
	result := s.db.First(&existing, "id = ?", cve.ID)
	
	if result.Error == gorm.ErrRecordNotFound {
		// 创建新记录
		return s.db.Create(cve).Error
	} else if result.Error != nil {
		return result.Error
	}
	
	// 更新现有记录
	return s.db.Model(&existing).Updates(cve).Error
}

// ListCVEs 列出 CVE (支持分页和筛选)
type CVEFilter struct {
	Severity   string
	Since      string
	Until      string
	Keyword    string
	Limit      int
	Offset     int
}

func (s *Storage) ListCVEs(filter CVEFilter) ([]models.CVE, int64, error) {
	var cves []models.CVE
	var total int64

	query := s.db.Model(&models.CVE{})

	// 应用筛选条件
	if filter.Severity != "" {
		query = query.Where("severity = ?", filter.Severity)
	}
	if filter.Since != "" {
		query = query.Where("published_date >= ?", filter.Since)
	}
	if filter.Until != "" {
		query = query.Where("published_date <= ?", filter.Until)
	}
	if filter.Keyword != "" {
		query = query.Where("description LIKE ? OR id LIKE ?", 
			"%"+filter.Keyword+"%", "%"+filter.Keyword+"%")
	}

	// 获取总数
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	// 分页
	if filter.Limit > 0 {
		query = query.Limit(filter.Limit)
	}
	if filter.Offset > 0 {
		query = query.Offset(filter.Offset)
	}

	// 排序
	query = query.Order("published_date DESC")

	if err := query.Find(&cves).Error; err != nil {
		return nil, 0, err
	}

	return cves, total, nil
}

// ============================================
// 补丁操作
// ============================================

// CreatePatch 创建补丁记录
func (s *Storage) CreatePatch(patch *models.Patch) error {
	return s.db.Create(patch).Error
}

// GetPatch 根据 ID 获取补丁
func (s *Storage) GetPatch(id uint) (*models.Patch, error) {
	var patch models.Patch
	err := s.db.Preload("FileChanges").First(&patch, id).Error
	if err != nil {
		return nil, err
	}
	return &patch, nil
}

// GetPatchByCommit 根据 commit hash 获取补丁
func (s *Storage) GetPatchByCommit(hash string) (*models.Patch, error) {
	var patch models.Patch
	err := s.db.Where("commit_hash = ? OR commit_hash_short = ?", hash, hash).
		Preload("FileChanges").
		First(&patch).Error
	if err != nil {
		return nil, err
	}
	return &patch, nil
}

// ListPatchesByCVE 获取 CVE 的所有补丁
func (s *Storage) ListPatchesByCVE(cveID string) ([]models.Patch, error) {
	var patches []models.Patch
	err := s.db.Where("cve_id = ?", cveID).
		Preload("FileChanges").
		Find(&patches).Error
	return patches, err
}

// ============================================
// 补丁状态操作
// ============================================

// CreatePatchStatus 创建补丁状态记录
func (s *Storage) CreatePatchStatus(status *models.PatchStatus) error {
	return s.db.Create(status).Error
}

// GetPatchStatus 获取补丁状态
func (s *Storage) GetPatchStatus(cveID, version string) (*models.PatchStatus, error) {
	var status models.PatchStatus
	err := s.db.Where("cve_id = ? AND target_version = ?", cveID, version).
		Order("checked_at DESC").
		First(&status).Error
	if err != nil {
		return nil, err
	}
	return &status, nil
}

// ListPatchStatuses 列出补丁的所有状态检测记录
func (s *Storage) ListPatchStatuses(cveID string) ([]models.PatchStatus, error) {
	var statuses []models.PatchStatus
	err := s.db.Where("cve_id = ?", cveID).
		Order("checked_at DESC").
		Find(&statuses).Error
	return statuses, err
}

// ============================================
// Kconfig 操作
// ============================================

// CreateKconfigRule 创建 Kconfig 规则
func (s *Storage) CreateKconfigRule(rule *models.KconfigRule) error {
	return s.db.Create(rule).Error
}

// GetKconfigRule 获取 Kconfig 规则
func (s *Storage) GetKconfigRule(cveID string) (*models.KconfigRule, error) {
	var rule models.KconfigRule
	err := s.db.Where("cve_id = ?", cveID).
		Order("updated_at DESC").
		First(&rule).Error
	if err != nil {
		return nil, err
	}
	return &rule, nil
}

// CreateKconfigAnalysis 创建 Kconfig 分析结果
func (s *Storage) CreateKconfigAnalysis(analysis *models.KconfigAnalysis) error {
	return s.db.Create(analysis).Error
}

// GetKconfigAnalysis 获取 Kconfig 分析结果
func (s *Storage) GetKconfigAnalysis(cveID, version string) (*models.KconfigAnalysis, error) {
	var analysis models.KconfigAnalysis
	err := s.db.Where("cve_id = ? AND kernel_version = ?", cveID, version).
		Order("analyzed_at DESC").
		First(&analysis).Error
	if err != nil {
		return nil, err
	}
	return &analysis, nil
}

// ============================================
// 同步日志操作
// ============================================

// CreateSyncLog 创建同步日志
func (s *Storage) CreateSyncLog(log *models.SyncLog) error {
	return s.db.Create(log).Error
}

// UpdateSyncLog 更新同步日志
func (s *Storage) UpdateSyncLog(log *models.SyncLog) error {
	return s.db.Save(log).Error
}

// GetLatestSyncLog 获取最新的同步日志
func (s *Storage) GetLatestSyncLog(source string) (*models.SyncLog, error) {
	var log models.SyncLog
	err := s.db.Where("source = ?", source).
		Order("start_time DESC").
		First(&log).Error
	if err != nil {
		return nil, err
	}
	return &log, nil
}

// ============================================
// 事务支持
// ============================================

// Transaction 执行事务
func (s *Storage) Transaction(fn func(tx *gorm.DB) error) error {
	return s.db.Transaction(fn)
}
