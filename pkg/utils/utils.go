// Package utils 提供通用工具函数
package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

// IsValidCVEID 检查 CVE ID 格式是否有效
func IsValidCVEID(id string) bool {
	// CVE-YYYY-NNNNN 格式
	pattern := `^CVE-\d{4}-\d{4,}$`
	matched, _ := regexp.MatchString(pattern, id)
	return matched
}

// ExtractCVEID 从文本中提取 CVE ID
func ExtractCVEID(text string) []string {
	pattern := `CVE-\d{4}-\d{4,}`
	re := regexp.MustCompile(pattern)
	return re.FindAllString(text, -1)
}

// IsValidCommitHash 检查 Git commit hash 格式
func IsValidCommitHash(hash string) bool {
	// 支持 7-40 位十六进制
	pattern := `^[a-f0-9]{7,40}$`
	matched, _ := regexp.MatchString(pattern, strings.ToLower(hash))
	return matched
}

// NormalizeCommitHash 规范化 commit hash (转为小写)
func NormalizeCommitHash(hash string) string {
	return strings.ToLower(strings.TrimSpace(hash))
}

// ShortenCommitHash 缩短 commit hash 到 12 位
func ShortenCommitHash(hash string) string {
	if len(hash) <= 12 {
		return hash
	}
	return hash[:12]
}

// CalculateSHA256 计算字符串的 SHA256
func CalculateSHA256(content string) string {
	hash := sha256.Sum256([]byte(content))
	return hex.EncodeToString(hash[:])
}

// CalculateFileHash 计算文件内容的 SHA256
func CalculateFileHash(content []byte) string {
	hash := sha256.Sum256(content)
	return hex.EncodeToString(hash[:])
}

// TruncateString 截断字符串到指定长度
func TruncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// SanitizeFilename 清理文件名，移除非法字符
func SanitizeFilename(name string) string {
	// 替换非法字符
	illegal := []string{"/", "\\", ":", "*", "?", "\"", "<", ">", "|"}
	result := name
	for _, char := range illegal {
		result = strings.ReplaceAll(result, char, "_")
	}
	return result
}

// CompareVersions 比较两个内核版本号
// 返回值: -1 (v1 < v2), 0 (v1 == v2), 1 (v1 > v2)
func CompareVersions(v1, v2 string) int {
	// 简单实现，解析 x.y.z 格式
	parts1 := strings.Split(v1, ".")
	parts2 := strings.Split(v2, ".")

	for i := 0; i < len(parts1) && i < len(parts2); i++ {
		var n1, n2 int
		fmt.Sscanf(parts1[i], "%d", &n1)
		fmt.Sscanf(parts2[i], "%d", &n2)

		if n1 < n2 {
			return -1
		}
		if n1 > n2 {
			return 1
		}
	}

	// 长度不同
	if len(parts1) < len(parts2) {
		return -1
	}
	if len(parts1) > len(parts2) {
		return 1
	}
	return 0
}

// ContainsString 检查字符串数组是否包含指定字符串
func ContainsString(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// UniqueStrings 去重字符串数组
func UniqueStrings(slice []string) []string {
	seen := make(map[string]bool)
	result := []string{}
	for _, s := range slice {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}

// RemoveEmptyStrings 移除空字符串
func RemoveEmptyStrings(slice []string) []string {
	result := []string{}
	for _, s := range slice {
		if strings.TrimSpace(s) != "" {
			result = append(result, s)
		}
	}
	return result
}
