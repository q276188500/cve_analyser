"""
工具函数测试
"""

import pytest

from cve_analyzer.utils import (
    is_valid_cve_id,
    extract_cve_ids,
    is_valid_commit_hash,
    normalize_commit_hash,
    shorten_commit_hash,
    calculate_sha256,
    calculate_file_hash,
    truncate_string,
    sanitize_filename,
    compare_versions,
    contains_string,
    unique_strings,
    remove_empty_strings,
)


class TestCVEValidation:
    """CVE ID 验证测试"""
    
    def test_valid_cve_id(self):
        """测试有效的 CVE ID"""
        assert is_valid_cve_id("CVE-2024-1234") is True
        assert is_valid_cve_id("CVE-2023-12345") is True
        assert is_valid_cve_id("CVE-2024-12345678") is True
    
    def test_invalid_cve_id(self):
        """测试无效的 CVE ID"""
        assert is_valid_cve_id("CVE-2024") is False  # 缺少编号
        assert is_valid_cve_id("2024-1234") is False  # 缺少 CVE 前缀
        assert is_valid_cve_id("CVE-24-1234") is False  # 年份不是4位
        assert is_valid_cve_id("cve-2024-1234") is False  # 小写
        assert is_valid_cve_id("") is False
        assert is_valid_cve_id("random text") is False
    
    def test_extract_single_cve(self):
        """测试提取单个 CVE"""
        text = "This is about CVE-2024-1234"
        result = extract_cve_ids(text)
        
        assert len(result) == 1
        assert result[0] == "CVE-2024-1234"
    
    def test_extract_multiple_cves(self):
        """测试提取多个 CVE"""
        text = "CVE-2024-1234 and CVE-2024-5678 are related to CVE-2023-9999"
        result = extract_cve_ids(text)
        
        assert len(result) == 3
        assert "CVE-2024-1234" in result
        assert "CVE-2024-5678" in result
        assert "CVE-2023-9999" in result
    
    def test_extract_no_cve(self):
        """测试没有 CVE 时返回空列表"""
        text = "No vulnerabilities here"
        result = extract_cve_ids(text)
        
        assert result == []


class TestCommitHashValidation:
    """Commit hash 验证测试"""
    
    def test_valid_short_hash(self):
        """测试有效的短 hash"""
        assert is_valid_commit_hash("abc1234") is True  # 7 位
        assert is_valid_commit_hash("abc123456789") is True  # 12 位
    
    def test_valid_full_hash(self):
        """测试有效的完整 hash"""
        hash_40 = "a" * 40
        assert is_valid_commit_hash(hash_40) is True
    
    def test_valid_mixed_case(self):
        """测试大小写混合"""
        assert is_valid_commit_hash("ABC1234") is True
        assert is_valid_commit_hash("AbC123dEf456") is True
    
    def test_invalid_hash_too_short(self):
        """测试过短的 hash"""
        assert is_valid_commit_hash("abc123") is False  # 6 位
    
    def test_invalid_hash_too_long(self):
        """测试过长的 hash"""
        assert is_valid_commit_hash("a" * 41) is False
    
    def test_invalid_hash_non_hex(self):
        """测试非十六进制字符"""
        assert is_valid_commit_hash("xyz1234") is False
        assert is_valid_commit_hash("abc_123") is False
    
    def test_normalize_commit_hash(self):
        """测试规范化 hash"""
        assert normalize_commit_hash("ABC123") == "abc123"
        assert normalize_commit_hash("  abc123  ") == "abc123"
    
    def test_shorten_commit_hash(self):
        """测试缩短 hash"""
        long_hash = "abc123def45678901234567890abcdef12345678"
        assert shorten_commit_hash(long_hash) == "abc123def456"
        
        short_hash = "abc123"
        assert shorten_commit_hash(short_hash) == "abc123"


class TestHashCalculation:
    """哈希计算测试"""
    
    def test_calculate_sha256_string(self):
        """测试计算字符串 SHA256"""
        result = calculate_sha256("hello world")
        
        assert len(result) == 64  # SHA256 是 64 位十六进制
        assert result == "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    
    def test_calculate_sha256_empty_string(self):
        """测试空字符串"""
        result = calculate_sha256("")
        
        assert len(result) == 64
    
    def test_calculate_file_hash(self):
        """测试计算文件内容哈希"""
        content = b"test content"
        result = calculate_file_hash(content)
        
        assert len(result) == 64
    
    def test_hash_consistency(self):
        """测试哈希一致性"""
        text = "consistent text"
        hash1 = calculate_sha256(text)
        hash2 = calculate_sha256(text)
        
        assert hash1 == hash2
    
    def test_hash_uniqueness(self):
        """测试不同内容哈希不同"""
        hash1 = calculate_sha256("text1")
        hash2 = calculate_sha256("text2")
        
        assert hash1 != hash2


class TestStringManipulation:
    """字符串操作测试"""
    
    def test_truncate_short_string(self):
        """测试短字符串不截断"""
        text = "short"
        result = truncate_string(text, 100)
        
        assert result == "short"
    
    def test_truncate_long_string(self):
        """测试长字符串截断"""
        text = "a" * 100
        result = truncate_string(text, 10)
        
        assert result == "a" * 10 + "..."
        assert len(result) == 13
    
    def test_truncate_exact_length(self):
        """测试刚好长度的字符串"""
        text = "exactly ten"
        result = truncate_string(text, 11)
        
        assert result == "exactly ten"
    
    def test_sanitize_filename(self):
        """测试清理文件名"""
        assert sanitize_filename("file/name") == "file_name"
        assert sanitize_filename("file\\name") == "file_name"
        assert sanitize_filename("file:name") == "file_name"
        assert sanitize_filename('file"name') == "file_name"
        assert sanitize_filename("file<name>") == "file_name_"
        assert sanitize_filename("file|name") == "file_name"
    
    def test_sanitize_filename_no_change(self):
        """测试不需要清理的文件名"""
        assert sanitize_filename("valid_filename.txt") == "valid_filename.txt"
        assert sanitize_filename("file-name_v2") == "file-name_v2"


class TestVersionComparison:
    """版本比较测试"""
    
    def test_same_version(self):
        """测试相同版本"""
        assert compare_versions("5.15.1", "5.15.1") == 0
        assert compare_versions("6.1", "6.1") == 0
    
    def test_first_version_lower(self):
        """测试第一个版本较低"""
        assert compare_versions("5.14", "5.15") == -1
        assert compare_versions("5.15.0", "5.15.1") == -1
        assert compare_versions("5.15", "6.0") == -1
    
    def test_first_version_higher(self):
        """测试第一个版本较高"""
        assert compare_versions("5.16", "5.15") == 1
        assert compare_versions("5.15.2", "5.15.1") == 1
        assert compare_versions("6.0", "5.15") == 1
    
    def test_different_length_versions(self):
        """测试不同长度版本号"""
        assert compare_versions("5.15", "5.15.0") == 0
        assert compare_versions("5.15", "5.15.1") == -1
        assert compare_versions("6.1.50", "6.1") == 1
    
    def test_complex_version_strings(self):
        """测试复杂的版本字符串"""
        # 带后缀的版本号
        assert compare_versions("5.15.100-generic", "5.15.100") == 0
        assert compare_versions("6.1.0-rc1", "6.1.0") == 0
        assert compare_versions("5.15.100-1", "5.15.100") == 0


class TestListOperations:
    """列表操作测试"""
    
    def test_contains_string_found(self):
        """测试包含字符串"""
        lst = ["a", "b", "c"]
        assert contains_string(lst, "b") is True
    
    def test_contains_string_not_found(self):
        """测试不包含字符串"""
        lst = ["a", "b", "c"]
        assert contains_string(lst, "d") is False
    
    def test_contains_string_empty_list(self):
        """测试空列表"""
        assert contains_string([], "a") is False
    
    def test_unique_strings(self):
        """测试去重"""
        lst = ["a", "b", "a", "c", "b", "d"]
        result = unique_strings(lst)
        
        assert result == ["a", "b", "c", "d"]
    
    def test_unique_strings_preserves_order(self):
        """测试去重保持顺序"""
        lst = ["z", "a", "z", "b", "a"]
        result = unique_strings(lst)
        
        assert result == ["z", "a", "b"]
    
    def test_unique_strings_empty(self):
        """测试空列表去重"""
        assert unique_strings([]) == []
    
    def test_unique_strings_no_duplicates(self):
        """测试无重复列表"""
        lst = ["a", "b", "c"]
        assert unique_strings(lst) == ["a", "b", "c"]
    
    def test_remove_empty_strings(self):
        """测试移除空字符串"""
        lst = ["a", "", "b", "   ", "c", ""]
        result = remove_empty_strings(lst)
        
        assert result == ["a", "b", "c"]
    
    def test_remove_empty_strings_all_empty(self):
        """测试全空列表"""
        lst = ["", "   ", "\t", "\n"]
        assert remove_empty_strings(lst) == []
    
    def test_remove_empty_strings_no_empty(self):
        """测试无空字符串"""
        lst = ["a", "b", "c"]
        assert remove_empty_strings(lst) == ["a", "b", "c"]
    
    def test_remove_empty_strings_empty_list(self):
        """测试空列表"""
        assert remove_empty_strings([]) == []
