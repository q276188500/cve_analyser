"""
工具函数模块
"""

import hashlib
import re
from typing import List


def is_valid_cve_id(cve_id: str) -> bool:
    """
    检查 CVE ID 格式是否有效
    
    Args:
        cve_id: CVE ID 字符串
    
    Returns:
        是否有效
    """
    pattern = r"^CVE-\d{4}-\d{4,}$"
    return bool(re.match(pattern, cve_id))


def extract_cve_ids(text: str) -> List[str]:
    """
    从文本中提取 CVE ID
    
    Args:
        text: 文本内容
    
    Returns:
        CVE ID 列表
    """
    pattern = r"CVE-\d{4}-\d{4,}"
    return re.findall(pattern, text)


def is_valid_commit_hash(hash_str: str) -> bool:
    """
    检查 Git commit hash 格式
    
    Args:
        hash_str: hash 字符串
    
    Returns:
        是否有效
    """
    pattern = r"^[a-f0-9]{7,40}$"
    return bool(re.match(pattern, hash_str.lower()))


def normalize_commit_hash(hash_str: str) -> str:
    """规范化 commit hash (转为小写)"""
    return hash_str.lower().strip()


def shorten_commit_hash(hash_str: str) -> str:
    """缩短 commit hash 到 12 位"""
    return hash_str[:12] if len(hash_str) > 12 else hash_str


def calculate_sha256(content: str) -> str:
    """计算字符串的 SHA256"""
    return hashlib.sha256(content.encode()).hexdigest()


def calculate_file_hash(content: bytes) -> str:
    """计算文件内容的 SHA256"""
    return hashlib.sha256(content).hexdigest()


def truncate_string(s: str, max_len: int) -> str:
    """截断字符串到指定长度"""
    return s if len(s) <= max_len else s[:max_len] + "..."


def sanitize_filename(name: str) -> str:
    """清理文件名，移除非法字符"""
    illegal = ["/", "\\", ":", "*", "?", '"', "<", ">", "|"]
    result = name
    for char in illegal:
        result = result.replace(char, "_")
    return result


def compare_versions(v1: str, v2: str) -> int:
    """
    比较两个内核版本号
    
    Returns:
        -1: v1 < v2
         0: v1 == v2
         1: v1 > v2
    """
    def parse_version(v: str) -> List[int]:
        # 解析 x.y.z 格式
        parts = v.split(".")
        result = []
        for part in parts:
            # 提取数字部分
            num = ""
            for c in part:
                if c.isdigit():
                    num += c
                else:
                    break
            if num:
                result.append(int(num))
        return result
    
    parts1 = parse_version(v1)
    parts2 = parse_version(v2)
    
    for i in range(max(len(parts1), len(parts2))):
        n1 = parts1[i] if i < len(parts1) else 0
        n2 = parts2[i] if i < len(parts2) else 0
        
        if n1 < n2:
            return -1
        if n1 > n2:
            return 1
    
    return 0


def contains_string(lst: List[str], item: str) -> bool:
    """检查字符串列表是否包含指定字符串"""
    return item in lst


def unique_strings(lst: List[str]) -> List[str]:
    """去重字符串列表 (保持顺序)"""
    seen = set()
    result = []
    for s in lst:
        if s not in seen:
            seen.add(s)
            result.append(s)
    return result


def remove_empty_strings(lst: List[str]) -> List[str]:
    """移除空字符串"""
    return [s for s in lst if s.strip()]
