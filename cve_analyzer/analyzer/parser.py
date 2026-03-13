"""
Commit 解析器

解析 commit message 和 diff 提取信息
"""

import re
from typing import Dict, List, Optional


class CommitParser:
    """Commit 解析器"""
    
    def parse_message(self, message: str) -> Dict:
        """
        解析 commit message
        
        Args:
            message: Commit message
        
        Returns:
            解析结果字典
        """
        result = {
            "cve_ids": [],
            "fixes": [],
            "cc_stable": False,
            "breaking_change": False,
        }
        
        # 提取 CVE ID
        cve_pattern = r'CVE-\d{4}-\d{4,}'
        result["cve_ids"] = re.findall(cve_pattern, message)
        
        # 提取 Fixes (commit hash 或 CVE ID)
        fixes_pattern = r'Fixes:\s*([0-9a-f]{8,40}|CVE-\d{4}-\d{4,})'
        result["fixes"] = re.findall(fixes_pattern, message, re.IGNORECASE)
        
        # 检查 Cc: stable
        result["cc_stable"] = bool(re.search(r'Cc:\s*stable@vger\.kernel\.org', message))
        
        # 检查是否是破坏性变更
        result["breaking_change"] = any(word in message.lower() for word in 
                                        ["breaking", "incompatible", "api change"])
        
        return result
    
    def parse_functions(self, diff: str) -> List[str]:
        """
        从 diff 解析函数名
        
        Args:
            diff: Diff 文本
        
        Returns:
            函数名列表
        """
        functions = []
        
        # 匹配 C 函数定义 (@@ 行后的大括号开始)
        # 例如: @@ -100,6 +100,9 @@ int nf_hook_slow(int pf, ...
        func_pattern = r'@@\s*-\d+,\d+\s+\+\d+,\d+\s+@@\s*(\w+\s+)?(\w+)\s*\('
        
        for match in re.finditer(func_pattern, diff):
            func_name = match.group(2)
            if func_name and func_name not in functions:
                functions.append(func_name)
        
        # 匹配简单的函数名模式
        # 例如: -void old_function(void)
        #       +void new_function(void)
        simple_pattern = r'^[\+\-]\s*(\w+)\s+\w+\s*\([^)]*\)\s*\{'
        for line in diff.split('\n'):
            match = re.match(simple_pattern, line)
            if match:
                func_name = match.group(1)
                if func_name not in functions:
                    functions.append(func_name)
        
        return functions
    
    def parse_affected_versions(self, message: str) -> Dict[str, Optional[str]]:
        """
        解析受影响的版本范围
        
        Args:
            message: Commit message
        
        Returns:
            {"start": "x.y", "end": "x.y"} 或 {}
        """
        versions = {}
        
        # 匹配版本范围描述
        # 例如: "affects kernels from v5.10 to v6.6"
        range_pattern = r'(?:from|since)\s+v?(\d+\.\d+)\s+(?:to|through|until)\s+v?(\d+\.\d+)'
        match = re.search(range_pattern, message, re.IGNORECASE)
        if match:
            versions["start"] = match.group(1)
            versions["end"] = match.group(2)
            return versions
        
        # 匹配 "introduced in vX.Y"
        intro_pattern = r'introduced\s+in\s+v?(\d+\.\d+)'
        match = re.search(intro_pattern, message, re.IGNORECASE)
        if match:
            versions["start"] = match.group(1)
            versions["end"] = None  # 到修复版本
        
        return versions
    
    def extract_patch_links(self, text: str) -> List[str]:
        """
        从文本提取补丁链接
        
        Args:
            text: 文本内容
        
        Returns:
            URL 列表
        """
        # 匹配 git.kernel.org 链接
        kernel_org_pattern = r'https?://git\.kernel\.org/[^\s\)]+'
        
        # 匹配 github commit 链接
        github_pattern = r'https?://github\.com/[^/]+/[^/]+/commit/[a-f0-9]+'
        
        links = []
        links.extend(re.findall(kernel_org_pattern, text))
        links.extend(re.findall(github_pattern, text))
        
        return links
