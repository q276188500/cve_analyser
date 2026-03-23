# Patch Parser - 解析 diff 内容

import re
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class FileChange:
    """文件变更"""
    path: str
    old_path: Optional[str] = None  # 重命名时
    additions: int = 0
    deletions: int = 0
    hunks: List['Hunk'] = field(default_factory=list)
    change_type: str = "modify"  # add, delete, modify, rename


@dataclass
class Hunk:
    """代码块"""
    old_start: int
    old_count: int
    new_start: int
    new_count: int
    content: str


@dataclass
class FunctionChange:
    """函数变更"""
    function_name: str
    file_path: str
    change_type: str  # added, deleted, modified
    context: str = ""  # 函数周围代码


@dataclass
class PatchInfo:
    """Patch 完整信息"""
    raw: str
    files: List[FileChange] = field(default_factory=list)
    functions: List[FunctionChange] = field(default_factory=list)
    commit_hash: Optional[str] = None
    commit_message: Optional[str] = None
    author: Optional[str] = None


class PatchParser:
    """Patch 解析器"""
    
    # diff 文件头正则
    DIFF_HEADER_RE = re.compile(
        r'^diff --git a/(.+?) b/(.+?)$'
    )
    FILE_HEADER_RE = re.compile(
        r'^\+\+\+ b/(.+?)$|^\+\+\+ (/.+?)$'
    )
    HUNK_RE = re.compile(
        r'^@@ -(\d+),?(\d*) \+(\d+),?(\d*) @@'
    )
    FUNCTION_RE = re.compile(
        r'^(\w+)\s*\([^)]*\)\s*\{'  # 函数名匹配
    )
    
    def __init__(self):
        self.current_file: Optional[FileChange] = None
        self.current_hunk: Optional[Hunk] = None
    
    def parse(self, patch_content: str) -> PatchInfo:
        """解析 patch 内容"""
        info = PatchInfo(raw=patch_content)
        lines = patch_content.split('\n')
        
        i = 0
        while i < len(lines):
            line = lines[i]
            
            # 检测 diff 文件头
            diff_match = self.DIFF_HEADER_RE.match(line)
            if diff_match:
                # 保存之前的文件
                if self.current_file:
                    info.files.append(self.current_file)
                
                old_path = diff_match.group(1)
                new_path = diff_match.group(2)
                
                self.current_file = FileChange(
                    path=new_path,
                    old_path=old_path if old_path != new_path else None,
                    change_type="rename" if old_path != new_path else "modify"
                )
                i += 1
                continue
            
            # 检测文件头 +++
            file_match = self.FILE_HEADER_RE.match(line)
            if file_match and self.current_file:
                path = file_match.group(1) or file_match.group(2)
                self.current_file.path = path
                i += 1
                continue
            
            # 检测 hunk 头
            hunk_match = self.HUNK_RE.match(line)
            if hunk_match and self.current_file:
                # 保存之前的 hunk
                if self.current_hunk:
                    self.current_file.hunks.append(self.current_hunk)
                
                self.current_hunk = Hunk(
                    old_start=int(hunk_match.group(1)),
                    old_count=int(hunk_match.group(2)) if hunk_match.group(2) else 1,
                    new_start=int(hunk_match.group(3)),
                    new_count=int(hunk_match.group(4)) if hunk_match.group(4) else 1,
                    content=""
                )
                i += 1
                continue
            
            # 收集 hunk 内容
            if self.current_hunk:
                if line.startswith('+') and not line.startswith('+++'):
                    self.current_file.additions += 1
                elif line.startswith('-') and not line.startswith('---'):
                    self.current_file.deletions += 1
                self.current_hunk.content += line + '\n'
            
            # 检测提交信息 (git format-patch)
            if line.startswith('commit '):
                info.commit_hash = line.split()[1]
            elif line.startswith('Author:'):
                info.author = line.replace('Author:', '').strip()
            elif line.startswith('    ') and not info.commit_message:
                info.commit_message = line.strip()
            
            i += 1
        
        # 保存最后的文件
        if self.current_file:
            if self.current_hunk:
                self.current_file.hunks.append(self.current_hunk)
            info.files.append(self.current_file)
        
        # 推断文件变更类型
        for f in info.files:
            if f.additions > 0 and f.deletions == 0:
                f.change_type = "add"
            elif f.deletions > 0 and f.additions == 0:
                f.change_type = "delete"
        
        return info
    
    def extract_functions(self, info: PatchInfo) -> List[FunctionChange]:
        """提取函数变更"""
        functions = []
        
        for file_change in info.files:
            for hunk in file_change.hunk:
                content = hunk.content
                # 简单函数检测
                for line in content.split('\n'):
                    if line.startswith('+') and '{' in line:
                        # 尝试提取函数名
                        func_match = re.search(r'(\w+)\s*\([^)]*\)\s*\{', line)
                        if func_match:
                            functions.append(FunctionChange(
                                function_name=func_match.group(1),
                                file_path=file_change.path,
                                change_type="modified" if hunk.old_count > 0 else "added"
                            ))
        
        return functions


def parse_patch(patch_content: str) -> PatchInfo:
    """便捷函数：解析 patch"""
    parser = PatchParser()
    return parser.parse(patch_content)
