"""
补丁提取器

从各种来源提取补丁信息
"""

import re
from typing import List, Optional

from cve_analyzer.analyzer.data import PatchData, FileChangeData


class PatchExtractor:
    """补丁提取器"""
    
    def extract_from_commit(self, repo, commit_hash):
        """
        从 Git commit 提取补丁
        
        Args:
            repo: Git 仓库
            commit_hash: Commit hash
        
        Returns:
            PatchData 对象或 None
        """
        try:
            commit_info = repo.get_commit(commit_hash)
            
            # 处理 dict 或对象的情况
            if isinstance(commit_info, dict):
                patch = PatchData(
                    commit_hash=commit_info.get("hash", commit_hash),
                    commit_hash_short=commit_info.get("short_hash", commit_hash[:12]),
                    subject=commit_info.get("subject", ""),
                    body=commit_info.get("body", ""),
                    author=commit_info.get("author", ""),
                    author_email=commit_info.get("author_email", ""),
                    author_date=commit_info.get("author_date"),
                )
                
                # 转换文件变更
                files_changed = commit_info.get("files_changed", [])
                for fc in files_changed:
                    if isinstance(fc, dict):
                        patch.files_changed.append(FileChangeData(
                            filename=fc.get("filename", ""),
                            status=fc.get("status", "Modified"),
                            additions=fc.get("additions", 0),
                            deletions=fc.get("deletions", 0),
                        ))
                    else:
                        patch.files_changed.append(FileChangeData(
                            filename=fc.filename,
                            status=fc.status,
                            additions=fc.additions,
                            deletions=fc.deletions,
                        ))
            else:
                patch = PatchData(
                    commit_hash=commit_info.hash,
                    commit_hash_short=commit_info.short_hash,
                    subject=commit_info.subject,
                    body=commit_info.body,
                    author=commit_info.author,
                    author_email=commit_info.author_email,
                    author_date=commit_info.author_date,
                )
                
                # 转换文件变更
                for fc in commit_info.files_changed:
                    patch.files_changed.append(FileChangeData(
                        filename=fc.filename,
                        status=fc.status,
                        additions=fc.additions,
                        deletions=fc.deletions,
                    ))
            
            return patch
            
        except Exception as e:
            print(f"提取 commit {commit_hash} 失败: {e}")
            return None
    
    def extract_from_url(self, url: str) -> Optional[PatchData]:
        """
        从 URL 提取补丁
        
        Args:
            url: 补丁 URL
        
        Returns:
            PatchData 对象或 None
        """
        import requests
        
        # 解析 git.kernel.org URL
        if "git.kernel.org" in url:
            return self._extract_from_kernel_org(url)
        
        # 其他来源
        try:
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            return self._parse_patch_text(response.text)
        except Exception as e:
            print(f"从 URL 提取补丁失败: {e}")
            return None
    
    def _extract_from_kernel_org(self, url: str) -> Optional[PatchData]:
        """从 git.kernel.org 提取补丁"""
        import requests
        
        # 转换 URL 为 raw patch 格式
        # 例如: /c/abc123 -> /c/abc123.patch
        if "/c/" in url and not url.endswith(".patch"):
            url = url.rstrip("/") + ".patch"
        
        try:
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            return self._parse_patch_text(response.text)
        except Exception as e:
            print(f"从 kernel.org 提取失败: {e}")
            return None
    
    def _parse_patch_text(self, text: str) -> Optional[PatchData]:
        """解析补丁文本"""
        try:
            # 解析邮件头
            subject = ""
            author = ""
            
            # 提取 Subject
            subject_match = re.search(r'Subject:\s*\[PATCH\]?\s*(.+)', text, re.MULTILINE)
            if subject_match:
                subject = subject_match.group(1).strip()
            
            # 提取 From
            from_match = re.search(r'From:\s*(.+?)\s*<(.+?)>', text)
            if from_match:
                author = from_match.group(1).strip()
            
            # 提取文件变更
            files_changed = []
            file_pattern = r'diff --git a/(\S+) b/(\S+)'
            for match in re.finditer(file_pattern, text):
                filename = match.group(1)
                
                # 统计行数
                file_start = match.start()
                file_end = text.find('diff --git', file_start + 1)
                if file_end == -1:
                    file_end = len(text)
                
                file_text = text[file_start:file_end]
                additions = file_text.count('\n+')
                deletions = file_text.count('\n-')
                
                files_changed.append(FileChangeData(
                    filename=filename,
                    status="Modified",
                    additions=additions,
                    deletions=deletions,
                ))
            
            patch = PatchData(
                commit_hash="",  # 从 URL 提取的可能没有完整 hash
                subject=subject,
                author=author,
                files_changed=files_changed
            )
            
            return patch
            
        except Exception as e:
            print(f"解析补丁文本失败: {e}")
            return None
    
    def extract_from_mbox(self, content: str) -> List[PatchData]:
        """
        从 mbox 格式提取补丁
        
        Args:
            content: mbox 内容
        
        Returns:
            补丁列表
        """
        patches = []
        
        # 简单解析，按 From 分割
        messages = content.split("\nFrom ")
        
        for msg in messages:
            if not msg.strip():
                continue
            
            patch = self._parse_patch_text(msg)
            if patch:
                patches.append(patch)
        
        return patches
