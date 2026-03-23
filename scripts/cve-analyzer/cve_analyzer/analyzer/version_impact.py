"""
版本影响分析器

分析补丁影响的内核版本范围
"""

from typing import List


class VersionImpact:
    """版本影响分析结果"""
    def __init__(self, mainline_affected=None, stable_affected=None, 
                 longterm_affected=None, backported_to=None, not_backported_to=None):
        self.mainline_affected = mainline_affected or []
        self.stable_affected = stable_affected or []
        self.longterm_affected = longterm_affected or []
        self.backported_to = backported_to or []
        self.not_backported_to = not_backported_to or []


class VersionImpactAnalyzer:
    """版本影响分析器"""
    
    def __init__(self, repo):
        """
        初始化分析器
        
        Args:
            repo: Linux 内核 Git 仓库
        """
        self.repo = repo
    
    def analyze(self, patch) -> VersionImpact:
        """
        分析补丁的版本影响
        
        Args:
            patch: 补丁对象
        
        Returns:
            版本影响分析结果
        """
        impact = VersionImpact(
            mainline_affected=[],
            stable_affected=[],
            longterm_affected=[],
            backported_to=[],
            not_backported_to=[],
        )
        
        commit_hash = patch.commit_hash
        if not commit_hash:
            return impact
        
        # 分析主线版本
        impact.mainline_affected = self._analyze_mainline(commit_hash)
        
        # 分析 stable 分支
        impact.backported_to = self._analyze_backports(commit_hash)
        
        # 分析未回溯的版本
        impact.not_backported_to = self._analyze_missing_backports(
            impact.mainline_affected, 
            impact.backported_to
        )
        
        return impact
    
    def _analyze_mainline(self, commit_hash: str) -> List[str]:
        """分析主线受影响版本"""
        affected = []
        
        try:
            # 获取包含该 commit 的 tags
            tags = self.repo.get_tags_containing_commit(commit_hash)
            
            # 确保 tags 是可迭代的
            if tags is None:
                return affected
            
            # 过滤主线版本 tag (vX.Y.Z)
            for tag in tags:
                if tag.startswith("v") and tag.count(".") >= 1:
                    # 简化：只取主要版本
                    version = tag.lstrip("v")
                    if version not in affected:
                        affected.append(version)
        
        except Exception as e:
            print(f"分析主线版本失败: {e}")
        
        return affected
    
    def _analyze_backports(self, commit_hash: str) -> List[str]:
        """分析已回溯的版本"""
        backported = []
        
        try:
            # 获取包含该 commit 的分支
            branches = self.repo.get_branches_containing_commit(commit_hash)
            
            # 提取 stable/longterm 版本
            for branch in branches:
                # 匹配 stable 分支 (linux-5.15.y, linux-6.1.y)
                if "stable" in branch or branch.endswith(".y"):
                    version = self._extract_version_from_branch(branch)
                    if version and version not in backported:
                        backported.append(version)
        
        except Exception as e:
            print(f"分析回溯版本失败: {e}")
        
        return backported
    
    def _analyze_missing_backports(self, mainline: List[str], backported: List[str]) -> List[str]:
        """分析未回溯的版本"""
        # 已知的稳定版本列表
        known_stable = [
            "5.4", "5.10", "5.15", "6.1", "6.6"
        ]
        
        missing = []
        
        # 检查每个已知的 stable 版本是否已回溯
        for stable_ver in known_stable:
            if stable_ver not in backported:
                # 检查是否应该回溯（基于主线受影响版本）
                if self._should_be_backported(stable_ver, mainline):
                    missing.append(stable_ver)
        
        return missing
    
    def _extract_version_from_branch(self, branch: str) -> str:
        """从分支名提取版本号"""
        import re
        
        # 匹配 linux-5.15.y 或 linux-6.1.y
        match = re.search(r'linux-(\d+\.\d+)\.y', branch)
        if match:
            return match.group(1)
        
        return None
    
    def _should_be_backported(self, stable_ver: str, mainline_affected: List[str]) -> bool:
        """判断某个 stable 版本是否应该回溯"""
        from cve_analyzer.utils import compare_versions
        
        # 简化逻辑：如果主线受影响版本 >= stable 版本，则应该回溯
        for mainline_ver in mainline_affected:
            try:
                if compare_versions(mainline_ver, stable_ver) >= 0:
                    return True
            except Exception:
                continue
        
        return False
    
    def get_first_fixed_version(self, commit_hash: str) -> str:
        """获取补丁首次引入的主线版本"""
        try:
            tags = self.repo.get_tags_containing_commit(commit_hash)
            
            # 按版本排序，取第一个
            versions = []
            for tag in tags:
                if tag.startswith("v"):
                    ver = tag.lstrip("v")
                    versions.append(ver)
            
            if versions:
                versions.sort(key=lambda x: [int(n) for n in x.split(".")])
                return versions[0]
        
        except Exception as e:
            print(f"获取首次修复版本失败: {e}")
        
        return ""
