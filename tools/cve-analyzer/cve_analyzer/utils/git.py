"""
Git 仓库操作封装
使用 GitPython
"""

import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from git import Repo, Commit
from git.exc import GitCommandError, InvalidGitRepositoryError


@dataclass
class CommitInfo:
    """提交信息"""
    hash: str
    short_hash: str
    subject: str
    body: str
    author: str
    author_email: str
    author_date: datetime
    committer: str
    commit_date: datetime
    files_changed: List["FileChange"]
    parent_hashes: List[str]


@dataclass
class FileChange:
    """文件变更信息"""
    filename: str
    status: str  # Added/Modified/Deleted/Renamed
    additions: int
    deletions: int


class GitRepository:
    """Git 仓库封装"""
    
    def __init__(self, path: str):
        """
        初始化仓库
        
        Args:
            path: 仓库路径
        
        Raises:
            InvalidGitRepositoryError: 如果路径不是有效的 Git 仓库
        """
        self.path = Path(path)
        try:
            self.repo = Repo(path)
        except InvalidGitRepositoryError:
            raise InvalidGitRepositoryError(f"不是有效的 Git 仓库: {path}")
    
    @classmethod
    def clone(
        cls,
        url: str,
        path: str,
        branch: Optional[str] = None,
        depth: Optional[int] = None,
    ) -> "GitRepository":
        """
        克隆远程仓库
        
        Args:
            url: 远程仓库 URL
            path: 本地路径
            branch: 指定分支
            depth: 浅克隆深度
        
        Returns:
            GitRepository 实例
        """
        clone_kwargs = {}
        if branch:
            clone_kwargs["branch"] = branch
        if depth:
            clone_kwargs["depth"] = depth
        
        repo = Repo.clone_from(url, path, **clone_kwargs)
        return cls(path)
    
    @classmethod
    def init(cls, path: str) -> "GitRepository":
        """初始化新仓库"""
        repo = Repo.init(path)
        return cls(path)
    
    # ============================================
    # 远程操作
    # ============================================
    
    def fetch(self, remote: str = "origin") -> None:
        """获取远程更新"""
        remote_obj = self.repo.remote(remote)
        remote_obj.fetch()
    
    def pull(self, remote: str = "origin", branch: Optional[str] = None) -> None:
        """拉取远程更新"""
        origin = self.repo.remote(remote)
        if branch:
            origin.pull(branch)
        else:
            origin.pull()
    
    # ============================================
    # 分支操作
    # ============================================
    
    def checkout(self, target: str) -> None:
        """
        切换到指定分支或 commit
        
        Args:
            target: 分支名、tag 或 commit hash
        """
        self.repo.git.checkout(target)
    
    def checkout_commit(self, commit_hash: str) -> None:
        """
        切换到指定 commit (detach HEAD)
        
        Args:
            commit_hash: commit hash
        """
        self.repo.git.checkout(commit_hash, force=True)
    
    def get_current_branch(self) -> str:
        """获取当前分支名"""
        try:
            return self.repo.active_branch.name
        except TypeError:
            # detached HEAD
            return self.repo.head.commit.hexsha[:12]
    
    def list_branches(self) -> List[str]:
        """列出所有本地分支"""
        return [b.name for b in self.repo.branches]
    
    def list_remote_branches(self) -> List[str]:
        """列出所有远程分支"""
        return [b.name for b in self.repo.remote().refs]
    
    def list_tags(self) -> List[str]:
        """列出所有标签"""
        return [t.name for t in self.repo.tags]
    
    # ============================================
    # Commit 操作
    # ============================================
    
    def get_commit(self, commit_hash: str) -> CommitInfo:
        """
        获取指定 commit 的信息
        
        Args:
            commit_hash: commit hash (完整或短)
        
        Returns:
            CommitInfo
        """
        commit = self.repo.commit(commit_hash)
        return self._parse_commit(commit)
    
    def get_latest_commit(self) -> CommitInfo:
        """获取最新 commit"""
        return self._parse_commit(self.repo.head.commit)
    
    def find_commits_by_message(
        self,
        pattern: str,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
    ) -> List[CommitInfo]:
        """
        根据 commit message 搜索 commits
        
        Args:
            pattern: 搜索模式
            since: 起始时间
            until: 结束时间
        
        Returns:
            匹配的 commits 列表
        """
        # 构建 git log 参数
        log_args = ["--all", "--grep", pattern, "--format=%H"]
        
        if since:
            log_args.extend(["--since", since.isoformat()])
        if until:
            log_args.extend(["--until", until.isoformat()])
        
        # 执行 git log
        output = self.repo.git.log(*log_args)
        
        if not output:
            return []
        
        commits = []
        for line in output.strip().split("\n"):
            if line:
                commits.append(self.get_commit(line))
        
        return commits
    
    def find_commits_by_file(
        self,
        filename: str,
        since: Optional[datetime] = None,
    ) -> List[CommitInfo]:
        """
        查找修改指定文件的所有 commits
        
        Args:
            filename: 文件路径
            since: 起始时间
        
        Returns:
            修改过该文件的 commits 列表
        """
        log_args = ["--all", "--follow", "--format=%H", "--", filename]
        
        if since:
            log_args.extend(["--since", since.isoformat()])
        
        output = self.repo.git.log(*log_args)
        
        if not output:
            return []
        
        commits = []
        for line in output.strip().split("\n"):
            if line:
                commits.append(self.get_commit(line))
        
        return commits
    
    def is_commit_exists(self, commit_hash: str) -> bool:
        """检查 commit 是否存在于仓库"""
        try:
            self.repo.commit(commit_hash)
            return True
        except Exception:
            return False
    
    def get_tags_containing_commit(self, commit_hash: str) -> List[str]:
        """
        获取包含指定 commit 的所有标签
        
        Args:
            commit_hash: commit hash
        
        Returns:
            标签列表
        """
        try:
            output = self.repo.git.tag("--contains", commit_hash)
            return output.strip().split("\n") if output else []
        except GitCommandError:
            return []
    
    def get_branches_containing_commit(self, commit_hash: str) -> List[str]:
        """
        获取包含指定 commit 的所有分支
        
        Args:
            commit_hash: commit hash
        
        Returns:
            分支列表
        """
        try:
            output = self.repo.git.branch("-a", "--contains", commit_hash)
            branches = []
            for line in output.strip().split("\n"):
                line = line.strip()
                if line.startswith("*"):
                    line = line[1:].strip()
                if line:
                    branches.append(line)
            return branches
        except GitCommandError:
            return []
    
    # ============================================
    # 文件操作
    # ============================================
    
    def get_file_content_at_commit(self, commit_hash: str, filepath: str) -> Optional[str]:
        """
        获取指定 commit 时的文件内容
        
        Args:
            commit_hash: commit hash
            filepath: 文件路径
        
        Returns:
            文件内容，如果文件不存在则返回 None
        """
        try:
            commit = self.repo.commit(commit_hash)
            blob = commit.tree / filepath
            return blob.data_stream.read().decode("utf-8", errors="replace")
        except Exception:
            return None
    
    def get_file_history(self, filepath: str) -> List[CommitInfo]:
        """获取文件的修改历史"""
        return self.find_commits_by_file(filepath)
    
    # ============================================
    # 辅助方法
    # ============================================
    
    def _parse_commit(self, commit: Commit) -> CommitInfo:
        """解析 commit 对象"""
        # 获取文件变更统计
        stats = commit.stats
        files_changed = []
        
        for filename, stat in stats.files.items():
            files_changed.append(FileChange(
                filename=filename,
                status="Modified",  # GitPython stats 不直接提供状态
                additions=stat.get("insertions", 0),
                deletions=stat.get("deletions", 0),
            ))
        
        return CommitInfo(
            hash=commit.hexsha,
            short_hash=commit.hexsha[:12],
            subject=commit.message.split("\n")[0],
            body=commit.message,
            author=commit.author.name,
            author_email=commit.author.email,
            author_date=commit.authored_datetime,
            committer=commit.committer.name,
            commit_date=commit.committed_datetime,
            files_changed=files_changed,
            parent_hashes=[p.hexsha for p in commit.parents],
        )
    
    def __repr__(self) -> str:
        return f"GitRepository(path='{self.path}')"
