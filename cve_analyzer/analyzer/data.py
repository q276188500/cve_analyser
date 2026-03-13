"""
补丁数据类 (用于分析器，避免 SQLAlchemy 依赖)
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional


@dataclass
class FileChangeData:
    """文件变更数据类"""
    filename: str
    status: str = "Modified"
    additions: int = 0
    deletions: int = 0
    functions: List[str] = field(default_factory=list)
    old_file_hash: Optional[str] = None
    new_file_hash: Optional[str] = None
    patch_content: Optional[str] = None


@dataclass
class PatchData:
    """补丁数据类 (非 ORM)"""
    id: int = 0
    cve_id: str = ""
    commit_hash: str = ""
    commit_hash_short: str = ""
    subject: str = ""
    body: str = ""
    author: str = ""
    author_email: str = ""
    author_date: Optional[datetime] = None
    committer: str = ""
    commit_date: Optional[datetime] = None
    files_changed: List[FileChangeData] = field(default_factory=list)
    branches: List[str] = field(default_factory=list)
    backported_to: List[str] = field(default_factory=list)
    not_backported_to: List[str] = field(default_factory=list)


@dataclass
class VersionImpact:
    """版本影响分析结果"""
    mainline_affected: List[str] = field(default_factory=list)
    stable_affected: List[str] = field(default_factory=list)
    longterm_affected: List[str] = field(default_factory=list)
    backported_to: List[str] = field(default_factory=list)
    not_backported_to: List[str] = field(default_factory=list)


@dataclass
class AnalysisResult:
    """分析结果"""
    cve: "CVE" = None
    patches: List[PatchData] = field(default_factory=list)
    affected_files: List[str] = field(default_factory=list)
    affected_functions: List[str] = field(default_factory=list)
    version_impact: VersionImpact = field(default_factory=VersionImpact)
    body: str = ""
    author: str = ""
    author_email: str = ""
    author_date: Optional[datetime] = None
    committer: str = ""
    commit_date: Optional[datetime] = None
    files_changed: List[FileChangeData] = field(default_factory=list)
    branches: List[str] = field(default_factory=list)
    backported_to: List[str] = field(default_factory=list)
    not_backported_to: List[str] = field(default_factory=list)

    def to_model(self):
        """转换为 SQLAlchemy 模型"""
        from cve_analyzer.core.models import Patch, FileChange
        
        patch = Patch(
            id=self.id,
            cve_id=self.cve_id,
            commit_hash=self.commit_hash,
            commit_hash_short=self.commit_hash_short,
            subject=self.subject,
            body=self.body,
            author=self.author,
            author_email=self.author_email,
            author_date=self.author_date,
            committer=self.committer,
            commit_date=self.commit_date,
            branches=self.branches,
            backported_to=self.backported_to,
            not_backported_to=self.not_backported_to,
        )
        
        for fc in self.files_changed:
            patch.files_changed.append(FileChange(
                filename=fc.filename,
                status=fc.status,
                additions=fc.additions,
                deletions=fc.deletions,
                functions=fc.functions,
                old_file_hash=fc.old_file_hash,
                new_file_hash=fc.new_file_hash,
                patch_content=fc.patch_content,
            ))
        
        return patch
    
    @classmethod
    def from_model(cls, patch: "Patch") -> "PatchData":
        """从 SQLAlchemy 模型创建"""
        data = cls(
            id=patch.id,
            cve_id=patch.cve_id,
            commit_hash=patch.commit_hash,
            commit_hash_short=patch.commit_hash_short,
            subject=patch.subject,
            body=patch.body,
            author=patch.author,
            author_email=patch.author_email,
            author_date=patch.author_date,
            committer=patch.committer,
            commit_date=patch.commit_date,
            branches=patch.branches or [],
            backported_to=patch.backported_to or [],
            not_backported_to=patch.not_backported_to or [],
        )
        
        for fc in patch.files_changed:
            data.files_changed.append(FileChangeData(
                filename=fc.filename,
                status=fc.status,
                additions=fc.additions,
                deletions=fc.deletions,
                functions=fc.functions or [],
                old_file_hash=fc.old_file_hash,
                new_file_hash=fc.new_file_hash,
                patch_content=fc.patch_content,
            ))
        
        return data
