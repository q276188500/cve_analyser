"""
数据模型定义
使用 SQLAlchemy 2.0 风格
"""

from datetime import datetime
from enum import Enum
from typing import List, Optional

from sqlalchemy import JSON, ForeignKey, String, Text, Float, Integer, DateTime, Boolean
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """ORM 基类"""
    pass


class Severity(str, Enum):
    """严重程度枚举"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class PatchStatusEnum(str, Enum):
    """补丁状态枚举"""
    APPLIED = "APPLIED"      # 已应用
    PENDING = "PENDING"      # 未应用 (存在漏洞)
    MODIFIED = "MODIFIED"    # 已修改 (不是原补丁)
    REVERTED = "REVERTED"    # 已回退
    UNKNOWN = "UNKNOWN"      # 未知


class DetectionMethod(str, Enum):
    """检测方法枚举"""
    COMMIT_HASH = "commit_hash"    # Commit hash 精确匹配
    FILE_HASH = "file_hash"        # 文件哈希匹配
    CONTENT = "content_match"      # 代码内容特征匹配
    AST = "ast_match"              # AST 特征匹配


class ChangeType(str, Enum):
    """补丁修改类型枚举"""
    ORIGINAL = "ORIGINAL"
    BACKPORT = "BACKPORT"
    FIXUP = "FIXUP"
    REVERT = "REVERT"
    REFACTOR = "REFACTOR"
    CONFLICT = "CONFLICT"


class ConfigStatus(str, Enum):
    """Kconfig 状态枚举"""
    VULNERABLE = "VULNERABLE"
    PATCHED = "PATCHED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    UNKNOWN = "UNKNOWN"


class RiskLevel(str, Enum):
    """风险等级枚举"""
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


# ============================================
# CVE 相关模型
# ============================================

class CVE(Base):
    """CVE 漏洞主表"""
    __tablename__ = "cves"
    
    id: Mapped[str] = mapped_column(String(20), primary_key=True)  # CVE-2024-XXXX
    description: Mapped[Optional[str]] = mapped_column(Text)
    published_date: Mapped[Optional[datetime]] = mapped_column(DateTime, index=True)
    last_modified: Mapped[Optional[datetime]] = mapped_column(DateTime)
    severity: Mapped[Optional[str]] = mapped_column(String(20), index=True)
    cvss_score: Mapped[Optional[float]] = mapped_column(Float, index=True)
    cvss_vector: Mapped[Optional[str]] = mapped_column(String(100))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )
    
    # 关系
    references: Mapped[List["CVEReference"]] = relationship(
        back_populates="cve", cascade="all, delete-orphan"
    )
    affected_configs: Mapped[List["AffectedConfig"]] = relationship(
        back_populates="cve", cascade="all, delete-orphan"
    )
    patches: Mapped[List["Patch"]] = relationship(
        back_populates="cve", cascade="all, delete-orphan"
    )


class CVEReference(Base):
    """CVE 参考链接表"""
    __tablename__ = "cve_references"
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    cve_id: Mapped[str] = mapped_column(String(20), ForeignKey("cves.id"), index=True)
    url: Mapped[str] = mapped_column(String(500))
    type: Mapped[Optional[str]] = mapped_column(String(50), index=True)  # PATCH/ADVISORY/EXPLOIT
    source: Mapped[Optional[str]] = mapped_column(String(50))  # NVD/MITRE/GIT_SECURITY
    
    # 关系
    cve: Mapped["CVE"] = relationship(back_populates="references")


# ============================================
# 补丁相关模型
# ============================================

class Patch(Base):
    """补丁信息表"""
    __tablename__ = "patches"
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    cve_id: Mapped[str] = mapped_column(String(20), ForeignKey("cves.id"), index=True)
    commit_hash: Mapped[str] = mapped_column(String(40), index=True)
    commit_hash_short: Mapped[str] = mapped_column(String(12))
    subject: Mapped[str] = mapped_column(String(500))
    body: Mapped[Optional[str]] = mapped_column(Text)
    author: Mapped[str] = mapped_column(String(100))
    author_email: Mapped[Optional[str]] = mapped_column(String(100))
    author_date: Mapped[Optional[datetime]] = mapped_column(DateTime)
    committer: Mapped[Optional[str]] = mapped_column(String(100))
    commit_date: Mapped[Optional[datetime]] = mapped_column(DateTime)
    branches: Mapped[Optional[List[str]]] = mapped_column(JSON)  # 影响的内核分支
    backported_to: Mapped[Optional[List[str]]] = mapped_column(JSON)
    not_backported_to: Mapped[Optional[List[str]]] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )
    
    # 关系
    cve: Mapped["CVE"] = relationship(back_populates="patches")
    file_changes: Mapped[List["FileChange"]] = relationship(
        back_populates="patch", cascade="all, delete-orphan"
    )
    patch_statuses: Mapped[List["PatchStatus"]] = relationship(
        back_populates="patch", cascade="all, delete-orphan"
    )
    patch_history: Mapped[List["PatchHistory"]] = relationship(
        back_populates="patch", cascade="all, delete-orphan"
    )


class FileChange(Base):
    """文件变更表"""
    __tablename__ = "file_changes"
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    patch_id: Mapped[int] = mapped_column(Integer, ForeignKey("patches.id"), index=True)
    filename: Mapped[str] = mapped_column(String(500), index=True)
    status: Mapped[str] = mapped_column(String(20))  # added/modified/deleted/renamed
    additions: Mapped[int] = mapped_column(Integer, default=0)
    deletions: Mapped[int] = mapped_column(Integer, default=0)
    functions: Mapped[Optional[List[str]]] = mapped_column(JSON)  # 受影响的函数
    old_file_hash: Mapped[Optional[str]] = mapped_column(String(64))  # SHA256
    new_file_hash: Mapped[Optional[str]] = mapped_column(String(64))
    patch_content: Mapped[Optional[str]] = mapped_column(Text)  # diff 内容
    
    # 关系
    patch: Mapped["Patch"] = relationship(back_populates="file_changes")


class PatchStatus(Base):
    """补丁在目标代码中的状态"""
    __tablename__ = "patch_statuses"
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    cve_id: Mapped[str] = mapped_column(String(20), ForeignKey("cves.id"), index=True)
    patch_id: Mapped[int] = mapped_column(Integer, ForeignKey("patches.id"), index=True)
    target_version: Mapped[str] = mapped_column(String(50), index=True)
    target_path: Mapped[str] = mapped_column(String(500))
    status: Mapped[str] = mapped_column(String(20), index=True)  # PatchStatusEnum
    detection_method: Mapped[str] = mapped_column(String(50))
    matched_commit: Mapped[Optional[str]] = mapped_column(String(40))
    match_confidence: Mapped[float] = mapped_column(Float, index=True)
    expected_hash: Mapped[Optional[str]] = mapped_column(String(64))
    actual_hash: Mapped[Optional[str]] = mapped_column(String(64))
    diff_summary: Mapped[Optional[str]] = mapped_column(Text)
    checked_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    
    # 关系
    patch: Mapped["Patch"] = relationship(back_populates="patch_statuses")


class PatchHistory(Base):
    """补丁应用历史"""
    __tablename__ = "patch_history"
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    cve_id: Mapped[str] = mapped_column(String(20), ForeignKey("cves.id"), index=True)
    patch_id: Mapped[int] = mapped_column(Integer, ForeignKey("patches.id"), index=True)
    change_type: Mapped[str] = mapped_column(String(30), index=True)  # ChangeType
    commit_hash: Mapped[str] = mapped_column(String(40))
    commit_subject: Mapped[str] = mapped_column(String(500))
    author: Mapped[str] = mapped_column(String(100))
    commit_date: Mapped[datetime] = mapped_column(DateTime)
    parent_commit: Mapped[Optional[str]] = mapped_column(String(40))
    related_to: Mapped[Optional[str]] = mapped_column(String(40))
    description: Mapped[Optional[str]] = mapped_column(Text)
    files_changed: Mapped[Optional[List[str]]] = mapped_column(JSON)
    impact: Mapped[Optional[str]] = mapped_column(String(50))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    
    # 关系
    patch: Mapped["Patch"] = relationship(back_populates="patch_history")


# ============================================
# 版本配置模型
# ============================================

class AffectedConfig(Base):
    """受影响的内核版本配置"""
    __tablename__ = "affected_configs"
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    cve_id: Mapped[str] = mapped_column(String(20), ForeignKey("cves.id"), index=True)
    vendor: Mapped[str] = mapped_column(String(50), index=True)  # Linux/RedHat/Ubuntu
    product: Mapped[str] = mapped_column(String(100))
    version_start: Mapped[Optional[str]] = mapped_column(String(50))
    version_end: Mapped[Optional[str]] = mapped_column(String(50))
    version_exact: Mapped[Optional[str]] = mapped_column(String(50))
    cpe_match: Mapped[Optional[str]] = mapped_column(String(200))
    
    # 关系
    cve: Mapped["CVE"] = relationship(back_populates="affected_configs")


class KernelVersion(Base):
    """内核版本追踪"""
    __tablename__ = "kernel_versions"
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    version: Mapped[str] = mapped_column(String(50), unique=True, index=True)
    branch: Mapped[str] = mapped_column(String(50), index=True)
    release_date: Mapped[Optional[datetime]] = mapped_column(DateTime)
    eol_date: Mapped[Optional[datetime]] = mapped_column(DateTime)
    is_supported: Mapped[bool] = mapped_column(Boolean, default=True)
    source: Mapped[Optional[str]] = mapped_column(String(50))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )


# ============================================
# Kconfig 配置分析模型
# ============================================

class KconfigDependency(Base):
    """漏洞触发的 Kconfig 依赖"""
    __tablename__ = "kconfig_dependencies"
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    cve_id: Mapped[str] = mapped_column(String(20), ForeignKey("cves.id"), index=True)
    patch_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("patches.id"))
    config_name: Mapped[str] = mapped_column(String(100), index=True)  # CONFIG_XXX
    config_file: Mapped[str] = mapped_column(String(500))
    description: Mapped[Optional[str]] = mapped_column(Text)
    default_value: Mapped[Optional[str]] = mapped_column(String(50))
    depends_on: Mapped[Optional[List[str]]] = mapped_column(JSON)
    selects: Mapped[Optional[List[str]]] = mapped_column(JSON)
    implied_by: Mapped[Optional[List[str]]] = mapped_column(JSON)
    is_vulnerable: Mapped[bool] = mapped_column(Boolean, default=False)
    is_required: Mapped[bool] = mapped_column(Boolean, default=False)
    is_sufficient: Mapped[bool] = mapped_column(Boolean, default=False)
    subsystem: Mapped[Optional[str]] = mapped_column(String(100), index=True)
    source_files: Mapped[Optional[List[str]]] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )


class KconfigAnalysis(Base):
    """针对特定内核版本的配置分析结果"""
    __tablename__ = "kconfig_analyses"
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    cve_id: Mapped[str] = mapped_column(String(20), ForeignKey("cves.id"), index=True)
    kernel_version: Mapped[str] = mapped_column(String(50), index=True)
    config_status: Mapped[str] = mapped_column(String(30))  # ConfigStatus
    required_configs: Mapped[Optional[List[str]]] = mapped_column(JSON)
    active_configs: Mapped[Optional[List[str]]] = mapped_column(JSON)
    missing_configs: Mapped[Optional[List[str]]] = mapped_column(JSON)
    risk_level: Mapped[str] = mapped_column(String(20))  # RiskLevel
    exploitable: Mapped[bool] = mapped_column(Boolean, default=False)
    exploit_conditions: Mapped[Optional[str]] = mapped_column(Text)
    mitigation_configs: Mapped[Optional[List[str]]] = mapped_column(JSON)
    suggested_config: Mapped[Optional[str]] = mapped_column(Text)
    analyzed_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class KconfigRule(Base):
    """Kconfig 规则库条目"""
    __tablename__ = "kconfig_rules"
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    cve_id: Mapped[str] = mapped_column(String(20), ForeignKey("cves.id"), index=True)
    rule_version: Mapped[str] = mapped_column(String(20))
    required: Mapped[Optional[dict]] = mapped_column(JSON)  # 必需配置条件
    vulnerable_if: Mapped[Optional[dict]] = mapped_column(JSON)  # 触发条件
    mitigation: Mapped[Optional[dict]] = mapped_column(JSON)  # 缓解措施
    source: Mapped[str] = mapped_column(String(50))  # community/manual/auto
    author: Mapped[Optional[str]] = mapped_column(String(100))
    verified: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )


# ============================================
# 报告和同步模型
# ============================================

class Report(Base):
    """报告记录"""
    __tablename__ = "reports"
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    type: Mapped[str] = mapped_column(String(50), index=True)  # cve/summary/audit
    format: Mapped[str] = mapped_column(String(20))  # json/markdown/html
    cve_count: Mapped[int] = mapped_column(Integer, default=0)
    file_path: Mapped[str] = mapped_column(String(500))
    query_params: Mapped[Optional[dict]] = mapped_column(JSON)
    generated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class SyncLog(Base):
    """数据同步日志"""
    __tablename__ = "sync_logs"
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source: Mapped[str] = mapped_column(String(50), index=True)  # NVD/CVE_ORG
    status: Mapped[str] = mapped_column(String(20))  # SUCCESS/PARTIAL/FAILED
    start_time: Mapped[datetime] = mapped_column(DateTime)
    end_time: Mapped[Optional[datetime]] = mapped_column(DateTime)
    total_count: Mapped[int] = mapped_column(Integer, default=0)
    new_count: Mapped[int] = mapped_column(Integer, default=0)
    update_count: Mapped[int] = mapped_column(Integer, default=0)
    error_count: Mapped[int] = mapped_column(Integer, default=0)
    errors: Mapped[Optional[List[str]]] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
