"""
报告系统数据模型
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Dict, Any
from enum import Enum


class ReportFormat(Enum):
    """报告格式类型"""
    JSON = "json"
    MARKDOWN = "markdown"
    HTML = "html"


@dataclass
class PatchInfo:
    """补丁信息"""
    commit_hash: str
    commit_hash_short: Optional[str] = None
    subject: str = ""
    author: str = ""
    author_date: Optional[str] = None
    files_changed: List[str] = field(default_factory=list)
    functions_changed: List[str] = field(default_factory=list)
    branches: List[str] = field(default_factory=list)
    backported_to: List[str] = field(default_factory=list)
    not_backported_to: List[str] = field(default_factory=list)


@dataclass
class VersionImpactInfo:
    """版本影响信息"""
    mainline_affected: List[str] = field(default_factory=list)
    stable_affected: List[str] = field(default_factory=list)
    longterm_affected: List[str] = field(default_factory=list)
    backported_to: List[str] = field(default_factory=list)
    not_backported_to: List[str] = field(default_factory=list)


@dataclass
class KconfigInfo:
    """Kconfig 分析信息"""
    trigger_configs: List[str] = field(default_factory=list)
    dependency_chain: List[str] = field(default_factory=list)
    risk_level: str = "unknown"  # high/medium/low/unknown
    is_vulnerable: bool = False


@dataclass
class PatchHistoryInfo:
    """补丁历史信息"""
    change_type: str = ""  # fixup/revert/refactor/backport/conflict_fix/follow_up
    commit_hash: str = ""
    commit_subject: str = ""
    author: str = ""
    commit_date: Optional[str] = None
    risk_level: str = "low"


@dataclass
class DetectionStatusInfo:
    """检测状态信息"""
    target_version: str = ""
    status: str = "unknown"  # applied/pending/unknown/not_affected
    detection_method: Optional[str] = None
    confidence: float = 0.0
    checked_at: Optional[str] = None


@dataclass
class CVEReport:
    """单个 CVE 的完整报告"""
    cve_id: str
    description: str = ""
    severity: str = "unknown"
    cvss_score: Optional[float] = None
    published_date: Optional[str] = None
    last_modified: Optional[str] = None
    
    # 分析结果
    patches: List[PatchInfo] = field(default_factory=list)
    version_impact: Optional[VersionImpactInfo] = None
    kconfig_analysis: Optional[KconfigInfo] = None
    patch_history: List[PatchHistoryInfo] = field(default_factory=list)
    detection_status: List[DetectionStatusInfo] = field(default_factory=list)
    
    # 元数据
    generated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    report_version: str = "1.0"


@dataclass
class SummaryReport:
    """批量 CVE 摘要报告"""
    total_cves: int = 0
    by_severity: Dict[str, int] = field(default_factory=dict)
    by_status: Dict[str, int] = field(default_factory=dict)
    high_risk_cves: List[str] = field(default_factory=list)
    cves: List[CVEReport] = field(default_factory=list)
    generated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
