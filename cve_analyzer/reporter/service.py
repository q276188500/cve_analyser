"""
报告服务 - 从数据库数据生成报告
"""

from typing import List, Optional
from datetime import datetime

from sqlalchemy.orm import Session

from cve_analyzer.core.database import Database
from cve_analyzer.core.models import CVE, Patch, PatchStatus, KconfigAnalysis, PatchHistory
from cve_analyzer.reporter.models import (
    CVEReport, SummaryReport, ReportFormat,
    PatchInfo, VersionImpactInfo, KconfigInfo,
    PatchHistoryInfo as HistoryInfo, DetectionStatusInfo
)


class ReportService:
    """报告服务 - 协调数据获取和报告生成"""
    
    def __init__(self, db: Optional[Database] = None):
        self.db = db or Database()
    
    def generate_cve_report(self, cve_id: str) -> Optional[CVEReport]:
        """
        生成单个 CVE 的完整报告
        
        Args:
            cve_id: CVE ID
            
        Returns:
            CVEReport 对象，如果 CVE 不存在则返回 None
        """
        with self.db.session() as session:
            cve = session.query(CVE).filter_by(id=cve_id).first()
            if not cve:
                return None
            
            # 构建报告
            report = CVEReport(
                cve_id=cve.id,
                description=cve.description or "",
                severity=cve.severity or "unknown",
                cvss_score=cve.cvss_score,
                published_date=cve.published_date.isoformat() if cve.published_date else None,
                last_modified=cve.last_modified.isoformat() if cve.last_modified else None,
            )
            
            # 添加补丁信息
            for patch in cve.patches:
                patch_info = PatchInfo(
                    commit_hash=patch.commit_hash,
                    commit_hash_short=patch.commit_hash_short,
                    subject=patch.subject,
                    author=patch.author,
                    author_date=patch.author_date.isoformat() if patch.author_date else None,
                    files_changed=[fc.filename for fc in patch.file_changes],
                    branches=patch.branches or [],
                    backported_to=patch.backported_to or [],
                    not_backported_to=patch.not_backported_to or [],
                )
                report.patches.append(patch_info)
            
            # 添加 Kconfig 分析
            if cve.kconfig_analyses:
                kconfig = cve.kconfig_analyses[0]  # 取第一个
                report.kconfig_analysis = KconfigInfo(
                    trigger_configs=kconfig.trigger_configs or [],
                    dependency_chain=kconfig.dependency_chain or [],
                    risk_level=kconfig.risk_level or "unknown",
                    is_vulnerable=kconfig.is_vulnerable or False,
                )
            
            # 添加补丁历史
            for history in cve.patch_history:
                history_info = HistoryInfo(
                    change_type=history.change_type or "",
                    commit_hash=history.commit_hash or "",
                    commit_subject=history.commit_subject or "",
                    author=history.author or "",
                    commit_date=history.commit_date.isoformat() if history.commit_date else None,
                    risk_level=history.risk_level or "low",
                )
                report.patch_history.append(history_info)
            
            # 添加检测状态
            for status in cve.patch_statuses:
                status_info = DetectionStatusInfo(
                    target_version=status.target_version,
                    status=status.status or "unknown",
                    detection_method=status.detection_method,
                    confidence=status.match_confidence or 0.0,
                    checked_at=status.checked_at.isoformat() if status.checked_at else None,
                )
                report.detection_status.append(status_info)
            
            return report
    
    def generate_summary_report(self, cve_ids: Optional[List[str]] = None) -> SummaryReport:
        """
        生成摘要报告
        
        Args:
            cve_ids: CVE ID 列表，None 则包含所有 CVE
            
        Returns:
            SummaryReport 对象
        """
        with self.db.session() as session:
            query = session.query(CVE)
            if cve_ids:
                query = query.filter(CVE.id.in_(cve_ids))
            
            cves = query.all()
            
            report = SummaryReport(
                total_cves=len(cves),
                generated_at=datetime.utcnow().isoformat()
            )
            
            # 按严重程度统计
            for cve in cves:
                severity = cve.severity or "unknown"
                report.by_severity[severity] = report.by_severity.get(severity, 0) + 1
                
                # 高风险 CVE
                if severity in ["critical", "high"]:
                    report.high_risk_cves.append(cve.id)
                
                # 生成详细报告
                cve_report = self._cve_to_report(cve)
                report.cves.append(cve_report)
            
            return report
    
    def _cve_to_report(self, cve: CVE) -> CVEReport:
        """将 CVE 模型转换为报告模型"""
        return CVEReport(
            cve_id=cve.id,
            description=cve.description or "",
            severity=cve.severity or "unknown",
            cvss_score=cve.cvss_score,
            published_date=cve.published_date.isoformat() if cve.published_date else None,
            last_modified=cve.last_modified.isoformat() if cve.last_modified else None,
        )
    
    def list_available_cves(self, severity: Optional[str] = None) -> List[str]:
        """
        列出可用的 CVE ID
        
        Args:
            severity: 按严重程度过滤
            
        Returns:
            CVE ID 列表
        """
        with self.db.session() as session:
            query = session.query(CVE.id)
            if severity:
                query = query.filter_by(severity=severity)
            return [id for (id,) in query.all()]
