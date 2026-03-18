"""
报告生成器基类
"""

from abc import ABC, abstractmethod
from typing import List, Optional
from pathlib import Path
import json

from cve_analyzer.reporter.models import CVEReport, SummaryReport, ReportFormat


class ReportGenerator(ABC):
    """报告生成器基类"""
    
    def __init__(self, output_dir: Optional[str] = None):
        self.output_dir = Path(output_dir) if output_dir else Path.cwd()
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    @abstractmethod
    def generate(self, report: CVEReport, filename: Optional[str] = None) -> str:
        """
        生成单个 CVE 报告
        
        Args:
            report: CVE 报告数据
            filename: 输出文件名，None 则自动生成
            
        Returns:
            生成的文件路径
        """
        pass
    
    @abstractmethod
    def generate_summary(self, report: SummaryReport, filename: Optional[str] = None) -> str:
        """
        生成摘要报告
        
        Args:
            report: 摘要报告数据
            filename: 输出文件名
            
        Returns:
            生成的文件路径
        """
        pass
    
    def _get_output_path(self, cve_id: str, extension: str) -> Path:
        """生成输出文件路径"""
        safe_id = cve_id.replace("-", "_").lower()
        return self.output_dir / f"{safe_id}_report.{extension}"


class JSONReportGenerator(ReportGenerator):
    """JSON 格式报告生成器"""
    
    def generate(self, report: CVEReport, filename: Optional[str] = None) -> str:
        """生成 JSON 报告"""
        if filename is None:
            output_path = self._get_output_path(report.cve_id, "json")
        else:
            output_path = self.output_dir / filename
        
        # 转换为字典
        data = self._report_to_dict(report)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        return str(output_path)
    
    def generate_summary(self, report: SummaryReport, filename: Optional[str] = None) -> str:
        """生成 JSON 摘要报告"""
        if filename is None:
            filename = "summary_report.json"
        output_path = self.output_dir / filename
        
        data = {
            "generated_at": report.generated_at,
            "total_cves": report.total_cves,
            "by_severity": report.by_severity,
            "by_status": report.by_status,
            "high_risk_cves": report.high_risk_cves,
            "cves": [self._report_to_dict(r) for r in report.cves]
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        return str(output_path)
    
    def _report_to_dict(self, report: CVEReport) -> dict:
        """将报告对象转换为字典"""
        return {
            "cve_id": report.cve_id,
            "description": report.description,
            "severity": report.severity,
            "cvss_score": report.cvss_score,
            "published_date": report.published_date,
            "last_modified": report.last_modified,
            "patches": [
                {
                    "commit_hash": p.commit_hash,
                    "commit_hash_short": p.commit_hash_short,
                    "subject": p.subject,
                    "author": p.author,
                    "author_date": p.author_date,
                    "files_changed": p.files_changed,
                    "functions_changed": p.functions_changed,
                    "branches": p.branches,
                    "backported_to": p.backported_to,
                    "not_backported_to": p.not_backported_to,
                }
                for p in report.patches
            ],
            "version_impact": {
                "mainline_affected": report.version_impact.mainline_affected if report.version_impact else [],
                "stable_affected": report.version_impact.stable_affected if report.version_impact else [],
                "longterm_affected": report.version_impact.longterm_affected if report.version_impact else [],
                "backported_to": report.version_impact.backported_to if report.version_impact else [],
                "not_backported_to": report.version_impact.not_backported_to if report.version_impact else [],
            } if report.version_impact else None,
            "kconfig_analysis": {
                "trigger_configs": report.kconfig_analysis.trigger_configs if report.kconfig_analysis else [],
                "dependency_chain": report.kconfig_analysis.dependency_chain if report.kconfig_analysis else [],
                "risk_level": report.kconfig_analysis.risk_level if report.kconfig_analysis else "unknown",
                "is_vulnerable": report.kconfig_analysis.is_vulnerable if report.kconfig_analysis else False,
            } if report.kconfig_analysis else None,
            "patch_history": [
                {
                    "change_type": h.change_type,
                    "commit_hash": h.commit_hash,
                    "commit_subject": h.commit_subject,
                    "author": h.author,
                    "commit_date": h.commit_date,
                    "risk_level": h.risk_level,
                }
                for h in report.patch_history
            ],
            "detection_status": [
                {
                    "target_version": d.target_version,
                    "status": d.status,
                    "detection_method": d.detection_method,
                    "confidence": d.confidence,
                    "checked_at": d.checked_at,
                }
                for d in report.detection_status
            ],
            "generated_at": report.generated_at,
            "report_version": report.report_version,
        }
