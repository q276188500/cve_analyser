"""
报告系统 - CVE 分析报告生成

支持格式:
- JSON: 机器可读，完整数据
- Markdown: 人工可读，适合文档
- HTML: 网页展示，带样式
"""

from cve_analyzer.reporter.base import ReportGenerator, JSONReportGenerator
from cve_analyzer.reporter.markdown import MarkdownReportGenerator
from cve_analyzer.reporter.html import HTMLReportGenerator
from cve_analyzer.reporter.models import (
    CVEReport, SummaryReport, ReportFormat,
    PatchInfo, VersionImpactInfo, KconfigInfo,
    PatchHistoryInfo, DetectionStatusInfo
)

__all__ = [
    'ReportGenerator',
    'JSONReportGenerator',
    'MarkdownReportGenerator',
    'HTMLReportGenerator',
    'CVEReport',
    'SummaryReport',
    'ReportFormat',
    'PatchInfo',
    'VersionImpactInfo',
    'KconfigInfo',
    'PatchHistoryInfo',
    'DetectionStatusInfo',
]
