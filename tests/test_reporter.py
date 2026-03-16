"""
报告系统测试
"""

import json
import pytest
from datetime import datetime

from cve_analyzer.reporter.models import (
    CVEReport, SummaryReport, ReportFormat,
    PatchInfo, VersionImpactInfo, KconfigInfo,
    PatchHistoryInfo, DetectionStatusInfo
)
from cve_analyzer.reporter.base import JSONReportGenerator
from cve_analyzer.reporter.markdown import MarkdownReportGenerator
from cve_analyzer.reporter.html import HTMLReportGenerator


class TestReportModels:
    """报告模型测试"""
    
    def test_cve_report_creation(self):
        """测试创建 CVE 报告"""
        report = CVEReport(
            cve_id="CVE-2024-1234",
            description="Test vulnerability",
            severity="HIGH",
            cvss_score=7.5,
        )
        
        assert report.cve_id == "CVE-2024-1234"
        assert report.severity == "HIGH"
        assert report.cvss_score == 7.5
        assert report.generated_at is not None
    
    def test_patch_info_creation(self):
        """测试补丁信息"""
        patch = PatchInfo(
            commit_hash="abc123def456",
            commit_hash_short="abc123",
            subject="Fix vulnerability",
            author="John Doe",
            files_changed=["file1.c", "file2.c"],
        )
        
        assert patch.commit_hash == "abc123def456"
        assert len(patch.files_changed) == 2
    
    def test_summary_report_creation(self):
        """测试摘要报告"""
        report = SummaryReport(
            total_cves=10,
            by_severity={"HIGH": 3, "MEDIUM": 5, "LOW": 2},
            high_risk_cves=["CVE-2024-1234"],
        )
        
        assert report.total_cves == 10
        assert report.by_severity["HIGH"] == 3


class TestJSONReportGenerator:
    """JSON 报告生成器测试"""
    
    def test_generate_single_report(self, temp_dir):
        """测试生成单个报告"""
        generator = JSONReportGenerator(output_dir=str(temp_dir))
        
        report = CVEReport(
            cve_id="CVE-2024-1234",
            description="Test",
            severity="HIGH",
        )
        
        output_path = generator.generate(report)
        
        assert output_path.endswith(".json")
        assert Path(output_path).exists()
        
        # 验证内容
        with open(output_path) as f:
            data = json.load(f)
            assert data["cve_id"] == "CVE-2024-1234"
            assert data["severity"] == "HIGH"
    
    def test_generate_summary_report(self, temp_dir):
        """测试生成摘要报告"""
        generator = JSONReportGenerator(output_dir=str(temp_dir))
        
        report = SummaryReport(
            total_cves=5,
            by_severity={"CRITICAL": 1, "HIGH": 4},
        )
        
        output_path = generator.generate_summary(report)
        
        assert "summary" in output_path
        with open(output_path) as f:
            data = json.load(f)
            assert data["total_cves"] == 5


class TestMarkdownReportGenerator:
    """Markdown 报告生成器测试"""
    
    def test_generate_markdown_report(self, temp_dir):
        """测试生成 Markdown 报告"""
        generator = MarkdownReportGenerator(output_dir=str(temp_dir))
        
        report = CVEReport(
            cve_id="CVE-2024-1234",
            description="Test vulnerability",
            severity="HIGH",
            patches=[
                PatchInfo(
                    commit_hash="abc123",
                    subject="Fix bug",
                    author="John Doe",
                    files_changed=["file.c"],
                )
            ],
        )
        
        output_path = generator.generate(report)
        
        assert output_path.endswith(".md")
        assert Path(output_path).exists()
        
        # 验证内容
        content = Path(output_path).read_text()
        assert "CVE-2024-1234" in content
        assert "Fix bug" in content
        assert "file.c" in content


class TestHTMLReportGenerator:
    """HTML 报告生成器测试"""
    
    def test_generate_html_report(self, temp_dir):
        """测试生成 HTML 报告"""
        generator = HTMLReportGenerator(output_dir=str(temp_dir))
        
        report = CVEReport(
            cve_id="CVE-2024-1234",
            description="Test",
            severity="MEDIUM",
        )
        
        output_path = generator.generate(report)
        
        assert output_path.endswith(".html")
        assert Path(output_path).exists()
        
        # 验证 HTML 结构
        content = Path(output_path).read_text()
        assert "<html" in content
        assert "CVE-2024-1234" in content
        assert "</html>" in content


# 导入 Path
from pathlib import Path
