"""
数据模型测试
"""

from datetime import datetime

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from cve_analyzer.core.models import (
    CVE,
    CVEReference,
    Patch,
    FileChange,
    PatchStatus,
    PatchHistory,
    AffectedConfig,
    KernelVersion,
    KconfigDependency,
    KconfigAnalysis,
    KconfigRule,
    Report,
    SyncLog,
    Severity,
    PatchStatusEnum,
    RiskLevel,
    Base,
)


class TestCVE:
    """CVE 模型测试"""
    
    def test_create_cve(self, db_session):
        """测试创建 CVE"""
        cve = CVE(
            id="CVE-2024-1234",
            description="Test vulnerability",
            severity=Severity.HIGH.value,
            cvss_score=7.5,
        )
        
        db_session.add(cve)
        db_session.commit()
        
        # 查询验证
        result = db_session.query(CVE).filter_by(id="CVE-2024-1234").first()
        assert result is not None
        assert result.description == "Test vulnerability"
        assert result.severity == "HIGH"
        assert result.cvss_score == 7.5
    
    def test_cve_with_references(self, db_session):
        """测试 CVE 与参考链接的关系"""
        cve = CVE(id="CVE-2024-1234", description="Test")
        ref = CVEReference(
            cve_id="CVE-2024-1234",
            url="https://example.com/cve-2024-1234",
            type="PATCH",
            source="NVD",
        )
        
        db_session.add(cve)
        db_session.add(ref)
        db_session.commit()
        
        result = db_session.query(CVE).filter_by(id="CVE-2024-1234").first()
        assert len(result.references) == 1
        assert result.references[0].url == "https://example.com/cve-2024-1234"
    
    def test_cve_timestamps(self, db_session):
        """测试时间戳自动设置"""
        cve = CVE(id="CVE-2024-1234", description="Test")
        
        db_session.add(cve)
        db_session.commit()
        
        assert cve.created_at is not None
        assert cve.updated_at is not None
        assert isinstance(cve.created_at, datetime)


class TestPatch:
    """Patch 模型测试"""
    
    def test_create_patch(self, db_session):
        """测试创建补丁"""
        # 先创建 CVE
        cve = CVE(id="CVE-2024-1234", description="Test")
        db_session.add(cve)
        
        patch = Patch(
            cve_id="CVE-2024-1234",
            commit_hash="abc123def45678901234567890abcdef12345678",
            commit_hash_short="abc123def456",
            subject="Fix vulnerability",
            author="John Doe",
        )
        
        db_session.add(patch)
        db_session.commit()
        
        result = db_session.query(Patch).first()
        assert result is not None
        assert result.commit_hash == "abc123def45678901234567890abcdef12345678"
        assert result.cve_id == "CVE-2024-1234"
    
    def test_patch_with_file_changes(self, db_session):
        """测试补丁与文件变更的关系"""
        cve = CVE(id="CVE-2024-1234", description="Test")
        db_session.add(cve)
        
        patch = Patch(
            cve_id="CVE-2024-1234",
            commit_hash="abc123",
            subject="Fix",
            author="Test",
        )
        db_session.add(patch)
        db_session.flush()  # 获取 patch.id
        
        file_change = FileChange(
            patch_id=patch.id,
            filename="net/core/sock.c",
            status="modified",
            additions=10,
            deletions=5,
            functions=["sock_init", "sock_bind"],
        )
        
        db_session.add(file_change)
        db_session.commit()
        
        result = db_session.query(Patch).first()
        assert len(result.file_changes) == 1
        assert result.file_changes[0].filename == "net/core/sock.c"
    
    def test_patch_branches_json(self, db_session):
        """测试分支 JSON 字段"""
        cve = CVE(id="CVE-2024-1234", description="Test")
        db_session.add(cve)
        
        patch = Patch(
            cve_id="CVE-2024-1234",
            commit_hash="abc123",
            subject="Fix",
            author="Test",
            branches=["mainline", "stable"],
            backported_to=["v5.15", "v6.1"],
        )
        
        db_session.add(patch)
        db_session.commit()
        
        result = db_session.query(Patch).first()
        assert "mainline" in result.branches
        assert "v5.15" in result.backported_to


class TestPatchStatus:
    """PatchStatus 模型测试"""
    
    def test_create_patch_status(self, db_session):
        """测试创建补丁状态"""
        cve = CVE(id="CVE-2024-1234", description="Test")
        db_session.add(cve)
        
        patch = Patch(
            cve_id="CVE-2024-1234",
            commit_hash="abc123",
            subject="Fix",
            author="Test",
        )
        db_session.add(patch)
        db_session.flush()
        
        status = PatchStatus(
            cve_id="CVE-2024-1234",
            patch_id=patch.id,
            target_version="5.15.100",
            target_path="/path/to/kernel",
            status=PatchStatusEnum.APPLIED.value,
            detection_method="commit_hash",
            match_confidence=1.0,
        )
        
        db_session.add(status)
        db_session.commit()
        
        result = db_session.query(PatchStatus).first()
        assert result.status == "APPLIED"
        assert result.match_confidence == 1.0
        assert result.target_version == "5.15.100"


class TestPatchHistory:
    """PatchHistory 模型测试"""
    
    def test_create_patch_history(self, db_session):
        """测试创建补丁历史"""
        cve = CVE(id="CVE-2024-1234", description="Test")
        db_session.add(cve)
        
        patch = Patch(
            cve_id="CVE-2024-1234",
            commit_hash="abc123",
            subject="Fix",
            author="Test",
        )
        db_session.add(patch)
        db_session.flush()
        
        history = PatchHistory(
            cve_id="CVE-2024-1234",
            patch_id=patch.id,
            change_type="FIXUP",
            commit_hash="def456",
            commit_subject="Fixup for previous patch",
            author="Jane Doe",
            commit_date=datetime.utcnow(),
            related_to="abc123",
        )
        
        db_session.add(history)
        db_session.commit()
        
        result = db_session.query(PatchHistory).first()
        assert result.change_type == "FIXUP"
        assert result.related_to == "abc123"


class TestKconfigModels:
    """Kconfig 相关模型测试"""
    
    def test_create_kconfig_dependency(self, db_session):
        """测试创建 Kconfig 依赖"""
        cve = CVE(id="CVE-2024-1234", description="Test")
        db_session.add(cve)
        
        dep = KconfigDependency(
            cve_id="CVE-2024-1234",
            config_name="CONFIG_NETFILTER",
            config_file="net/Kconfig",
            description="Netfilter support",
            is_vulnerable=True,
            is_required=True,
            subsystem="networking",
            source_files=["net/core/netfilter.c"],
        )
        
        db_session.add(dep)
        db_session.commit()
        
        result = db_session.query(KconfigDependency).first()
        assert result.config_name == "CONFIG_NETFILTER"
        assert result.is_vulnerable is True
        assert "networking" in result.subsystem
    
    def test_create_kconfig_analysis(self, db_session):
        """测试创建 Kconfig 分析结果"""
        cve = CVE(id="CVE-2024-1234", description="Test")
        db_session.add(cve)
        
        analysis = KconfigAnalysis(
            cve_id="CVE-2024-1234",
            kernel_version="5.15.100",
            config_status="VULNERABLE",
            required_configs=["CONFIG_NETFILTER", "CONFIG_NF_TABLES"],
            active_configs=["CONFIG_NETFILTER"],
            missing_configs=["CONFIG_NF_TABLES"],
            risk_level=RiskLevel.HIGH.value,
            exploitable=True,
        )
        
        db_session.add(analysis)
        db_session.commit()
        
        result = db_session.query(KconfigAnalysis).first()
        assert result.risk_level == "HIGH"
        assert result.exploitable is True
        assert "CONFIG_NETFILTER" in result.active_configs
    
    def test_create_kconfig_rule(self, db_session):
        """测试创建 Kconfig 规则"""
        cve = CVE(id="CVE-2024-1234", description="Test")
        db_session.add(cve)
        
        rule = KconfigRule(
            cve_id="CVE-2024-1234",
            rule_version="1.0",
            required={"configs": ["CONFIG_NETFILTER"]},
            vulnerable_if={"all": ["CONFIG_NETFILTER=y"]},
            mitigation={"disable": ["CONFIG_NF_TABLES"]},
            source="community",
            verified=True,
        )
        
        db_session.add(rule)
        db_session.commit()
        
        result = db_session.query(KconfigRule).first()
        assert result.verified is True
        assert result.source == "community"


class TestKernelVersion:
    """KernelVersion 模型测试"""
    
    def test_create_kernel_version(self, db_session):
        """测试创建内核版本"""
        version = KernelVersion(
            version="6.6.1",
            branch="mainline",
            is_supported=True,
        )
        
        db_session.add(version)
        db_session.commit()
        
        result = db_session.query(KernelVersion).first()
        assert result.version == "6.6.1"
        assert result.branch == "mainline"
        assert result.is_supported is True
    
    def test_unique_version_constraint(self, db_session):
        """测试版本唯一约束"""
        version1 = KernelVersion(version="6.6.1", branch="mainline")
        version2 = KernelVersion(version="6.6.1", branch="stable")
        
        db_session.add(version1)
        db_session.commit()
        
        db_session.add(version2)
        with pytest.raises(Exception):  # 应该违反唯一约束
            db_session.commit()


class TestAffectedConfig:
    """AffectedConfig 模型测试"""
    
    def test_create_affected_config(self, db_session):
        """测试创建受影响配置"""
        cve = CVE(id="CVE-2024-1234", description="Test")
        db_session.add(cve)
        
        config = AffectedConfig(
            cve_id="CVE-2024-1234",
            vendor="Linux",
            product="Linux Kernel",
            version_start="5.10",
            version_end="6.6",
            cpe_match="cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*",
        )
        
        db_session.add(config)
        db_session.commit()
        
        result = db_session.query(AffectedConfig).first()
        assert result.vendor == "Linux"
        assert result.version_start == "5.10"


class TestReport:
    """Report 模型测试"""
    
    def test_create_report(self, db_session):
        """测试创建报告"""
        report = Report(
            name="CVE Analysis Report 2024",
            type="cve",
            format="json",
            cve_count=100,
            file_path="/reports/report.json",
        )
        
        db_session.add(report)
        db_session.commit()
        
        result = db_session.query(Report).first()
        assert result.name == "CVE Analysis Report 2024"
        assert result.cve_count == 100


class TestSyncLog:
    """SyncLog 模型测试"""
    
    def test_create_sync_log(self, db_session):
        """测试创建同步日志"""
        log = SyncLog(
            source="NVD",
            status="SUCCESS",
            start_time=datetime.utcnow(),
            total_count=1000,
            new_count=50,
            update_count=30,
            error_count=0,
        )
        
        db_session.add(log)
        db_session.commit()
        
        result = db_session.query(SyncLog).first()
        assert result.source == "NVD"
        assert result.status == "SUCCESS"
        assert result.new_count == 50
