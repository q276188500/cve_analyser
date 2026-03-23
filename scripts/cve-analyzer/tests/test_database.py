"""
数据库操作测试
"""

from datetime import datetime

import pytest
from sqlalchemy.orm import Session

from cve_analyzer.core.database import (
    Database,
    CVERepository,
    PatchRepository,
    PatchStatusRepository,
    KconfigRepository,
)
from cve_analyzer.core.models import (
    CVE,
    Patch,
    PatchStatus,
    KconfigRule,
    KconfigAnalysis,
    CVEReference,
    FileChange,
)


class TestDatabase:
    """数据库基础操作测试"""
    
    def test_create_tables(self, temp_dir):
        """测试创建表"""
        db_path = temp_dir / "test.db"
        db = Database(str(db_path))
        db.create_tables()
        
        # 验证数据库文件存在
        assert db_path.exists()
        db.close()
    
    def test_session_context_manager(self, test_db):
        """测试会话上下文管理器"""
        with test_db.session() as session:
            cve = CVE(id="CVE-2024-TEST", description="Test")
            session.add(cve)
        
        # 会话应该已提交
        with test_db.session() as session:
            result = session.query(CVE).filter_by(id="CVE-2024-TEST").first()
            assert result is not None
    
    def test_session_rollback_on_error(self, test_db):
        """测试错误时回滚"""
        try:
            with test_db.session() as session:
                cve = CVE(id="CVE-2024-ROLLBACK", description="Test")
                session.add(cve)
                raise ValueError("Test error")
        except ValueError:
            pass
        
        # 数据应该被回滚
        with test_db.session() as session:
            result = session.query(CVE).filter_by(id="CVE-2024-ROLLBACK").first()
            assert result is None


class TestCVERepository:
    """CVE 仓库测试"""
    
    @pytest.fixture
    def repo(self, db_session):
        return CVERepository(db_session)
    
    def test_create_cve(self, repo, db_session):
        """测试创建 CVE"""
        cve = CVE(id="CVE-2024-1234", description="Test", severity="HIGH")
        result = repo.create(cve)
        
        assert result.id == "CVE-2024-1234"
        
        # 验证数据库中有数据
        saved = db_session.query(CVE).filter_by(id="CVE-2024-1234").first()
        assert saved is not None
        assert saved.severity == "HIGH"
    
    def test_get_by_id(self, repo):
        """测试根据 ID 获取 CVE"""
        cve = CVE(id="CVE-2024-GET", description="Test")
        repo.create(cve)
        
        result = repo.get_by_id("CVE-2024-GET")
        assert result is not None
        assert result.description == "Test"
    
    def test_get_by_id_not_found(self, repo):
        """测试获取不存在的 CVE"""
        result = repo.get_by_id("CVE-NOT-EXIST")
        assert result is None
    
    def test_update_cve(self, repo):
        """测试更新 CVE"""
        cve = CVE(id="CVE-2024-UPDATE", description="Old description")
        repo.create(cve)
        
        cve.description = "New description"
        cve.cvss_score = 7.5
        repo.update(cve)
        
        result = repo.get_by_id("CVE-2024-UPDATE")
        assert result.description == "New description"
        assert result.cvss_score == 7.5
    
    def test_create_or_update_new(self, repo):
        """测试 create_or_update 创建新记录"""
        cve = CVE(id="CVE-2024-NEW", description="New")
        result = repo.create_or_update(cve)
        
        assert result.id == "CVE-2024-NEW"
    
    def test_create_or_update_existing(self, repo):
        """测试 create_or_update 更新现有记录"""
        # 先创建
        cve = CVE(id="CVE-2024-EXISTING", description="Original")
        repo.create(cve)
        
        # 更新
        cve.description = "Updated"
        cve.severity = "CRITICAL"
        result = repo.create_or_update(cve)
        
        assert result.description == "Updated"
        assert result.severity == "CRITICAL"
    
    def test_list_all_with_pagination(self, repo):
        """测试分页查询"""
        # 创建多个 CVE
        for i in range(10):
            cve = CVE(
                id=f"CVE-2024-{i:04d}",
                description=f"Test {i}",
                severity="HIGH" if i % 2 == 0 else "MEDIUM",
                published_date=datetime(2024, 1, i + 1) if i < 28 else None,
            )
            repo.create(cve)
        
        # 测试分页
        cves, total = repo.list_all(limit=5, offset=0)
        assert len(cves) == 5
        assert total == 10
        
        # 测试第二页
        cves, _ = repo.list_all(limit=5, offset=5)
        assert len(cves) == 5
    
    def test_list_all_with_severity_filter(self, repo):
        """测试按严重程度筛选"""
        repo.create(CVE(id="CVE-HIGH", description="Test", severity="HIGH"))
        repo.create(CVE(id="CVE-LOW", description="Test", severity="LOW"))
        
        cves, total = repo.list_all(severity="HIGH")
        assert total == 1
        assert cves[0].id == "CVE-HIGH"
    
    def test_list_all_with_keyword_filter(self, repo):
        """测试按关键词筛选"""
        repo.create(CVE(id="CVE-TEST-1", description="Linux kernel bug"))
        repo.create(CVE(id="CVE-TEST-2", description="Network issue"))
        
        cves, total = repo.list_all(keyword="Linux")
        assert total == 1
        assert cves[0].id == "CVE-TEST-1"


class TestPatchRepository:
    """Patch 仓库测试"""
    
    @pytest.fixture
    def repo(self, db_session):
        return PatchRepository(db_session)
    
    @pytest.fixture
    def sample_cve(self, db_session):
        cve = CVE(id="CVE-2024-PATCH", description="Test")
        db_session.add(cve)
        db_session.flush()
        return cve
    
    def test_create_patch(self, repo, db_session, sample_cve):
        """测试创建补丁"""
        patch = Patch(
            cve_id=sample_cve.id,
            commit_hash="abc123def45678901234567890abcdef12345678",
            subject="Fix bug",
            author="Test",
        )
        result = repo.create(patch)
        
        assert result.commit_hash == "abc123def45678901234567890abcdef12345678"
    
    def test_get_by_commit(self, repo, sample_cve):
        """测试根据 commit hash 获取补丁"""
        patch = Patch(
            cve_id=sample_cve.id,
            commit_hash="abc123def45678901234567890abcdef12345678",
            commit_hash_short="abc123def456",
            subject="Fix",
            author="Test",
        )
        repo.create(patch)
        
        # 用完整 hash 查询
        result = repo.get_by_commit("abc123def45678901234567890abcdef12345678")
        assert result is not None
        
        # 用短 hash 查询
        result = repo.get_by_commit("abc123def456")
        assert result is not None
    
    def test_list_by_cve(self, repo, sample_cve):
        """测试获取 CVE 的所有补丁"""
        for i in range(3):
            patch = Patch(
                cve_id=sample_cve.id,
                commit_hash=f"abc{i}23def45678901234567890abcdef1234567",
                subject=f"Fix {i}",
                author="Test",
            )
            repo.create(patch)
        
        patches = repo.list_by_cve(sample_cve.id)
        assert len(patches) == 3


class TestPatchStatusRepository:
    """PatchStatus 仓库测试"""
    
    @pytest.fixture
    def repo(self, db_session):
        return PatchStatusRepository(db_session)
    
    @pytest.fixture
    def sample_patch(self, db_session):
        cve = CVE(id="CVE-2024-STATUS", description="Test")
        db_session.add(cve)
        
        patch = Patch(
            cve_id="CVE-2024-STATUS",
            commit_hash="abc123",
            subject="Fix",
            author="Test",
        )
        db_session.add(patch)
        db_session.flush()
        return patch
    
    def test_create_status(self, repo, sample_patch):
        """测试创建状态记录"""
        status = PatchStatus(
            cve_id="CVE-2024-STATUS",
            patch_id=sample_patch.id,
            target_version="5.15.100",
            status="APPLIED",
            detection_method="commit_hash",
            match_confidence=1.0,
        )
        result = repo.create(status)
        
        assert result.status == "APPLIED"
        assert result.match_confidence == 1.0
    
    def test_get_latest(self, repo, sample_patch):
        """测试获取最新状态"""
        # 创建两个状态记录
        status1 = PatchStatus(
            cve_id="CVE-2024-STATUS",
            patch_id=sample_patch.id,
            target_version="5.15.100",
            status="PENDING",
            checked_at=datetime(2024, 1, 1),
        )
        status2 = PatchStatus(
            cve_id="CVE-2024-STATUS",
            patch_id=sample_patch.id,
            target_version="5.15.100",
            status="APPLIED",
            checked_at=datetime(2024, 2, 1),
        )
        repo.create(status1)
        repo.create(status2)
        
        latest = repo.get_latest("CVE-2024-STATUS", "5.15.100")
        assert latest.status == "APPLIED"
    
    def test_list_by_cve(self, repo, sample_patch):
        """测试获取 CVE 的所有状态"""
        for version in ["5.15.100", "5.15.101", "6.1.0"]:
            status = PatchStatus(
                cve_id="CVE-2024-STATUS",
                patch_id=sample_patch.id,
                target_version=version,
                status="APPLIED",
            )
            repo.create(status)
        
        statuses = repo.list_by_cve("CVE-2024-STATUS")
        assert len(statuses) == 3


class TestKconfigRepository:
    """Kconfig 仓库测试"""
    
    @pytest.fixture
    def repo(self, db_session):
        return KconfigRepository(db_session)
    
    @pytest.fixture
    def sample_cve(self, db_session):
        cve = CVE(id="CVE-2024-KCONFIG", description="Test")
        db_session.add(cve)
        db_session.flush()
        return cve
    
    def test_create_and_get_rule(self, repo, sample_cve):
        """测试创建和获取规则"""
        rule = KconfigRule(
            cve_id="CVE-2024-KCONFIG",
            rule_version="1.0",
            required={"configs": ["CONFIG_TEST"]},
            source="community",
            verified=True,
        )
        repo.create_rule(rule)
        
        result = repo.get_rule("CVE-2024-KCONFIG")
        assert result is not None
        assert result.rule_version == "1.0"
        assert result.verified is True
    
    def test_create_and_get_analysis(self, repo, sample_cve):
        """测试创建和获取分析结果"""
        analysis = KconfigAnalysis(
            cve_id="CVE-2024-KCONFIG",
            kernel_version="5.15.100",
            config_status="VULNERABLE",
            risk_level="HIGH",
            exploitable=True,
        )
        repo.create_analysis(analysis)
        
        result = repo.get_analysis("CVE-2024-KCONFIG", "5.15.100")
        assert result is not None
        assert result.risk_level == "HIGH"
        assert result.exploitable is True


class TestDatabaseIntegration:
    """数据库集成测试"""
    
    def test_cascade_delete_cve(self, test_db):
        """测试级联删除 CVE"""
        with test_db.session() as session:
            cve = CVE(id="CVE-2024-CASCADE", description="Test")
            session.add(cve)
            session.flush()
            
            # 添加关联数据
            ref = CVEReference(
                cve_id="CVE-2024-CASCADE",
                url="https://example.com",
                type="PATCH",
            )
            patch = Patch(
                cve_id="CVE-2024-CASCADE",
                commit_hash="abc123",
                subject="Fix",
                author="Test",
            )
            session.add(ref)
            session.add(patch)
        
        # 删除 CVE
        with test_db.session() as session:
            cve = session.query(CVE).filter_by(id="CVE-2024-CASCADE").first()
            session.delete(cve)
        
        # 验证关联数据也被删除
        with test_db.session() as session:
            assert session.query(CVEReference).count() == 0
            assert session.query(Patch).count() == 0
