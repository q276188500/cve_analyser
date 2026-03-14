"""
Phase 6: 补丁历史追踪测试
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import Mock, MagicMock

from cve_analyzer.history import (
    HistoryTracker, TrackedChange, ChangeType, HistoryResult,
    GitHistoryTracker, HistoryAnalyzer,
)


class TestChangeType:
    """测试变更类型枚举"""
    
    def test_change_type_values(self):
        """测试变更类型值"""
        assert ChangeType.FIXUP.value == "fixup"
        assert ChangeType.REVERT.value == "revert"
        assert ChangeType.REFACTOR.value == "refactor"
        assert ChangeType.BACKPORT.value == "backport"
        assert ChangeType.CONFLICT_FIX.value == "conflict_fix"
        assert ChangeType.FOLLOW_UP.value == "follow_up"
        assert ChangeType.CVE_RELATED.value == "cve_related"
        assert ChangeType.UNKNOWN.value == "unknown"


class TestTrackedChange:
    """测试变更追踪数据类"""
    
    def test_tracked_change_creation(self):
        """测试创建 TrackedChange"""
        change = TrackedChange(
            commit_hash="abc123",
            commit_subject="Fix bug",
            author="Test Author",
            author_email="test@example.com",
            commit_date=datetime.now(),
            change_type=ChangeType.FIXUP,
        )
        
        assert change.commit_hash == "abc123"
        assert change.change_type == ChangeType.FIXUP
        assert change.confidence == 0.0  # 默认值


class TestHistoryResult:
    """测试历史结果数据类"""
    
    @pytest.fixture
    def sample_result(self):
        """创建示例结果"""
        return HistoryResult(
            cve_id="CVE-2024-0001",
            patch_commit="abc123",
            original_subject="Original patch",
            changes=[
                TrackedChange(
                    commit_hash="def456",
                    commit_subject="Fix the fix",
                    author="Dev",
                    author_email="dev@example.com",
                    commit_date=datetime.now() - timedelta(days=1),
                    change_type=ChangeType.FIXUP,
                ),
                TrackedChange(
                    commit_hash="ghi789",
                    commit_subject="Revert fix",
                    author="Dev",
                    author_email="dev@example.com",
                    commit_date=datetime.now(),
                    change_type=ChangeType.REVERT,
                ),
            ],
        )
    
    def test_get_changes_by_type(self, sample_result):
        """测试按类型获取变更"""
        fixups = sample_result.get_changes_by_type(ChangeType.FIXUP)
        assert len(fixups) == 1
        assert fixups[0].commit_hash == "def456"
    
    def test_has_revert(self, sample_result):
        """测试检查是否有回退"""
        assert sample_result.has_revert() is True
    
    def test_has_fixups(self, sample_result):
        """测试检查是否有修复"""
        assert sample_result.has_fixups() is True
    
    def test_get_latest_status_reverted(self, sample_result):
        """测试获取最新状态 - 已回退"""
        assert sample_result.get_latest_status() == "reverted"
    
    def test_get_latest_status_fixed(self):
        """测试获取最新状态 - 已修复"""
        result = HistoryResult(
            cve_id="CVE-2024-0001",
            patch_commit="abc123",
            original_subject="Original",
            changes=[
                TrackedChange(
                    commit_hash="def456",
                    commit_subject="Fix",
                    author="Dev",
                    author_email="dev@example.com",
                    commit_date=datetime.now(),
                    change_type=ChangeType.FIXUP,
                ),
            ],
        )
        assert result.get_latest_status() == "fixed"
    
    def test_get_latest_status_original(self):
        """测试获取最新状态 - 原始"""
        result = HistoryResult(
            cve_id="CVE-2024-0001",
            patch_commit="abc123",
            original_subject="Original",
            changes=[],
        )
        assert result.get_latest_status() == "original"


class TestGitHistoryTracker:
    """测试 Git 历史追踪器"""
    
    @pytest.fixture
    def mock_repo(self):
        """创建 Mock 仓库"""
        repo = Mock()
        repo.get_commit.return_value = Mock(
            hash="abc123",
            subject="Original patch",
            files_changed=["file1.c", "file2.c"],
            committer_date=datetime.now() - timedelta(days=7),
        )
        repo.repo.git.log.return_value = ""
        return repo
    
    def test_classify_change_fixup(self):
        """测试分类 fixup 变更"""
        tracker = GitHistoryTracker()
        
        change_type, confidence = tracker._classify_change(
            "fixup: correct the fix",
            {"file_overlap": ["file.c"]}
        )
        
        assert change_type == ChangeType.FIXUP
        assert confidence > 0.8
    
    def test_classify_change_revert(self):
        """测试分类 revert 变更"""
        tracker = GitHistoryTracker()
        
        commit_info = {
            "is_revert": True,
            "file_overlap": [],
        }
        change_type, confidence = tracker._classify_change(
            'Revert "some change"',
            commit_info
        )
        
        assert change_type == ChangeType.REVERT
        assert confidence == 1.0
    
    def test_classify_change_refactor(self):
        """测试分类 refactor 变更"""
        tracker = GitHistoryTracker()
        
        change_type, confidence = tracker._classify_change(
            "refactor: clean up code",
            {}
        )
        
        assert change_type == ChangeType.REFACTOR
        assert confidence > 0.5
    
    def test_classify_change_backport(self):
        """测试分类 backport 变更"""
        tracker = GitHistoryTracker()
        
        change_type, confidence = tracker._classify_change(
            "backport to stable",
            {}
        )
        
        assert change_type == ChangeType.BACKPORT
    
    def test_classify_change_cve_related(self):
        """测试分类 CVE 相关变更"""
        tracker = GitHistoryTracker()
        
        change_type, confidence = tracker._classify_change(
            "net: fix socket issue related to CVE-2024-1234",
            {}
        )
        
        assert change_type == ChangeType.CVE_RELATED
        assert confidence > 0.5
    
    def test_is_revert_of_true(self):
        """测试检测 revert - 是 revert"""
        tracker = GitHistoryTracker()
        
        commit = Mock(subject='Revert "Original patch"')
        original = Mock(subject="Original patch", hash="abc123")
        
        # Mock commit message lookup
        commit_obj = Mock()
        commit_obj.message = "Revert...\n\nThis reverts commit abc123456."
        tracker.repo = Mock()
        tracker.repo.commit.return_value = commit_obj
        
        result = tracker._is_revert_of(commit, original)
        assert result is True
    
    def test_is_revert_of_false(self):
        """测试检测 revert - 不是 revert"""
        tracker = GitHistoryTracker()
        
        commit = Mock(subject="Some other change")
        original = Mock(subject="Original patch")
        
        result = tracker._is_revert_of(commit, original)
        assert result is False
    
    def test_generate_summary(self):
        """测试生成汇总"""
        tracker = GitHistoryTracker()
        
        changes = [
            TrackedChange(
                commit_hash="1",
                commit_subject="Fix",
                author="Dev",
                author_email="dev@example.com",
                commit_date=datetime.now(),
                change_type=ChangeType.FIXUP,
            ),
            TrackedChange(
                commit_hash="2",
                commit_subject="Revert",
                author="Dev",
                author_email="dev@example.com",
                commit_date=datetime.now(),
                change_type=ChangeType.REVERT,
            ),
        ]
        
        summary = tracker._generate_summary(changes)
        
        assert summary["total"] == 2
        assert summary["fixup"] == 1
        assert summary["revert"] == 1


class TestHistoryAnalyzer:
    """测试历史分析器"""
    
    @pytest.fixture
    def mock_tracker(self):
        """创建 Mock 追踪器"""
        tracker = Mock()
        tracker.track.return_value = HistoryResult(
            cve_id="CVE-2024-0001",
            patch_commit="abc123",
            original_subject="Original patch",
            changes=[],
            summary={"total": 0},
        )
        return tracker
    
    def test_analyze(self, mock_tracker):
        """测试分析方法"""
        analyzer = HistoryAnalyzer(mock_tracker)
        
        result = analyzer.analyze("abc123", "CVE-2024-0001")
        
        assert result.cve_id == "CVE-2024-0001"
        assert "trends" in result.analysis
        assert "risk_assessment" in result.analysis
        assert "timeline" in result.analysis
    
    def test_assess_risk_clean(self):
        """测试风险评估 - 干净"""
        analyzer = HistoryAnalyzer()
        
        result = HistoryResult(
            cve_id="CVE-2024-0001",
            patch_commit="abc123",
            original_subject="Original",
            changes=[],
        )
        
        risk = analyzer._assess_risk(result)
        
        assert risk["level"] == "low"
        assert risk["score"] == 0
    
    def test_assess_risk_reverted(self):
        """测试风险评估 - 已回退"""
        analyzer = HistoryAnalyzer()
        
        result = HistoryResult(
            cve_id="CVE-2024-0001",
            patch_commit="abc123",
            original_subject="Original",
            changes=[
                TrackedChange(
                    commit_hash="1",
                    commit_subject="Revert",
                    author="Dev",
                    author_email="dev@example.com",
                    commit_date=datetime.now(),
                    change_type=ChangeType.REVERT,
                ),
            ],
        )
        
        risk = analyzer._assess_risk(result)
        
        assert risk["level"] == "high"
        assert risk["score"] >= 50
        assert any("回退" in f for f in risk["factors"])
    
    def test_assess_risk_many_fixups(self):
        """测试风险评估 - 多次修复"""
        analyzer = HistoryAnalyzer()
        
        result = HistoryResult(
            cve_id="CVE-2024-0001",
            patch_commit="abc123",
            original_subject="Original",
            changes=[
                TrackedChange(
                    commit_hash=str(i),
                    commit_subject=f"Fix {i}",
                    author="Dev",
                    author_email="dev@example.com",
                    commit_date=datetime.now(),
                    change_type=ChangeType.FIXUP,
                )
                for i in range(3)
            ],
        )
        
        risk = analyzer._assess_risk(result)
        
        assert risk["score"] >= 30
        assert any("修复" in f for f in risk["factors"])


class TestHistoryIntegration:
    """集成测试"""
    
    def test_full_workflow(self, tmp_path):
        """测试完整工作流程"""
        # 这是一个简化的集成测试
        # 实际测试需要真实的 git 仓库
        
        # 创建分析器
        analyzer = HistoryAnalyzer()
        
        # 由于我们没有真实仓库，只验证初始化成功
        assert analyzer is not None
        assert analyzer.tracker is not None
