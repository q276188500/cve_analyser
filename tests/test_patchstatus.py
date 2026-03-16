"""
Phase 4: 补丁状态检测模块测试 (TDD)

测试驱动开发，先定义测试，再实现功能
"""

import pytest
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock

from cve_analyzer.patchstatus import PatchDetector, DetectionResult, TargetCode
from cve_analyzer.patchstatus.base import PatchStatusEnum, DetectionMethod
from cve_analyzer.core.models import Patch, PatchStatus


class TestPatchDetector:
    """补丁检测器基类测试"""
    
    @pytest.fixture
    def mock_target(self):
        """模拟目标代码"""
        target = Mock(spec=TargetCode)
        target.version = "5.15.100"
        target.path = "/path/to/kernel"
        return target
    
    @pytest.fixture
    def sample_patch(self):
        """示例补丁"""
        mock_patch = Mock(spec=Patch)
        mock_patch.commit_hash = "abc123def45678901234567890abcdef12345678"
        mock_patch.files_changed = [
            Mock(filename="net/core/sock.c", new_file_hash="sha256_hash_here")
        ]
        return patch
    
    def test_detect_applied_by_commit_hash(self, mock_target, sample_patch):
        """测试通过 commit hash 检测已应用补丁"""
        from cve_analyzer.patchstatus.detector import CommitHashDetector
        
        # 模拟目标仓库包含该 commit
        mock_target.repo.is_commit_exists.return_value = True
        
        detector = CommitHashDetector()
        result = detector.detect(sample_patch, mock_target)
        
        assert result.status == PatchStatusEnum.APPLIED
        assert result.detection_method == DetectionMethod.COMMIT_HASH
        assert result.confidence == 1.0
        assert result.matched_commit == sample_patch.commit_hash
    
    def test_detect_pending_no_commit(self, mock_target, sample_patch):
        """测试 commit 不存在时返回 PENDING"""
        from cve_analyzer.patchstatus.detector import CommitHashDetector
        
        # 模拟目标仓库不包含该 commit
        mock_target.repo.is_commit_exists.return_value = False
        
        detector = CommitHashDetector()
        result = detector.detect(sample_patch, mock_target)
        
        # Commit hash 检测返回 UNKNOWN，需要降级到其他方法
        assert result.status in [PatchStatusEnum.UNKNOWN, PatchStatusEnum.PENDING]
    
    def test_detect_by_file_hash(self, mock_target, sample_patch):
        """测试通过文件哈希检测"""
        from cve_analyzer.patchstatus.detector import FileHashDetector
        
        # 模拟文件哈希匹配
        mock_target.repo.get_file_content_at_commit.return_value = "file content"
        
        with patch('cve_analyzer.patchstatus.detector.calculate_file_hash') as mock_hash:
            mock_hash.return_value = "sha256_hash_here"  # 与补丁中的哈希匹配
            
            detector = FileHashDetector()
            result = detector.detect(sample_patch, mock_target)
            
            assert result.status == PatchStatusEnum.APPLIED
            assert result.detection_method == DetectionMethod.FILE_HASH
            assert result.confidence >= 0.95


class TestContentMatcher:
    """内容特征匹配测试"""
    
    def test_match_by_key_code_features(self):
        """测试通过关键代码特征匹配"""
        from cve_analyzer.patchstatus.matcher import ContentMatcher
        
        # 原始漏洞代码
        vulnerable_code = """
        void vulnerable_func() {
            ptr = kmalloc(size, GFP_KERNEL);
            // 缺少 null check
            ptr->data = value;  // 可能空指针解引用
        }
        """
        
        # 修复后代码 (有 null check)
        fixed_code = """
        void vulnerable_func() {
            ptr = kmalloc(size, GFP_KERNEL);
            if (!ptr)
                return -ENOMEM;
            ptr->data = value;
        }
        """
        
        matcher = ContentMatcher()
        
        # 检测修复后的代码
        result = matcher.match(fixed_code, patch_features=["if (!ptr)", "return -ENOMEM"])
        
        assert result["matched"] is True
        assert result["confidence"] > 0.7
    
    def test_match_partial_modified(self):
        """测试部分匹配 (代码被修改但逻辑等价)"""
        from cve_analyzer.patchstatus.matcher import ContentMatcher
        
        matcher = ContentMatcher()
        
        # 补丁中的代码
        patch_code = "if (!skb) return NF_DROP;"
        
        # 目标代码 (变量名不同但逻辑相同)
        target_code = "if (unlikely(!packet)) goto drop;"
        
        result = matcher.match(target_code, patch_code)
        
        # 应该识别为 MODIFIED (逻辑相似但不完全相同)
        assert result["status"] == PatchStatusEnum.MODIFIED
        assert 0.5 < result["confidence"] < 0.9


class TestMultiStrategyDetector:
    """多策略检测器测试"""
    
    def test_priority_commit_hash_first(self):
        """测试优先使用 commit hash 检测"""
        from cve_analyzer.patchstatus import MultiStrategyDetector
        
        detector = MultiStrategyDetector()
        
        mock_patch = Mock()
        mock_patch.commit_hash = "abc123"
        
        target = Mock()
        target.repo.is_commit_exists.return_value = True
        
        result = detector.detect(patch, target)
        
        # 应该优先使用 commit hash 方法
        assert result.detection_method == DetectionMethod.COMMIT_HASH
        assert result.confidence == 1.0
    
    def test_fallback_to_file_hash(self):
        """测试 commit hash 失败时降级到文件哈希"""
        from cve_analyzer.patchstatus import MultiStrategyDetector
        
        detector = MultiStrategyDetector()
        
        mock_patch = Mock()
        mock_patch.commit_hash = "abc123"
        mock_patch.files_changed = [Mock(filename="net.c", new_file_hash="hash123")]
        
        target = Mock()
        # commit hash 检测失败
        target.repo.is_commit_exists.return_value = False
        # 但文件哈希匹配
        target.repo.get_file_content_at_commit.return_value = "content"
        
        with patch('cve_analyzer.patchstatus.detector.calculate_file_hash') as mock_hash:
            mock_hash.return_value = "hash123"
            
            result = detector.detect(patch, target)
            
            # 降级到文件哈希检测
            assert result.detection_method == DetectionMethod.FILE_HASH
    
    def test_fallback_to_content_match(self):
        """测试所有精确方法失败时使用内容匹配"""
        from cve_analyzer.patchstatus import MultiStrategyDetector
        
        detector = MultiStrategyDetector()
        
        mock_patch = Mock()
        mock_patch.commit_hash = "abc123"
        mock_patch.files_changed = []
        mock_patch.patch_content = "fix code here"
        
        target = Mock()
        target.repo.is_commit_exists.return_value = False
        
        with patch.object(detector.content_matcher, 'match') as mock_match:
            mock_match.return_value = {"status": PatchStatusEnum.APPLIED, "confidence": 0.75}
            
            result = detector.detect(mock_patch, target)
            
            # 降级到内容匹配
            assert result.detection_method == DetectionMethod.CONTENT
            assert result.confidence == 0.75


class TestDetectionResult:
    """检测结果测试"""
    
    def test_result_structure(self):
        """测试结果数据结构"""
        result = DetectionResult(
            cve_id="CVE-2024-1234",
            target_version="5.15.100",
            status=PatchStatusEnum.APPLIED,
            confidence=0.95,
            detection_method=DetectionMethod.FILE_HASH,
            matched_commit="abc123",
            details={"file_hash_match": True}
        )
        
        assert result.cve_id == "CVE-2024-1234"
        assert result.status == "APPLIED"
        assert result.confidence == 0.95
    
    def test_confidence_thresholds(self):
        """测试置信度阈值"""
        # 高置信度 (0.9+)
        high_confidence = DetectionResult(
            cve_id="CVE-2024-1234",
            target_version="5.15.100",
            status=PatchStatusEnum.APPLIED,
            confidence=0.95,
            detection_method=DetectionMethod.COMMIT_HASH
        )
        assert high_confidence.confidence >= 0.9
        
        # 中等置信度 (0.7-0.9)
        medium_confidence = DetectionResult(
            cve_id="CVE-2024-1234",
            target_version="5.15.100",
            status=PatchStatusEnum.APPLIED,
            confidence=0.8,
            detection_method=DetectionMethod.CONTENT
        )
        assert 0.7 <= medium_confidence.confidence < 0.9
        
        # 低置信度 (<0.7)
        low_confidence = DetectionResult(
            cve_id="CVE-2024-1234",
            target_version="5.15.100",
            status=PatchStatusEnum.UNKNOWN,
            confidence=0.5,
            detection_method=DetectionMethod.AST
        )
        assert low_confidence.confidence < 0.7


class TestBatchDetection:
    """批量检测测试"""
    
    def test_detect_batch_multiple_cves(self):
        """测试批量检测多个 CVE"""
        from cve_analyzer.patchstatus import PatchDetector
        
        detector = PatchDetector()
        
        cves = ["CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"]
        target = Mock()
        
        with patch.object(detector, 'detect') as mock_detect:
            mock_detect.side_effect = [
                DetectionResult(cve_id="CVE-2024-0001", status=PatchStatusEnum.APPLIED, confidence=1.0, target_version="5.15", detection_method=DetectionMethod.COMMIT_HASH),
                DetectionResult(cve_id="CVE-2024-0002", status=PatchStatusEnum.PENDING, confidence=0.9, target_version="5.15", detection_method=DetectionMethod.FILE_HASH),
                DetectionResult(cve_id="CVE-2024-0003", status=PatchStatusEnum.UNKNOWN, confidence=0.5, target_version="5.15", detection_method=DetectionMethod.CONTENT),
            ]
            
            results = detector.detect_batch(cves, target)
            
            assert len(results) == 3
            assert results[0].status == PatchStatusEnum.APPLIED
            assert results[1].status == PatchStatusEnum.PENDING
            assert results[2].status == PatchStatusEnum.UNKNOWN


class TestRevertDetection:
    """Revert 检测测试"""
    
    def test_detect_reverted_patch(self):
        """测试检测被回退的补丁"""
        from cve_analyzer.patchstatus.detector import RevertDetector
        
        detector = RevertDetector()
        
        mock_patch = Mock()
        mock_patch.commit_hash = "abc123"
        mock_patch.subject = "Fix vulnerability"
        
        target = Mock()
        # 模拟找到 revert commit
        target.repo.find_commits_by_message.return_value = [
            Mock(subject='Revert "Fix vulnerability"', hash="def456")
        ]
        
        result = detector.detect(patch, target)
        
        assert result.status == PatchStatusEnum.REVERTED
        assert "Revert" in result.details.get("revert_commit_subject", "")


class TestErrorHandling:
    """错误处理测试"""
    
    def test_handle_missing_target_repo(self):
        """测试目标仓库不存在时的处理"""
        from cve_analyzer.patchstatus import PatchDetector
        
        detector = PatchDetector()
        
        mock_patch = Mock()
        target = Mock()
        target.repo = None  # 没有仓库
        
        result = detector.detect(patch, target)
        
        # 应该返回 UNKNOWN 而不是抛出异常
        assert result.status == PatchStatusEnum.UNKNOWN
        assert result.confidence == 0.0
    
    def test_handle_network_error(self):
        """测试网络错误时的处理"""
        from cve_analyzer.patchstatus.matcher import ContentMatcher
        
        matcher = ContentMatcher()
        
        with patch.object(matcher, '_fetch_remote_patch', side_effect=Exception("Network error")):
            result = matcher.match("local code", remote_url="http://example.com/patch")
            
            # 应该返回 UNKNOWN 而不是抛出异常
            assert result.get("status") == PatchStatusEnum.UNKNOWN
