"""
多策略检测器

整合多种检测策略，按优先级执行
"""

from typing import List

from cve_analyzer.patchstatus.base import (
    PatchDetector, DetectionResult, TargetCode,
    PatchStatusEnum, DetectionMethod
)
from cve_analyzer.patchstatus.detector import (
    CommitHashDetector, FileHashDetector, RevertDetector
)
from cve_analyzer.patchstatus.matcher import ContentMatcher


class MultiStrategyDetector(PatchDetector):
    """
    多策略检测器
    
    按优先级尝试多种检测方法:
    1. Commit hash (置信度 1.0) - 最可靠
    2. Revert 检测 (置信度 0.95)
    3. File hash (置信度 0.95)
    4. Content match (置信度 0.5-0.9)
    """
    
    def __init__(self):
        self.commit_detector = CommitHashDetector()
        self.revert_detector = RevertDetector()
        self.file_hash_detector = FileHashDetector()
        self.content_matcher = ContentMatcher()
    
    def detect(self, patch, target: TargetCode) -> DetectionResult:
        """
        执行多策略检测
        
        策略优先级:
        1. Commit hash - 如果匹配直接返回
        2. Revert 检测 - 如果被回退直接返回
        3. File hash - 如果匹配返回
        4. Content match - 降级方案
        """
        cve_id = getattr(patch, 'cve_id', 'UNKNOWN')
        
        # 策略 1: Commit hash (最可靠)
        result = self.commit_detector.detect(patch, target)
        if result.status == PatchStatusEnum.APPLIED:
            return result
        
        # 策略 2: Revert 检测
        result = self.revert_detector.detect(patch, target)
        if result.status == PatchStatusEnum.REVERTED:
            return result
        
        # 策略 3: File hash
        result = self.file_hash_detector.detect(patch, target)
        if result.status in [PatchStatusEnum.APPLIED, PatchStatusEnum.MODIFIED]:
            return result
        
        # 策略 4: Content match (降级方案)
        return self._content_match_detect(patch, target)
    
    def _content_match_detect(self, patch, target: TargetCode) -> DetectionResult:
        """使用内容匹配作为最后手段"""
        cve_id = getattr(patch, 'cve_id', 'UNKNOWN')
        
        # 获取补丁特征
        patch_features = []
        for fc in getattr(patch, 'files_changed', []):
            content = getattr(fc, 'patch_content', '')
            if content:
                features = self.content_matcher._extract_features(content)
                patch_features.extend(features)
        
        if not patch_features:
            return DetectionResult(
                cve_id=cve_id,
                target_version=target.version,
                status=PatchStatusEnum.UNKNOWN,
                confidence=0.0,
                detection_method=DetectionMethod.CONTENT,
                details={"error": "No patch features to match"}
            )
        
        # 对每个受影响的文件进行匹配
        best_match = None
        best_confidence = 0.0
        
        for fc in getattr(patch, 'files_changed', []):
            filename = fc.filename
            
            try:
                # 获取目标文件内容
                target_content = target.repo.get_file_content_at_commit(
                    target.repo.get_current_branch() or "HEAD",
                    filename
                ) if target.repo else None
                
                if target_content:
                    match_result = self.content_matcher.match(
                        target_content,
                        patch_features=patch_features
                    )
                    
                    if match_result["confidence"] > best_confidence:
                        best_confidence = match_result["confidence"]
                        best_match = match_result
                        
            except Exception as e:
                continue
        
        if best_match:
            return DetectionResult(
                cve_id=cve_id,
                target_version=target.version,
                status=best_match["status"],
                confidence=best_match["confidence"],
                detection_method=DetectionMethod.CONTENT,
                details={
                    "matched_features": best_match.get("matched_features", []),
                    "total_features": best_match.get("total_features", 0),
                    "match_ratio": best_match.get("match_ratio", 0)
                }
            )
        else:
            return DetectionResult(
                cve_id=cve_id,
                target_version=target.version,
                status=PatchStatusEnum.UNKNOWN,
                confidence=0.0,
                detection_method=DetectionMethod.CONTENT,
                details={"error": "Content match failed"}
            )
    
    def detect_batch(self, cve_ids: List[str], target: TargetCode) -> List[DetectionResult]:
        """批量检测"""
        results = []
        
        for cve_id in cve_ids:
            # 从数据库获取补丁信息
            patch = self._get_patch_for_cve(cve_id)
            
            if patch:
                result = self.detect(patch, target)
            else:
                # 没有找到补丁信息
                result = DetectionResult(
                    cve_id=cve_id,
                    target_version=target.version,
                    status=PatchStatusEnum.UNKNOWN,
                    confidence=0.0,
                    detection_method=DetectionMethod.COMMIT_HASH,
                    details={"error": "No patch found for CVE"}
                )
            
            results.append(result)
        
        return results
    
    def _get_patch_for_cve(self, cve_id: str):
        """从数据库获取补丁"""
        # 简化实现，实际应该从数据库查询
        from cve_analyzer.core.database import get_db, CVERepository
        
        try:
            db = get_db()
            with db.session() as session:
                repo = CVERepository(session)
                cve = repo.get_by_id(cve_id)
                
                if cve and cve.patches:
                    return cve.patches[0]  # 返回第一个补丁
        except Exception as e:
            print(f"获取补丁失败: {e}")
        
        return None
