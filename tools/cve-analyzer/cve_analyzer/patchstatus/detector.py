"""
补丁检测器实现

提供多种检测策略
"""

import hashlib
from typing import Optional

from cve_analyzer.patchstatus.base import (
    PatchDetector, DetectionResult, TargetCode,
    PatchStatusEnum, DetectionMethod
)


class CommitHashDetector(PatchDetector):
    """Commit hash 检测器 - 最可靠"""
    
    def detect(self, patch, target: TargetCode) -> DetectionResult:
        """
        通过 commit hash 检测
        
        策略:
        1. 在目标仓库中查找 commit hash
        2. 如果存在 -> APPLIED (置信度 1.0)
        3. 如果不存在 -> UNKNOWN (需要降级到其他方法)
        """
        commit_hash = patch.commit_hash
        
        if not commit_hash or not target.repo:
            return DetectionResult(
                cve_id=patch.cve_id,
                target_version=target.version,
                status=PatchStatusEnum.UNKNOWN,
                confidence=0.0,
                detection_method=DetectionMethod.COMMIT_HASH,
                details={"error": "No commit hash or repo"}
            )
        
        # 检查 commit 是否存在于仓库
        exists = target.repo.is_commit_exists(commit_hash)
        
        if exists:
            return DetectionResult(
                cve_id=patch.cve_id,
                target_version=target.version,
                status=PatchStatusEnum.APPLIED,
                confidence=1.0,
                detection_method=DetectionMethod.COMMIT_HASH,
                matched_commit=commit_hash,
                details={"method": "exact_commit_match"}
            )
        else:
            # Commit 不存在，返回 UNKNOWN 让其他检测器处理
            return DetectionResult(
                cve_id=patch.cve_id,
                target_version=target.version,
                status=PatchStatusEnum.UNKNOWN,
                confidence=0.0,
                detection_method=DetectionMethod.COMMIT_HASH,
                details={"method": "commit_not_found", "commit": commit_hash}
            )


class FileHashDetector(PatchDetector):
    """文件哈希检测器"""
    
    def detect(self, patch, target: TargetCode) -> DetectionResult:
        """
        通过文件哈希检测
        
        策略:
        1. 获取补丁中每个文件的预期哈希 (new_file_hash)
        2. 计算目标代码对应文件的实际哈希
        3. 对比:
           - 全部匹配 -> APPLIED (置信度 0.95+)
           - 部分匹配 -> MODIFIED
           - 不匹配 -> PENDING
        """
        if not target.repo:
            return self._unknown_result(patch, target, "No repo")
        
        files_checked = []
        files_matched = []
        
        for file_change in patch.files_changed:
            filename = file_change.filename
            expected_hash = getattr(file_change, 'new_file_hash', None)
            
            if not expected_hash:
                continue
            
            # 获取目标文件的当前内容
            try:
                content = target.repo.get_file_content_at_commit(
                    target.repo.get_current_branch() or "HEAD",
                    filename
                )
                
                if content is None:
                    # 文件不存在
                    files_checked.append({"file": filename, "status": "missing"})
                    continue
                
                # 计算实际哈希
                actual_hash = calculate_file_hash(content.encode())
                
                if actual_hash == expected_hash:
                    files_matched.append(filename)
                    files_checked.append({"file": filename, "status": "matched"})
                else:
                    files_checked.append({
                        "file": filename,
                        "status": "mismatch",
                        "expected": expected_hash[:16],
                        "actual": actual_hash[:16]
                    })
                    
            except Exception as e:
                files_checked.append({"file": filename, "status": "error", "error": str(e)})
        
        # 评估结果
        if not files_checked:
            return self._unknown_result(patch, target, "No files to check")
        
        match_ratio = len(files_matched) / len(files_checked)
        
        if match_ratio == 1.0:
            status = PatchStatusEnum.APPLIED
            confidence = 0.95
        elif match_ratio > 0.5:
            status = PatchStatusEnum.MODIFIED
            confidence = 0.7
        else:
            status = PatchStatusEnum.PENDING
            confidence = 0.8
        
        return DetectionResult(
            cve_id=patch.cve_id,
            target_version=target.version,
            status=status,
            confidence=confidence,
            detection_method=DetectionMethod.FILE_HASH,
            details={
                "files_checked": files_checked,
                "match_ratio": match_ratio
            }
        )
    
    def _unknown_result(self, patch, target, reason):
        """返回 UNKNOWN 结果"""
        return DetectionResult(
            cve_id=patch.cve_id,
            target_version=target.version,
            status=PatchStatusEnum.UNKNOWN,
            confidence=0.0,
            detection_method=DetectionMethod.FILE_HASH,
            details={"error": reason}
        )


class RevertDetector(PatchDetector):
    """Revert 检测器"""
    
    def detect(self, patch, target: TargetCode) -> DetectionResult:
        """
        检测补丁是否被回退
        
        策略:
        1. 搜索包含 "Revert" 和原 commit subject 的 commit
        2. 如果找到 -> REVERTED
        """
        if not target.repo:
            return DetectionResult(
                cve_id=patch.cve_id,
                target_version=target.version,
                status=PatchStatusEnum.UNKNOWN,
                confidence=0.0,
                detection_method=DetectionMethod.COMMIT_HASH,
                details={"error": "No repo"}
            )
        
        # 构建搜索模式
        subject = patch.subject
        if not subject:
            return DetectionResult(
                cve_id=patch.cve_id,
                target_version=target.version,
                status=PatchStatusEnum.UNKNOWN,
                confidence=0.0,
                detection_method=DetectionMethod.COMMIT_HASH,
                details={"error": "No subject"}
            )
        
        # 搜索 revert commit
        try:
            revert_commits = target.repo.find_commits_by_message(
                f'Revert "{subject}"',
                since=None
            )
            
            if revert_commits:
                return DetectionResult(
                    cve_id=patch.cve_id,
                    target_version=target.version,
                    status=PatchStatusEnum.REVERTED,
                    confidence=0.95,
                    detection_method=DetectionMethod.COMMIT_HASH,
                    matched_commit=revert_commits[0].hash,
                    details={
                        "revert_commit_subject": revert_commits[0].subject,
                        "revert_commit_hash": revert_commits[0].hash
                    }
                )
        except Exception as e:
            pass
        
        # 没有找到 revert，返回 UNKNOWN (需要其他检测器判断)
        return DetectionResult(
            cve_id=patch.cve_id,
            target_version=target.version,
            status=PatchStatusEnum.UNKNOWN,
            confidence=0.0,
            detection_method=DetectionMethod.COMMIT_HASH,
            details={"revert_check": "not_found"}
        )


def calculate_file_hash(content: bytes) -> str:
    """计算文件内容的 SHA256 哈希"""
    return hashlib.sha256(content).hexdigest()
