"""
Git 历史追踪器实现
"""

import re
from datetime import datetime
from typing import List, Optional, Dict, Any

from cve_analyzer.history.base import (
    HistoryTracker, TrackedChange, ChangeType, HistoryResult
)
from cve_analyzer.utils.git import GitRepository


class GitHistoryTracker(HistoryTracker):
    """基于 Git 的历史追踪器"""
    
    # 用于识别变更类型的模式
    PATTERNS = {
        ChangeType.REVERT: [
            r'^[Rr]evert\s+[\"\']?(.+)[\"\']?',
            r'^[Rr]evert\s+["\']?([a-f0-9]{7,40})["\']?',
            r'^Revert\s+"(.+)"',
        ],
        ChangeType.FIXUP: [
            r'^[Ff]ixup!?\s*:?\s*(.+)',
            r'^[Ff]ix\s*:?\s*(.+)',
            r'^[Cc]orrection\s*:?\s*(.+)',
            r'^[Bb]ugfix\s*:?\s*(.+)',
            r'^[Aa]mend\s*:?\s*(.+)',
        ],
        ChangeType.REFACTOR: [
            r'^[Rr]efactor\s*:?\s*(.+)',
            r'^[Cc]leanup\s*:?\s*(.+)',
            r'^[Ss]implify\s*:?\s*(.+)',
            r'^[Rr]ework\s*:?\s*(.+)',
        ],
        ChangeType.BACKPORT: [
            r'^[Bb]ackport\s*:?\s*(.+)',
            r'^[Bb]ack[-\s]?port\s*:?\s*(.+)',
        ],
        ChangeType.CONFLICT_FIX: [
            r'^[Mm]erge\s+(?:conflict|fix)',
            r'^[Cc]onflict\s*:?\s*(.+)',
            r'^[Rr]esolve\s+(?:conflict|merge)',
        ],
        ChangeType.FOLLOW_UP: [
            r'^[Ff]ollow[-\s]?up\s*:?\s*(.+)',
            r'^[Ff]ollowup\s*:?\s*(.+)',
            r'^[Ss]ee[-\s]?also\s*:?\s*(.+)',
            r'^[Rr]elated\s*:?\s*(.+)',
        ],
        ChangeType.CVE_RELATED: [
            r'CVE-\d{4}-\d{4,}',  # 匹配 CVE-YYYY-NNNN 格式
        ],
    }
    
    def __init__(self, repo_path: Optional[str] = None):
        """
        初始化追踪器
        
        Args:
            repo_path: Git 仓库路径，None 则使用当前目录
        """
        self.repo = GitRepository(repo_path) if repo_path else None
        self._repo_path = repo_path
    
    def track(self, patch_commit: str, cve_id: Optional[str] = None) -> HistoryResult:
        """
        追踪补丁的历史
        
        Args:
            patch_commit: 补丁的 commit hash
            cve_id: 可选的 CVE ID
        
        Returns:
            历史追踪结果
        """
        if not self.repo:
            raise ValueError("Git repository not configured")
        
        # 获取原始补丁信息
        original = self.repo.get_commit(patch_commit)
        if not original:
            return HistoryResult(
                cve_id=cve_id or "UNKNOWN",
                patch_commit=patch_commit,
                original_subject="NOT FOUND",
                changes=[],
                summary={"error": "Patch commit not found"},
            )
        
        # 查找相关 commits
        related = self.find_related_commits(patch_commit)
        
        # ⭐ 新增: 查找 commit message 中引用相同 CVE 的提交
        cve_related = []
        if cve_id and cve_id != "UNKNOWN":
            cve_related = self._find_cve_related_commits(cve_id, patch_commit)
        
        # 分析每个 commit 的类型
        changes = []
        for commit_info in related:
            change = self._analyze_commit(commit_info, original)
            if change:
                changes.append(change)
        
        # ⭐ 新增: 分析 CVE 相关提交
        for commit_info in cve_related:
            # 检查是否已经在 changes 中（去重）
            existing = [c for c in changes if c.commit_hash == commit_info["commit"].hash]
            if not existing:
                change = self._analyze_cve_related_commit(commit_info, original, cve_id)
                if change:
                    changes.append(change)
        
        # 按时间排序
        changes.sort(key=lambda c: c.commit_date)
        
        # 生成汇总
        summary = self._generate_summary(changes)
        
        # 分析结果
        analysis = self._analyze_result(changes, original)
        
        return HistoryResult(
            cve_id=cve_id or "UNKNOWN",
            patch_commit=patch_commit,
            original_subject=original.subject,
            changes=changes,
            summary=summary,
            analysis=analysis,
        )
    
    def find_related_commits(
        self,
        patch_commit: str,
        look_ahead: int = 100
    ) -> List[Dict[str, Any]]:
        """
        查找补丁后的相关 commits
        
        策略:
        1. 获取补丁后的 commits (按时间顺序)
        2. 匹配文件变更
        3. 匹配 commit message 模式
        """
        if not self.repo:
            return []
        
        original = self.repo.get_commit(patch_commit)
        if not original:
            return []
        
        # 获取补丁后的 commits
        try:
            commits_after = self.repo.repo.git.log(
                f"{patch_commit}..HEAD",
                f"--max-count={look_ahead}",
                "--format=%H"
            ).strip().split("\n")
        except Exception:
            return []
        
        if not commits_after or commits_after == ['']:
            return []
        
        related = []
        original_files = set(original.files_changed)
        
        for commit_hash in commits_after:
            if not commit_hash:
                continue
            
            try:
                commit = self.repo.get_commit(commit_hash)
                if not commit:
                    continue
                
                # 检查文件重叠
                commit_files = set(commit.files_changed)
                file_overlap = original_files & commit_files
                
                # 检查是否是 revert
                is_revert = self._is_revert_of(commit, original)
                
                # 检查 commit message 是否引用原补丁
                message_refs = self._check_message_refs(commit.subject, original)
                
                # 相关性评分
                relevance_score = 0
                relevance_score += len(file_overlap) * 2
                relevance_score += message_refs * 3
                if is_revert:
                    relevance_score += 10
                
                # 只保留相关度高的
                if relevance_score >= 2 or is_revert:
                    related.append({
                        "commit": commit,
                        "file_overlap": list(file_overlap),
                        "is_revert": is_revert,
                        "message_refs": message_refs,
                        "relevance_score": relevance_score,
                    })
            
            except Exception:
                continue
        
        # 按相关度排序
        related.sort(key=lambda x: x["relevance_score"], reverse=True)
        
        return related[:20]  # 最多返回 20 个
    
    def _analyze_commit(
        self,
        commit_info: Dict[str, Any],
        original: Any
    ) -> Optional[TrackedChange]:
        """分析单个 commit 的类型"""
        commit = commit_info["commit"]
        subject = commit.subject
        
        # 判断变更类型
        change_type, confidence = self._classify_change(subject, commit_info)
        
        # 获取统计信息
        stats = self._get_commit_stats(commit)
        
        # 生成描述
        description = self._generate_description(change_type, commit_info, original)
        
        return TrackedChange(
            commit_hash=commit.hash,
            commit_subject=subject,
            author=commit.author_name,
            author_email=commit.author_email,
            commit_date=commit.committer_date,
            change_type=change_type,
            parent_commit=commit.parents[0] if commit.parents else None,
            related_commits=[original.hash],
            files_changed=commit.files_changed,
            stats=stats,
            description=description,
            confidence=confidence,
        )
    
    def _classify_change(
        self,
        subject: str,
        commit_info: Dict[str, Any]
    ) -> tuple[ChangeType, float]:
        """分类变更类型"""
        subject_lower = subject.lower()
        
        # 检查是否是 revert
        if commit_info.get("is_revert"):
            return ChangeType.REVERT, 1.0
        
        # 按优先级匹配模式
        for change_type, patterns in self.PATTERNS.items():
            if change_type == ChangeType.REVERT:
                continue  # 已经检查过
            
            for pattern in patterns:
                if re.search(pattern, subject, re.IGNORECASE):
                    # 根据匹配质量计算置信度
                    confidence = 0.8
                    if change_type == ChangeType.FIXUP and commit_info.get("file_overlap"):
                        confidence = 0.95
                    return change_type, confidence
        
        # 检查文件重叠
        if commit_info.get("file_overlap"):
            return ChangeType.FOLLOW_UP, 0.6
        
        return ChangeType.UNKNOWN, 0.3
    
    def _is_revert_of(self, commit: Any, original: Any) -> bool:
        """检查 commit 是否是原补丁的 revert"""
        subject = commit.subject.lower()
        
        # 检查 subject 是否包含 revert
        if "revert" not in subject:
            return False
        
        # 检查是否引用原补丁
        original_subject = original.subject.lower()
        
        # 移除 revert 前缀进行比较
        cleaned = re.sub(r'^[\w\s]*revert["\'\s]*', '', subject)
        cleaned = re.sub(r'["\'\s]*$', '', cleaned)
        
        # 比较相似度
        if cleaned in original_subject or original_subject in cleaned:
            return True
        
        # 检查 commit body 是否引用原 hash
        try:
            commit_obj = self.repo.repo.commit(commit.hash)
            message = commit_obj.message.lower()
            if original.hash[:7] in message or original.hash in message:
                return True
        except Exception:
            pass
        
        return False
    
    def _check_message_refs(self, subject: str, original: Any) -> int:
        """检查 commit message 是否引用原补丁"""
        count = 0
        subject_lower = subject.lower()
        original_subject = original.subject.lower()
        
        # 检查原始 subject 是否被引用
        # 移除常见前缀后比较
        clean_original = re.sub(
            r'^[\w\s]*(?:revert|fixup|fix|backport)["\'\s]*',
            '',
            original_subject
        )
        clean_subject = re.sub(
            r'^[\w\s]*(?:revert|fixup|fix|backport)["\'\s]*',
            '',
            subject_lower
        )
        
        if clean_original in clean_subject or clean_subject in clean_original:
            count += 1
        
        return count
    
    def _get_commit_stats(self, commit: Any) -> Dict[str, Any]:
        """获取 commit 统计信息"""
        try:
            commit_obj = self.repo.repo.commit(commit.hash)
            stats = commit_obj.stats
            return {
                "insertions": stats.total["insertions"],
                "deletions": stats.total["deletions"],
                "lines_changed": stats.total["lines"],
                "files_changed": len(commit.files_changed),
            }
        except Exception:
            return {}
    
    def _generate_summary(self, changes: List[TrackedChange]) -> Dict[str, int]:
        """生成变更汇总"""
        summary = {t.value: 0 for t in ChangeType}
        summary["total"] = len(changes)
        
        for change in changes:
            summary[change.change_type.value] += 1
        
        return summary
    
    def _generate_description(
        self,
        change_type: ChangeType,
        commit_info: Dict[str, Any],
        original: Any
    ) -> str:
        """生成变更描述"""
        commit = commit_info["commit"]
        
        descriptions = {
            ChangeType.REVERT: f"回退了补丁: {original.subject[:50]}...",
            ChangeType.FIXUP: f"修复了补丁的问题，修改了 {len(commit_info.get('file_overlap', []))} 个文件",
            ChangeType.REFACTOR: f"重构了补丁引入的代码",
            ChangeType.BACKPORT: f"回溯移植补丁到稳定分支",
            ChangeType.CONFLICT_FIX: f"修复了合并冲突",
            ChangeType.FOLLOW_UP: f"后续相关修改",
            ChangeType.CVE_RELATED: f"CVE 相关提交: {commit_info.get('cve_context', '引用相同 CVE')}",
            ChangeType.UNKNOWN: f"可能的后续修改",
        }
        
        return descriptions.get(change_type, "未知类型修改")
    
    def _analyze_result(
        self,
        changes: List[TrackedChange],
        original: Any
    ) -> Dict[str, Any]:
        """分析追踪结果"""
        if not changes:
            return {"status": "clean", "message": "补丁后无相关修改"}
        
        # 按时间排序
        sorted_changes = sorted(changes, key=lambda c: c.commit_date)
        
        analysis = {
            "status": "modified",
            "total_changes": len(changes),
            "first_change_days": None,
            "latest_status": "unknown",
            "recommendations": [],
        }
        
        if sorted_changes:
            first_change = sorted_changes[0]
            days_diff = (first_change.commit_date - original.committer_date).days
            analysis["first_change_days"] = days_diff
        
        # 检查最新状态
        latest = sorted_changes[-1] if sorted_changes else None
        if latest:
            if latest.change_type == ChangeType.REVERT:
                analysis["latest_status"] = "reverted"
                analysis["recommendations"].append("⚠️ 补丁已被回退，需要重新评估漏洞状态")
            elif latest.change_type == ChangeType.FIXUP:
                analysis["latest_status"] = "fixed"
                analysis["recommendations"].append("✓ 补丁问题已修复")
            elif latest.change_type == ChangeType.BACKPORT:
                analysis["latest_status"] = "backported"
                analysis["recommendations"].append("✓ 补丁已回溯到稳定分支")
        
        # 统计建议
        fixup_count = len([c for c in changes if c.change_type == ChangeType.FIXUP])
        if fixup_count >= 2:
            analysis["recommendations"].append(
                f"⚠️ 补丁有 {fixup_count} 次修复，原始补丁可能存在问题"
            )
        
        # ⭐ 新增: CVE 相关提交建议
        cve_related_count = len([c for c in changes if c.change_type == ChangeType.CVE_RELATED])
        if cve_related_count > 0:
            analysis["recommendations"].append(
                f"📌 发现 {cve_related_count} 个引用相同 CVE 的相关提交，建议检查"
            )
        
        return analysis
    
    def _find_cve_related_commits(
        self,
        cve_id: str,
        exclude_commit: str,
        look_ahead: int = 200
    ) -> List[Dict[str, Any]]:
        """
        查找 commit message 中引用相同 CVE 的提交
        
        Args:
            cve_id: CVE ID，如 "CVE-2024-1234"
            exclude_commit: 要排除的原始补丁 commit
            look_ahead: 向后查找的 commit 数量
        
        Returns:
            CVE 相关提交列表
        """
        if not self.repo or not cve_id:
            return []
        
        related = []
        cve_pattern = cve_id.replace("-", "[-]?")  # 允许 CVE-2024-1234 或 CVE 2024 1234
        
        try:
            # 使用 git log 搜索包含 CVE ID 的提交
            # --grep 搜索 commit message
            commits_with_cve = self.repo.repo.git.log(
                f"{exclude_commit}..HEAD",
                f"--max-count={look_ahead}",
                "--grep", cve_id,
                "--format=%H"
            ).strip().split("\n")
            
            for commit_hash in commits_with_cve:
                if not commit_hash or commit_hash == exclude_commit:
                    continue
                
                try:
                    commit = self.repo.get_commit(commit_hash)
                    if not commit:
                        continue
                    
                    # 检查 commit message 中确实包含 CVE ID
                    if cve_id.lower() not in commit.subject.lower():
                        # 检查 body
                        try:
                            commit_obj = self.repo.repo.commit(commit_hash)
                            if cve_id.lower() not in commit_obj.message.lower():
                                continue
                        except Exception:
                            continue
                    
                    # 提取 CVE 引用的上下文
                    cve_context = self._extract_cve_context(commit, cve_id)
                    
                    related.append({
                        "commit": commit,
                        "cve_context": cve_context,
                        "relevance_score": 5,  # CVE 引用是高相关度
                        "is_cve_related": True,
                    })
                
                except Exception:
                    continue
        
        except Exception:
            pass
        
        return related
    
    def _extract_cve_context(self, commit: Any, cve_id: str) -> str:
        """提取 CVE 在 commit message 中的上下文"""
        try:
            commit_obj = self.repo.repo.commit(commit.hash)
            message = commit_obj.message
            
            # 找到 CVE ID 所在行
            lines = message.split("\n")
            for line in lines:
                if cve_id.lower() in line.lower():
                    # 返回包含 CVE ID 的行，限制长度
                    context = line.strip()
                    if len(context) > 100:
                        context = context[:97] + "..."
                    return context
            
            return f"引用 {cve_id}"
        except Exception:
            return f"引用 {cve_id}"
    
    def _analyze_cve_related_commit(
        self,
        commit_info: Dict[str, Any],
        original: Any,
        cve_id: str
    ) -> Optional[TrackedChange]:
        """分析 CVE 相关提交"""
        commit = commit_info["commit"]
        
        # 提取统计信息
        stats = self._get_commit_stats(commit)
        
        # 生成描述
        cve_context = commit_info.get("cve_context", f"引用 {cve_id}")
        description = f"CVE 相关提交: {cve_context}"
        
        return TrackedChange(
            commit_hash=commit.hash,
            commit_subject=commit.subject,
            author=commit.author_name,
            author_email=commit.author_email,
            commit_date=commit.committer_date,
            change_type=ChangeType.CVE_RELATED,
            parent_commit=commit.parents[0] if commit.parents else None,
            related_commits=[original.hash],
            files_changed=commit.files_changed,
            stats=stats,
            description=description,
            confidence=0.95,  # CVE 引用是高置信度
        )
