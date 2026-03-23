"""
历史分析器

提供补丁历史的高级分析功能
"""

from typing import List, Optional, Dict, Any, Tuple
from datetime import datetime, timedelta

from cve_analyzer.history.base import HistoryResult, TrackedChange, ChangeType
from cve_analyzer.history.tracker import GitHistoryTracker


class HistoryAnalyzer:
    """补丁历史分析器"""
    
    def __init__(self, tracker: Optional[GitHistoryTracker] = None):
        """
        初始化分析器
        
        Args:
            tracker: 历史追踪器实例
        """
        self.tracker = tracker or GitHistoryTracker()
    
    def analyze(self, patch_commit: str, cve_id: Optional[str] = None) -> HistoryResult:
        """
        执行完整的历史分析
        
        Args:
            patch_commit: 补丁 commit hash
            cve_id: 可选的 CVE ID
        
        Returns:
            带额外分析结果的历史追踪结果
        """
        result = self.tracker.track(patch_commit, cve_id)
        
        # 添加趋势分析
        result.analysis["trends"] = self._analyze_trends(result.changes)
        
        # 添加风险评估
        result.analysis["risk_assessment"] = self._assess_risk(result)
        
        # 添加时间线
        result.analysis["timeline"] = self._build_timeline(result)
        
        return result
    
    def batch_analyze(
        self,
        patches: List[Tuple[str, Optional[str]]]
    ) -> List[HistoryResult]:
        """
        批量分析多个补丁
        
        Args:
            patches: [(patch_commit, cve_id), ...]
        
        Returns:
            历史追踪结果列表
        """
        results = []
        for patch_commit, cve_id in patches:
            try:
                result = self.analyze(patch_commit, cve_id)
                results.append(result)
            except Exception as e:
                # 记录错误但继续处理其他补丁
                results.append(HistoryResult(
                    cve_id=cve_id or "UNKNOWN",
                    patch_commit=patch_commit,
                    original_subject="ERROR",
                    changes=[],
                    summary={"error": str(e)},
                ))
        return results
    
    def compare_branches(
        self,
        patch_commit: str,
        branches: List[str],
        cve_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        比较补丁在不同分支的历史
        
        Args:
            patch_commit: 补丁 commit hash
            branches: 要比较的分支列表
            cve_id: 可选的 CVE ID
        
        Returns:
            分支比较结果
        """
        comparison = {
            "patch_commit": patch_commit,
            "cve_id": cve_id,
            "branches": {},
            "summary": {},
        }
        
        original_branch = self.tracker.repo.get_current_branch()
        
        try:
            for branch in branches:
                try:
                    # 切换到分支
                    self.tracker.repo.checkout_branch(branch)
                    
                    # 追踪历史
                    result = self.tracker.track(patch_commit, cve_id)
                    
                    comparison["branches"][branch] = {
                        "status": result.get_latest_status(),
                        "change_count": len(result.changes),
                        "has_revert": result.has_revert(),
                        "has_fixups": result.has_fixups(),
                    }
                except Exception as e:
                    comparison["branches"][branch] = {"error": str(e)}
        
        finally:
            # 恢复原始分支
            if original_branch:
                try:
                    self.tracker.repo.checkout_branch(original_branch)
                except Exception:
                    pass
        
        # 生成汇总
        comparison["summary"] = self._summarize_comparison(comparison["branches"])
        
        return comparison
    
    def _analyze_trends(self, changes: List[TrackedChange]) -> Dict[str, Any]:
        """分析变更趋势"""
        if not changes:
            return {"status": "no_data"}
        
        # 按时间排序
        sorted_changes = sorted(changes, key=lambda c: c.commit_date)
        
        trends = {
            "total_changes": len(changes),
            "time_span_days": None,
            "change_frequency": {},
            "type_distribution": {},
        }
        
        # 计算时间跨度
        if len(sorted_changes) >= 2:
            time_span = sorted_changes[-1].commit_date - sorted_changes[0].commit_date
            trends["time_span_days"] = time_span.days
        
        # 变更类型分布
        for change in changes:
            change_type = change.change_type.value
            trends["type_distribution"][change_type] = \
                trends["type_distribution"].get(change_type, 0) + 1
        
        # 计算频率（每月变更数）
        if trends["time_span_days"] and trends["time_span_days"] > 0:
            months = trends["time_span_days"] / 30.0
            trends["changes_per_month"] = len(changes) / max(months, 1)
        
        return trends
    
    def _assess_risk(self, result: HistoryResult) -> Dict[str, Any]:
        """评估风险"""
        risk = {
            "level": "low",
            "score": 0,
            "factors": [],
            "mitigations": [],
        }
        
        changes = result.changes
        
        # 检查 revert
        if result.has_revert():
            risk["score"] += 50
            risk["factors"].append("补丁已被回退")
            risk["mitigations"].append("需要重新评估漏洞是否仍然有效")
        
        # 检查多次 fixup
        fixup_count = len([c for c in changes if c.change_type == ChangeType.FIXUP])
        if fixup_count >= 3:
            risk["score"] += 30
            risk["factors"].append(f"补丁有 {fixup_count} 次修复，原始实现可能不稳定")
        elif fixup_count > 0:
            risk["score"] += 10
            risk["factors"].append(f"补丁有 {fixup_count} 次修复")
        
        # 检查是否有 conflict fix
        conflict_count = len([c for c in changes if c.change_type == ChangeType.CONFLICT_FIX])
        if conflict_count > 0:
            risk["score"] += 15
            risk["factors"].append(f"补丁有 {conflict_count} 次冲突修复")
        
        # ⭐ 新增: 检查 CVE 相关提交
        cve_related_count = len([c for c in changes if c.change_type == ChangeType.CVE_RELATED])
        if cve_related_count > 0:
            risk["factors"].append(f"发现 {cve_related_count} 个 CVE 相关提交，可能包含补充修复或说明")
        
        # 确定风险等级
        if risk["score"] >= 50:
            risk["level"] = "high"
        elif risk["score"] >= 20:
            risk["level"] = "medium"
        
        return risk
    
    def _build_timeline(self, result: HistoryResult) -> List[Dict[str, Any]]:
        """构建时间线"""
        timeline = []
        
        # 添加原始补丁
        timeline.append({
            "date": None,  # 会在外部填充
            "type": "original",
            "commit": result.patch_commit,
            "subject": result.original_subject,
            "description": "原始补丁提交",
        })
        
        # 添加变更
        for change in sorted(result.changes, key=lambda c: c.commit_date):
            timeline.append({
                "date": change.commit_date.isoformat(),
                "type": change.change_type.value,
                "commit": change.commit_hash,
                "subject": change.commit_subject,
                "author": change.author,
                "description": change.description,
                "confidence": change.confidence,
            })
        
        return timeline
    
    def _summarize_comparison(self, branches: Dict[str, Any]) -> Dict[str, Any]:
        """汇总分支比较结果"""
        summary = {
            "total_branches": len(branches),
            "reverted_in": [],
            "fixed_in": [],
            "clean_in": [],
            "issues": [],
        }
        
        for branch, info in branches.items():
            if "error" in info:
                summary["issues"].append(f"{branch}: {info['error']}")
                continue
            
            status = info.get("status", "unknown")
            
            if status == "reverted":
                summary["reverted_in"].append(branch)
            elif status == "fixed":
                summary["fixed_in"].append(branch)
            elif status == "original" or info.get("change_count", 0) == 0:
                summary["clean_in"].append(branch)
        
        return summary
    
    def export_to_db(self, result: HistoryResult, db_session) -> bool:
        """
        导出历史追踪结果到数据库
        
        Args:
            result: 历史追踪结果
            db_session: 数据库会话
        
        Returns:
            是否成功
        """
        from cve_analyzer.core.models import PatchHistory
        
        try:
            for change in result.changes:
                history = PatchHistory(
                    cve_id=result.cve_id,
                    patch_id=None,  # 需要通过 commit hash 查找
                    change_type=change.change_type.value,
                    commit_hash=change.commit_hash,
                    commit_subject=change.commit_subject,
                    author=change.author,
                    commit_date=change.commit_date,
                    parent_commit=change.parent_commit,
                    related_to=result.patch_commit,
                    description=change.description,
                    files_changed=change.files_changed,
                    impact=self._determine_impact(change),
                )
                db_session.add(history)
            
            db_session.commit()
            return True
        
        except Exception as e:
            db_session.rollback()
            return False
    
    def _determine_impact(self, change: TrackedChange) -> str:
        """确定变更影响级别"""
        if change.change_type == ChangeType.REVERT:
            return "critical"
        elif change.change_type == ChangeType.FIXUP:
            return "high" if change.confidence > 0.9 else "medium"
        elif change.change_type == ChangeType.REFACTOR:
            return "low"
        else:
            return "unknown"
