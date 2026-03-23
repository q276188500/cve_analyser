# Impact Analyzer - 影响分析器

import json
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime

from .parser import PatchInfo, FileChange, FunctionChange
from ..knowledge.base import KnowledgeBase, KnowledgeRule


# 尝试导入 LLM 模块
try:
    from ..llm.analyzer import LLMAnalyzer, analyze_with_llm
    LLM_AVAILABLE = True
except ImportError:
    LLM_AVAILABLE = False
    LLMAnalyzer = None
    analyze_with_llm = None


@dataclass
class ImpactAssessment:
    """影响评估结果"""
    level: str  # high, medium, low
    description: str
    risk_factors: List[str] = field(default_factory=list)
    cve_fixes: List[str] = field(default_factory=list)  # 安全分析专用


@dataclass
class AnalysisResult:
    """完整分析结果"""
    # 元数据
    analyzer_version: str = "0.1.0"
    timestamp: str = ""
    input_type: str = "diff_string"
    llm_enabled: bool = False  # 是否启用了 LLM
    
    # Patch 摘要
    files_changed: List[str] = field(default_factory=list)
    lines_added: int = 0
    lines_deleted: int = 0
    commit: Optional[str] = None
    
    # 各项影响评估
    functional_impact: ImpactAssessment = None
    performance_impact: ImpactAssessment = None
    security_impact: ImpactAssessment = None
    compatibility_impact: ImpactAssessment = None
    
    # 知识库匹配
    knowledge_matches: List[Dict[str, Any]] = field(default_factory=list)
    
    # 合入建议
    recommendation: Dict[str, Any] = field(default_factory=dict)
    
    # LLM 分析结果
    llm_result: Optional[Dict[str, Any]] = field(default_factory=dict)
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.utcnow().isoformat() + "Z"
        if self.functional_impact is None:
            self.functional_impact = ImpactAssessment(level="low", description="")
        if self.performance_impact is None:
            self.performance_impact = ImpactAssessment(level="low", description="")
        if self.security_impact is None:
            self.security_impact = ImpactAssessment(level="low", description="")
        if self.compatibility_impact is None:
            self.compatibility_impact = ImpactAssessment(level="low", description="")


class ImpactAnalyzer:
    """影响分析器"""
    
    def __init__(self, knowledge_base: KnowledgeBase = None):
        self.kb = knowledge_base or KnowledgeBase()
    
    def analyze(self, patch_info: PatchInfo, use_llm: bool = False, llm_provider: str = None) -> AnalysisResult:
        """执行完整分析
        
        Args:
            patch_info: 解析后的 patch 信息
            use_llm: 是否使用 LLM 增强分析
            llm_provider: LLM 提供商 (openai/claude/ollama)
        """
        result = AnalysisResult()
        
        # 1. 提取 Patch 摘要
        result.files_changed = [f.path for f in patch_info.files]
        result.lines_added = sum(f.additions for f in patch_info.files)
        result.lines_deleted = sum(f.deletions for f in patch_info.files)
        result.commit = patch_info.commit_hash
        
        # 2. 检索知识库
        result.knowledge_matches = self._search_knowledge(patch_info)
        
        # 3. 规则引擎分析 (基础分析)
        result.functional_impact = self._analyze_functional(patch_info, result.knowledge_matches)
        result.performance_impact = self._analyze_performance(patch_info, result.knowledge_matches)
        result.security_impact = self._analyze_security(patch_info, result.knowledge_matches)
        result.compatibility_impact = self._analyze_compatibility(patch_info, result.knowledge_matches)
        
        # 4. 生成合入建议 (基于规则)
        result.recommendation = self._generate_recommendation(result)
        
        # 5. LLM 增强分析 (可选)
        if use_llm and LLM_AVAILABLE:
            result = self._analyze_with_llm(patch_info.raw, result, llm_provider)
        
        return result
    
    def _analyze_with_llm(self, raw_patch: str, result: AnalysisResult, provider: str = None) -> AnalysisResult:
        """使用 LLM 进行深度分析"""
        
        if not LLM_AVAILABLE:
            return result
        
        # 构建上下文
        context = {
            "files_changed": result.files_changed,
            "lines_added": result.lines_added,
            "lines_deleted": result.lines_deleted,
            "commit": result.commit,
            "knowledge_matches": result.knowledge_matches,
            "rule_based_recommendation": result.recommendation
        }
        
        # 调用 LLM
        llm_result = analyze_with_llm(raw_patch, context, provider)
        
        if llm_result:
            result.llm_enabled = True
            result.llm_result = {
                "summary": llm_result.summary,
                "functional_impact": llm_result.functional_impact,
                "performance_impact": llm_result.performance_impact,
                "security_impact": llm_result.security_impact,
                "compatibility_impact": llm_result.compatibility_impact,
                "recommendation": llm_result.recommendation,
                "risk_factors": llm_result.risk_factors,
                "business_impact": llm_result.business_impact,
                "_metadata": {
                    "model": llm_result.model,
                    "tokens": llm_result.tokens_used,
                    "cost": llm_result.cost
                }
            }
            
            # 如果 LLM 给出了建议，用 LLM 的建议覆盖规则引擎的建议
            if llm_result.recommendation.get("action"):
                result.recommendation = {
                    "source": "llm",
                    "action": llm_result.recommendation.get("action", "review"),
                    "reason": llm_result.recommendation.get("reason", ""),
                    "confidence": llm_result.recommendation.get("confidence", 0.5),
                    "requires_review": llm_result.recommendation.get("requires_expertise_review", False)
                }
        
        return result
    
    def _search_knowledge(self, patch_info: PatchInfo) -> List[Dict[str, Any]]:
        """搜索知识库"""
        matches = []
        
        for file_change in patch_info.files:
            # 按路径搜索
            rules = self.kb.search_by_path(file_change.path)
            for rule in rules:
                matches.append({
                    "rule_id": rule.id,
                    "title": rule.title,
                    "severity": rule.severity,
                    "type": rule.type,
                    "matched_file": file_change.path,
                    "description": rule.description[:200]  # 截断
                })
        
        # 去重
        seen = set()
        unique_matches = []
        for m in matches:
            if m['rule_id'] not in seen:
                seen.add(m['rule_id'])
                unique_matches.append(m)
        
        return unique_matches
    
    def _analyze_functional(self, patch_info: PatchInfo, knowledge_matches: List[Dict]) -> ImpactAssessment:
        """分析功能影响"""
        level = "low"
        risk_factors = []
        descriptions = []
        
        # 检查文件变更
        for f in patch_info.files:
            if f.change_type == "add":
                descriptions.append(f"新增文件 {f.path}")
                level = self._bump_level(level, "medium")
            elif f.change_type == "delete":
                descriptions.append(f"删除文件 {f.path}")
                risk_factors.append("删除文件可能影响功能")
                level = self._bump_level(level, "high")
        
        # 检查知识库约束
        for match in knowledge_matches:
            if match.get('severity') == 'critical':
                risk_factors.append(f"违反约束: {match.get('title')}")
                level = "high"
        
        # 检查函数变更
        functions = self._extract_function_names(patch_info)
        if functions:
            descriptions.append(f"涉及函数: {', '.join(functions[:3])}")
        
        return ImpactAssessment(
            level=level,
            description="; ".join(descriptions) if descriptions else "变更范围可控",
            risk_factors=risk_factors
        )
    
    def _analyze_performance(self, patch_info: PatchInfo, knowledge_matches: List[Dict]) -> ImpactAssessment:
        """分析性能影响"""
        level = "low"
        descriptions = []
        risk_factors = []
        
        # 简单启发式: 检查是否涉及性能关键路径
        perf_critical_paths = [
            "net/core/*",
            "drivers/virtio/*",
            "io_uring/*",
            "mm/*.c",
            "fs/buffer.c",
        ]
        
        for f in patch_info.files:
            for pattern in perf_critical_paths:
                if pattern.replace('*', '') in f.path:
                    descriptions.append(f"涉及性能关键路径: {f.path}")
                    level = "medium"
        
        # 检查内存分配相关
        raw = patch_info.raw.lower()
        if 'kmalloc' in raw or 'vmalloc' in raw or 'alloc' in raw:
            descriptions.append("涉及内存分配操作")
        
        # 检查循环
        if 'for (' in raw or 'while (' in raw:
            descriptions.append("涉及循环操作")
        
        return ImpactAssessment(
            level=level,
            description="; ".join(descriptions) if descriptions else "未发现明显性能影响",
            risk_factors=risk_factors
        )
    
    def _analyze_security(self, patch_info: PatchInfo, knowledge_matches: List[Dict]) -> ImpactAssessment:
        """分析安全影响"""
        level = "low"
        descriptions = []
        risk_factors = []
        cve_fixes = []
        
        raw = patch_info.raw
        
        # 检测安全相关关键词
        security_keywords = {
            'use-after-free': 'use-after-free 漏洞',
            'buffer overflow': '缓冲区溢出',
            'out-of-bounds': '越界访问',
            'privilege escalation': '权限提升',
            'cve-': 'CVE 修复',
            'security fix': '安全修复',
            'sanitize': '安全加固',
            'capability': '能力检查',
        }
        
        for keyword, desc in security_keywords.items():
            if keyword in raw.lower():
                descriptions.append(desc)
                if 'cve-' in keyword:
                    cve_fixes.append(keyword.upper())
                level = "high"
        
        # 检查知识库中的安全约束
        for match in knowledge_matches:
            if match.get('type') == 'constraint' and 'security' in match.get('title', '').lower():
                risk_factors.append(f"安全约束: {match.get('title')}")
                level = "high"
        
        return ImpactAssessment(
            level=level,
            description="; ".join(descriptions) if descriptions else "未发现明显安全风险",
            risk_factors=risk_factors,
            cve_fixes=cve_fixes  # 扩展字段
        )
    
    def _analyze_compatibility(self, patch_info: PatchInfo, knowledge_matches: List[Dict]) -> ImpactAssessment:
        """分析兼容性影响"""
        level = "low"
        descriptions = []
        risk_factors = []
        
        for f in patch_info.files:
            # API 相关文件
            if 'EXPORT_SYMBOL' in f.path or 'EXPORT_SYMBOL' in f.path:
                risk_factors.append("涉及内核导出符号")
                level = "medium"
        
        # 检查知识库中的 API 约束
        for match in knowledge_matches:
            if 'api' in match.get('title', '').lower() or 'symbol' in match.get('title', '').lower():
                risk_factors.append(f"API 影响: {match.get('title')}")
                level = "high"
        
        return ImpactAssessment(
            level=level,
            description="; ".join(descriptions) if descriptions else "未发现明显兼容性问题",
            risk_factors=risk_factors
        )
    
    def _extract_function_names(self, patch_info: PatchInfo) -> List[str]:
        """提取函数名"""
        names = []
        for f in patch_info.files:
            for hunk in f.hunks:
                # 简单函数名提取
                import re
                for line in hunk.content.split('\n'):
                    match = re.search(r'\b(\w+)\s*\([^)]*\)\s*\{', line)
                    if match:
                        names.append(match.group(1))
        return list(set(names))
    
    def _bump_level(self, current: str, new: str) -> str:
        """提升影响等级"""
        levels = {'low': 0, 'medium': 1, 'high': 2}
        return new if levels.get(new, 0) > levels.get(current, 0) else current
    
    def _generate_recommendation(self, result: AnalysisResult) -> Dict[str, Any]:
        """生成合入建议"""
        # 计算综合评分
        score = 0
        factors = []
        
        # 安全影响权重最高
        if result.security_impact.level == 'high':
            score += 2
            factors.append("安全修复")
        elif result.security_impact.level == 'medium':
            score += 1
        
        # 功能影响
        if result.functional_impact.level == 'high':
            score -= 1
            factors.append("功能影响较大")
        elif result.functional_impact.level == 'medium':
            score += 0
        
        # 兼容性
        if result.compatibility_impact.level == 'high':
            score -= 2
            factors.append("可能破坏兼容性")
        elif result.compatibility_impact.level == 'medium':
            score -= 1
        
        # 知识库约束
        critical_violations = sum(
            1 for m in result.knowledge_matches 
            if m.get('severity') == 'critical'
        )
        if critical_violations > 0:
            score -= 3
            factors.append(f"违反 {critical_violations} 条关键约束")
        
        # 判断建议
        requires_review = False
        if score >= 2:
            action = "merge"
            reason = "建议合入，影响正面"
        elif score >= 0:
            action = "review"
            reason = "建议 review 后合入"
            requires_review = True
        else:
            action = "defer"
            reason = "暂不建议合入，需进一步评估"
            requires_review = True
        
        # 如果有 critical 约束违反，强制要求 review
        if critical_violations > 0:
            action = "defer"
            reason = f"违反关键约束 ({critical_violations} 条)，必须安全团队审批"
            requires_review = True
        
        return {
            "action": action,
            "confidence": min(abs(score) / 3, 1.0),
            "reason": reason + ("; " + "; ".join(factors) if factors else ""),
            "requires_review": requires_review,
            "score": score
        }


def analyze_patch(patch_content: str, knowledge_base: KnowledgeBase = None) -> AnalysisResult:
    """便捷函数：分析 patch"""
    from .parser import PatchParser
    
    parser = PatchParser()
    patch_info = parser.parse(patch_content)
    
    analyzer = ImpactAnalyzer(knowledge_base)
    return analyzer.analyze(patch_info)
