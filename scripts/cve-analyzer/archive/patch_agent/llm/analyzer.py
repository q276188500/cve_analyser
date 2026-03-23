# LLM Analyzer - LLM 增强分析

import os
from typing import Dict, Any, Optional
from dataclasses import dataclass

from .provider import LLMProvider, LLMFactory, get_default_provider


@dataclass
class LLMAnalysisResult:
    """LLM 分析结果"""
    summary: str
    functional_impact: Dict[str, Any]
    performance_impact: Dict[str, Any]
    security_impact: Dict[str, Any]
    compatibility_impact: Dict[str, Any]
    recommendation: Dict[str, Any]
    risk_factors: list
    business_impact: str
    
    # 元数据
    model: str = ""
    tokens_used: int = 0
    cost: float = 0.0


class LLMAnalyzer:
    """LLM 增强分析器"""
    
    def __init__(self, provider: LLMProvider = None):
        self.provider = provider or get_default_provider()
    
    def is_available(self) -> bool:
        """检查 LLM 是否可用"""
        return self.provider is not None
    
    def analyze(self, patch_content: str, context: Dict) -> Optional[LLMAnalysisResult]:
        """使用 LLM 分析 patch"""
        
        if not self.provider:
            return None
        
        try:
            result = self.provider.analyze_patch(patch_content, context)
            
            if result.get("error"):
                print(f"LLM Error: {result.get('error')}")
                return None
            
            # 解析结果
            llm_result = LLMAnalysisResult(
                summary=result.get("summary", ""),
                functional_impact=result.get("functional_impact", {}),
                performance_impact=result.get("performance_impact", {}),
                security_impact=result.get("security_impact", {}),
                compatibility_impact=result.get("compatibility_impact", {}),
                recommendation=result.get("recommendation", {}),
                risk_factors=result.get("risk_factors", []),
                business_impact=result.get("business_impact", ""),
                model=result.get("_llm_metadata", {}).get("model", ""),
                tokens_used=result.get("_llm_metadata", {}).get("tokens", 0),
                cost=result.get("_llm_metadata", {}).get("cost", 0)
            )
            
            return llm_result
            
        except Exception as e:
            print(f"LLM Analysis Error: {e}")
            return None
    
    def to_dict(self, result: LLMAnalysisResult) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "summary": result.summary,
            "functional_impact": result.functional_impact,
            "performance_impact": result.performance_impact,
            "security_impact": result.security_impact,
            "compatibility_impact": result.compatibility_impact,
            "recommendation": result.recommendation,
            "risk_factors": result.risk_factors,
            "business_impact": result.business_impact,
            "_llm_metadata": {
                "model": result.model,
                "tokens_used": result.tokens_used,
                "cost_usd": result.cost
            }
        }


def analyze_with_llm(patch_content: str, context: Dict, provider: str = None) -> Optional[LLMAnalysisResult]:
    """便捷函数：使用 LLM 分析"""
    
    if provider:
        llm_provider = LLMFactory.create(provider)
    else:
        llm_provider = get_default_provider()
    
    if not llm_provider:
        print("Warning: No LLM provider available")
        return None
    
    analyzer = LLMAnalyzer(llm_provider)
    return analyzer.analyze(patch_content, context)
