"""
LLM 漏洞分析器

使用大模型进行智能 CVE 分析和报告生成
"""

import json
from typing import Dict, Any, Optional
from dataclasses import asdict

from cve_analyzer.llm.base import LLMProvider, LLMResponse
from cve_analyzer.core.models import CVE


class LLMVulnerabilityAnalyzer:
    """LLM 漏洞分析器"""
    
    def __init__(self, provider: LLMProvider):
        self.provider = provider
    
    async def analyze_cve(self, cve: CVE) -> Dict[str, Any]:
        """
        分析 CVE 并返回结构化结果
        
        Returns:
            {
                "summary": "中文漏洞摘要",
                "attack_scenario": "攻击场景描述",
                "affected_components": ["组件列表"],
                "exploit_difficulty": "难度评估",
                "mitigation": "缓解措施",
                "similar_cves": ["类似漏洞"],
            }
        """
        messages = [
            {
                "role": "system",
                "content": """你是一个专业的 Linux 内核安全分析专家。
请分析给定的 CVE 漏洞，并以 JSON 格式输出分析结果。

输出格式:
{
    "summary": "一句话中文漏洞摘要",
    "attack_scenario": "详细的攻击场景描述",
    "affected_components": ["受影响的组件/子系统"],
    "exploit_difficulty": "LOW/MEDIUM/HIGH",
    "prerequisites": ["攻击所需条件"],
    "mitigation": "缓解措施建议",
    "patch_complexity": "补丁复杂度评估",
    "similar_cves": ["可能相关的类似漏洞类型"]
}"""
            },
            {
                "role": "user",
                "content": f"""请分析以下 CVE 漏洞：

CVE ID: {cve.id}
严重程度: {cve.severity}
CVSS 评分: {cve.cvss_score}
描述: {cve.description}

请提供详细的结构化分析。"""
            }
        ]
        
        response = await self.provider.chat(messages, temperature=0.3, max_tokens=2000)
        
        # 解析 JSON 响应
        try:
            result = json.loads(response.content)
            result["_metadata"] = {
                "model": response.model,
                "tokens_used": response.tokens_used,
                "cost_usd": response.cost_usd,
            }
            return result
        except json.JSONDecodeError:
            # 如果不是有效 JSON，包装原始响应
            return {
                "summary": response.content[:500],
                "raw_analysis": response.content,
                "_metadata": {
                    "model": response.model,
                    "tokens_used": response.tokens_used,
                    "cost_usd": response.cost_usd,
                }
            }
    
    async def generate_report(self, cve: CVE, analysis: Optional[Dict] = None) -> str:
        """
        生成中文漏洞报告
        
        Returns:
            Markdown 格式的报告
        """
        if analysis is None:
            analysis = await self.analyze_cve(cve)
        
        messages = [
            {
                "role": "system",
                "content": """你是一个专业的安全报告撰写专家。
请将 CVE 分析结果转换为格式化的中文 Markdown 报告。
报告应该专业、清晰、适合技术人员阅读。"""
            },
            {
                "role": "user",
                "content": f"""基于以下 CVE 信息生成报告：

CVE ID: {cve.id}
严重程度: {cve.severity}
CVSS: {cve.cvss_score}
描述: {cve.description}

分析结果:
{json.dumps(analysis, indent=2, ensure_ascii=False)}

请生成格式化的 Markdown 报告，包含：
1. 漏洞概述
2. 技术细节
3. 影响评估
4. 修复建议
5. 参考信息"""
            }
        ]
        
        response = await self.provider.chat(messages, temperature=0.4, max_tokens=3000)
        return response.content
    
    async def analyze_patch(self, patch_content: str, context: str = "") -> Dict[str, Any]:
        """
        分析补丁代码
        
        Args:
            patch_content: 补丁 diff 内容
            context: 额外上下文
        
        Returns:
            补丁分析结果
        """
        messages = [
            {
                "role": "system",
                "content": """你是一个 Linux 内核代码审查专家。
请分析给定的安全补丁，识别修复的漏洞类型和潜在影响。"""
            },
            {
                "role": "user",
                "content": f"""{context}

请分析以下补丁：

```diff
{patch_content[:8000]}  # 限制长度避免超出 token 限制
```

请以 JSON 格式输出：
{{
    "vulnerability_type": "漏洞类型 (如 use-after-free, buffer overflow)",
    "root_cause": "根本原因分析",
    "fix_approach": "修复方法",
    "affected_functions": ["受影响的函数"],
    "side_effects": "可能的副作用",
    "test_suggestions": ["测试建议"]
}}"""
            }
        ]
        
        response = await self.provider.chat(messages, temperature=0.3, max_tokens=2000)
        
        try:
            return json.loads(response.content)
        except json.JSONDecodeError:
            return {"raw_analysis": response.content}


class LLMReportGenerator:
    """LLM 增强的报告生成器"""
    
    def __init__(self, provider: LLMProvider):
        self.provider = provider
    
    async def generate_executive_summary(self, cves: list) -> str:
        """
        生成管理层摘要
        
        将技术性的 CVE 列表转换为适合管理层阅读的业务风险摘要
        """
        cve_data = []
        for cve in cves[:20]:  # 限制数量避免 token 超限
            cve_data.append({
                "id": cve.id,
                "severity": cve.severity,
                "cvss": cve.cvss_score,
                "description": cve.description[:200] if cve.description else "",
            })
        
        messages = [
            {
                "role": "system",
                "content": """你是一个安全顾问，专门为高管撰写安全风险摘要。
请将技术性的 CVE 列表转换为业务风险语言，突出关键风险和建议。"""
            },
            {
                "role": "user",
                "content": f"""请为以下 CVE 漏洞列表生成执行摘要：

CVE 数据:
{json.dumps(cve_data, indent=2, ensure_ascii=False)}

请生成中文执行摘要，包含：
1. 整体风险概况
2. 关键漏洞（TOP 3）
3. 业务影响评估
4. 建议行动计划
5. 时间线建议"""
            }
        ]
        
        response = await self.provider.chat(messages, temperature=0.4, max_tokens=2500)
        return response.content
