#!/usr/bin/env python3
"""
CVE Review Skill - 工具

本工具是 CVE Review SKILL 的组成部分，用于：
- 从 NVD 获取 CVE 数据
- 生成 LLM 分析所需的 Prompt

使用方法：
    python tools/cve_review.py CVE-2024-XXXX

注意：本工具仅用于数据获取，实际分析由 OpenCLAW Agent 完成。
"""

import os
import sys
import json
import re
import requests
from dataclasses import dataclass
from typing import Optional, Dict, Any, List
from datetime import datetime


# CVE 数据获取
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


@dataclass
class CVEData:
    """CVE 数据"""
    cve_id: str
    description: str
    severity: str
    cvss_score: float
    published: str
    references: List[str]
    weaknesses: List[str]
    configurations: List[str]
    weaknesses: List[str]
    configurations: List[str]


class CVEFetcher:
    """CVE 数据获取"""
    
    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.environ.get("NVD_API_KEY")
        self.session = requests.Session()
        if self.api_key:
            self.session.headers["apiKey"] = self.api_key
    
    def fetch(self, cve_id: str) -> Optional[CVEData]:
        """获取 CVE 数据"""
        try:
            # 从 NVD 获取
            url = f"{NVD_API_URL}?cveId={cve_id}"
            resp = self.session.get(url, timeout=30)
            
            if resp.status_code != 200:
                print(f"NVD API error: {resp.status_code}")
                return None
            
            data = resp.json()
            vulnerabilities = data.get("vulnerabilities", [])
            
            if not vulnerabilities:
                return None
            
            cve_data = vulnerabilities[0]["cve"]
            
            # 提取描述
            descriptions = cve_data.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break
            
            # 提取严重程度
            severity = "UNKNOWN"
            cvss_score = 0.0
            metrics = cve_data.get("metrics", {})
            
            if "cvssMetricV31" in metrics:
                cvss = metrics["cvssMetricV31"][0]["cvssData"]
                severity = cvss.get("baseSeverity", "UNKNOWN")
                cvss_score = cvss.get("baseScore", 0.0)
            elif "cvssMetricV30" in metrics:
                cvss = metrics["cvssMetricV30"][0]["cvssData"]
                severity = cvss.get("baseSeverity", "UNKNOWN")
                cvss_score = cvss.get("baseScore", 0.0)
            
            # 提取引用
            references = [ref["url"] for ref in cve_data.get("references", [])]
            
            # 提取弱点 (CWE)
            weaknesses = []
            for problem in cve_data.get("problemtype", {}).get("problemtypeData", []):
                for desc in problem.get("description", []):
                    if desc.get("lang") == "en":
                        weaknesses.append(desc.get("value", ""))
            
            # 提取配置
            configurations = []
            for node in cve_data.get("configurations", []):
                for c in node.get("nodes", []):
                    for cp in c.get("cpeMatch", []):
                        configurations.append(cp.get("criteria", ""))
            
            return CVEData(
                cve_id=cve_id,
                description=description,
                severity=severity,
                cvss_score=cvss_score,
                published=cve_data.get("published", ""),
                references=references[:5],  # 限制数量
                weaknesses=weaknesses,
                configurations=configurations[:10]
            )
            
        except Exception as e:
            print(f"Error fetching CVE: {e}")
            return None


class LLMCVEAnalyzer:
    """LLM CVE 分析器"""
    
    def __init__(self, model: str = None):
        self.model = model or "default"
    
    def analyze(self, cve: CVEData, patch: str = None) -> Dict[str, Any]:
        """使用 LLM 分析 CVE"""
        
        # 构建 prompt
        prompt = self._build_prompt(cve, patch)
        
        # 这里应该调用实际的 LLM
        # 为了演示，返回一个结构化的分析框架
        
        return {
            "summary": "",
            "analysis": {
                "functional_impact": {"level": "", "description": ""},
                "performance_impact": {"level": "", "description": ""},
                "security_impact": {"level": "", "description": ""},
                "compatibility_impact": {"level": "", "description": ""}
            },
            "recommendation": {"action": "", "reason": ""},
            "llm_prompt": prompt  # 返回 prompt供调用方使用
        }
    
    def _build_prompt(self, cve: CVEData, patch: str = None) -> str:
        """构建 LLM 分析 prompt"""
        
        base_info = f"""
请分析以下 CVE 漏洞：

## CVE 信息
- ID: {cve.cve_id}
- 严重程度: {cve.severity} (CVSS: {cve.cvss_score})
- 披露日期: {cve.published}
- 描述: {cve.description}

- CWE: {', '.join(cve.weaknesses) if cve.weaknesses else 'N/A'}
"""
        
        patch_info = ""
        if patch:
            patch_info = f"""
## 补丁内容
```
{patch[:5000]}
```
"""
        
        question = """
请给出：
1. 一句话概括这个漏洞
2. 对业务的功能影响 (高/中/低 + 描述)
3. 对业务的性能影响 (高/中/低 + 描述)
4. 对业务的安全影响 (高/中/低 + 描述)
5. 兼容性影响 (高/中/低 + 描述)
6. 合入建议 (合入/谨慎/暂不合入 + 理由)

请用中文回复。
"""
        
        return base_info + patch_info + question


def review_cve(cve_id: str, patch: str = None) -> Dict[str, Any]:
    """CVE 审查主函数"""
    
    print(f"🔍 审查 CVE: {cve_id}")
    
    # 1. 获取 CVE 数据
    print("📥 获取 CVE 数据...")
    fetcher = CVEFetcher()
    cve_data = fetcher.fetch(cve_id)
    
    if not cve_data:
        return {"error": f"无法获取 CVE {cve_id} 的数据"}
    
    # 2. 构建分析 (返回 prompt，实际分析由 OpenClaw 调用 LLM)
    print("🤖 构建分析...")
    analyzer = LLMCVEAnalyzer()
    result = analyzer.analyze(cve_data, patch)
    
    # 3. 返回结构化结果
    return {
        "cve_id": cve_data.cve_id,
        "severity": cve_data.severity,
        "cvss_score": cve_data.cvss_score,
        "description": cve_data.description,
        "published": cve_data.published,
        "weaknesses": cve_data.weaknesses,
        "references": cve_data.references,
        "llm_prompt": result["llm_prompt"],
        "recommendation": result["recommendation"]
    }


def format_report(data: Dict[str, Any]) -> str:
    """格式化报告"""
    
    lines = []
    lines.append("")
    lines.append("╔════════════════════════════════════════════════════════════╗")
    lines.append("║          🔍 CVE 漏洞审查报告                              ║")
    lines.append("╚════════════════════════════════════════════════════════════╝")
    lines.append("")
    lines.append(f"📋 CVE: {data['cve_id']}")
    lines.append(f"📊 严重程度: {data['severity']} ({data['cvss_score']})")
    lines.append(f"📅 披露日期: {data['published']}")
    lines.append("")
    lines.append("📌 漏洞描述")
    lines.append(f"   {data['description'][:200]}...")
    lines.append("")
    
    if data.get('weaknesses'):
        lines.append(f"📌 CWE: {', '.join(data['weaknesses'])}")
        lines.append("")
    
    # LLM 分析部分需要后续填充
    lines.append("📌 影响评估")
    lines.append("   (请使用 /reasoning 或配置 LLM 进行深度分析)")
    lines.append("")
    
    lines.append("📌 合入建议")
    lines.append("   (LLM 分析后生成)")
    lines.append("")
    
    return "\n".join(lines)


if __name__ == "__main__":
    # 命令行测试
    if len(sys.argv) > 1:
        cve_id = sys.argv[1]
        result = review_cve(cve_id)
        
        if "error" in result:
            print(f"❌ {result['error']}")
        else:
            print(format_report(result))
            print("\n📝 LLM 分析 Prompt:")
            print("-" * 40)
            print(result["llm_prompt"])
    else:
        print("Usage: python cve_review.py CVE-2024-XXXX")
