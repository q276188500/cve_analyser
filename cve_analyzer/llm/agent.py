"""
代码分析 LLM Agent (简化版)

直接获取代码后单次分析，不依赖 function calling
"""

import subprocess
from typing import Dict, Any, List


class CodeAnalysisAgent:
    """代码分析 Agent"""
    
    def __init__(self, llm_provider, kernel_path: str):
        self.llm = llm_provider
        self.kernel_path = kernel_path
    
    async def analyze(self, cve_id: str, patches: List[Dict]) -> str:
        """执行分析"""
        
        # 获取补丁代码
        code_context = await self._fetch_patch_code(patches)
        
        # 构建 prompt
        system_prompt = """你是一个专业的 Linux 内核安全工程师。

你的任务是检查 CVE 补丁是否已应用到你本地内核代码中。

**重要**：必须基于实际代码分析，不要推测！

分析步骤：
1. 检查每个补丁 commit 是否存在于本地 git 历史
2. 用 git show 查看具体代码变更
3. 综合判断修复状态

输出格式：
```
修复状态: [已修复/未修复/无法确认]
风险评估: [高/中/低]
关键发现: [你看到的代码具体情况]
建议: [接下来要做什么]
```
"""
        
        user_prompt = f"""请分析 CVE {cve_id} 的修复状态。

**本地内核路径**: {self.kernel_path}

**补丁列表**：
{chr(10).join([f"- {p['commit'][:12]}: {p.get('subject', 'N/A')[:100]}" for p in patches[:3]])}

**本地代码查询结果**：
{code_context}

请基于以上代码查询结果进行分析。
"""
        
        # 单次调用
        response = await self.llm.chat([
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ])
        
        return response.content
    
    async def _fetch_patch_code(self, patches: List[Dict]) -> str:
        """获取补丁代码"""
        results = []
        
        for patch in patches[:3]:  # 只查前3个
            commit = patch['commit']
            short = patch.get('commit_hash_short', commit[:12])
            
            results.append(f"\n=== 补丁: {short} ===")
            
            # 1. 检查 commit 是否存在
            result = subprocess.run(
                ["git", "log", "--oneline", "-1", commit],
                cwd=self.kernel_path,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0 and result.stdout:
                results.append(f"✓ Commit 存在于本地仓库")
                results.append(f"  {result.stdout.strip()}")
                
                # 2. 获取详细 diff
                result = subprocess.run(
                    ["git", "show", commit, "--stat", "--format=%H%n%s%n%b"],
                    cwd=self.kernel_path,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                if result.returncode == 0:
                    results.append(f"\n代码变更:\n{result.stdout[:2000]}")
            else:
                results.append(f"✗ Commit 不存在于本地仓库")
        
        return "\n".join(results)
