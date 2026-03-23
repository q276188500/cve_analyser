"""
代码分析 - 一次性分析版本

不依赖 function calling，直接获取代码后分析
"""

import subprocess
from typing import Dict, List


def analyze_patch_sync(llm, kernel_path: str, cve_id: str, patches: List[Dict]) -> str:
    """同步分析版本"""
    import asyncio
    
    async def _analyze():
        # 获取补丁代码
        code_context = await _fetch_patch_code(kernel_path, patches)
        
        # 构建 prompt
        system_prompt = """你是一个专业的 Linux 内核安全工程师。

你的任务是检查 CVE 补丁是否已应用到你本地内核代码中。

**重要**：必须基于实际代码分析，不要推测！

分析步骤：
1. 检查每个补丁 commit 是否存在于本地 git 历史
2. 根据代码变更判断修复状态
3. 给出明确结论

输出格式：
```
修复状态: [已修复/未修复/无法确认]
风险评估: [高/中/低]
关键发现: [你看到的代码具体情况]
建议: [接下来要做什么]
```
"""
        
        user_prompt = f"""请分析 CVE {cve_id} 的修复状态。

**本地内核路径**: {kernel_path}

**补丁列表**（共 {len(patches)} 个）：
{chr(10).join([f"- {p['commit'][:12]}: {str(p.get('subject', 'N/A'))[:80]}" for p in patches])}

**本地代码查询结果**：
{code_context}

请基于以上代码查询结果进行分析，给出结论。
"""
        
        response = await llm.chat([
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ])
        
        return response.content
    
    return asyncio.run(_analyze())


async def _fetch_patch_code(kernel_path: str, patches: List[Dict]) -> str:
    """获取补丁代码"""
    results = []
    
    # 不限制数量，全部查询
    for patch in patches:
        commit = patch['commit']
        short = patch.get('commit_hash_short', commit[:12])
        
        results.append(f"\n=== 补丁: {short} ===")
        
        # 1. 检查 commit 是否存在
        result = subprocess.run(
            ["git", "log", "-1", "--oneline", commit],
            cwd=kernel_path,
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if result.returncode == 0 and result.stdout:
            results.append(f"✓ Commit 存在于本地仓库")
            results.append(f"  {result.stdout.strip()}")
        else:
            results.append(f"✗ Commit 不存在于本地仓库")
    
    return "\n".join(results)
