"""
代码分析 LLM Agent

支持工具调用，按需获取代码进行分析
"""

import json
import asyncio
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass


@dataclass
class Tool:
    """工具定义"""
    name: str
    description: str
    parameters: Dict[str, Any]
    function: Callable


class CodeAnalysisAgent:
    """代码分析 Agent"""
    
    def __init__(self, llm_provider, kernel_path: str):
        self.llm = llm_provider
        self.kernel_path = kernel_path
        self.messages = []
        self.tools = self._register_tools()
    
    def _register_tools(self) -> List[Tool]:
        """注册可用工具"""
        return [
            Tool(
                name="git_log",
                description="查询 git 提交历史，查找特定 commit 是否存在",
                parameters={
                    "type": "object",
                    "properties": {
                        "commit": {"type": "string", "description": "commit hash (可截取前12位)"},
                        "grep": {"type": "string", "description": "搜索关键词"},
                    },
                    "required": [],
                },
                function=self._git_log,
            ),
            Tool(
                name="git_show",
                description="显示 commit 的具体代码变更",
                parameters={
                    "type": "object",
                    "properties": {
                        "commit": {"type": "string", "description": "commit hash"},
                    },
                    "required": ["commit"],
                },
                function=self._git_show,
            ),
            Tool(
                name="search_code",
                description="在代码库中搜索特定函数或字符串",
                parameters={
                    "type": "object",
                    "properties": {
                        "pattern": {"type": "string", "description": "搜索模式"},
                        "path": {"type": "string", "description": "搜索路径"},
                    },
                    "required": ["pattern"],
                },
                function=self._search_code,
            ),
            Tool(
                name="check_file_exists",
                description="检查特定文件是否存在",
                parameters={
                    "type": "object",
                    "properties": {
                        "file": {"type": "string", "description": "文件路径"},
                    },
                    "required": ["file"],
                },
                function=self._check_file_exists,
            ),
            Tool(
                name="final_answer",
                description="完成分析，输出最终结论",
                parameters={
                    "type": "object",
                    "properties": {
                        "status": {"type": "string", "description": "修复状态: 已修复/未修复/无法确认"},
                        "risk": {"type": "string", "description": "风险评估: 高/中/低"},
                        "reason": {"type": "string", "description": "分析理由"},
                        "suggestion": {"type": "string", "description": "建议"},
                    },
                    "required": ["status", "risk"],
                },
                function=self._final_answer,
            ),
        ]
    
    def _git_log(self, commit: str = None, grep: str = None) -> str:
        """查询 git log"""
        import subprocess
        
        cmd = ["git", "log", "--oneline", "-20"]
        if commit:
            cmd = ["git", "log", "--oneline", "-10", "--all", "-S", commit]
        elif grep:
            cmd = ["git", "log", "--oneline", "--all", "--grep", grep]
        
        try:
            result = subprocess.run(
                cmd,
                cwd=self.kernel_path,
                capture_output=True,
                text=True,
                timeout=30
            )
            return result.stdout[:2000] if result.stdout else "No commits found"
        except Exception as e:
            return f"Error: {e}"
    
    def _git_show(self, commit: str) -> str:
        """显示 commit 内容"""
        import subprocess
        
        try:
            result = subprocess.run(
                ["git", "show", commit],
                cwd=self.kernel_path,
                capture_output=True,
                text=True,
                timeout=30
            )
            return result.stdout[:5000] if result.stdout else "Commit not found"
        except Exception as e:
            return f"Error: {e}"
    
    def _search_code(self, pattern: str, path: str = None) -> str:
        """搜索代码"""
        import subprocess
        
        cmd = ["grep", "-r", "-n", pattern]
        if path:
            cmd.append(path)
        
        try:
            result = subprocess.run(
                cmd,
                cwd=self.kernel_path,
                capture_output=True,
                text=True,
                timeout=30
            )
            return result.stdout[:2000] if result.stdout else "No matches"
        except Exception as e:
            return f"Error: {e}"
    
    def _check_file_exists(self, file: str) -> str:
        """检查文件是否存在"""
        import os
        
        full_path = os.path.join(self.kernel_path, file)
        exists = os.path.exists(full_path)
        return f"EXISTS: {full_path}" if exists else f"NOT FOUND: {full_path}"
    
    def _final_answer(self, status: str, risk: str, reason: str = "", suggestion: str = "") -> str:
        """输出最终答案"""
        return json.dumps({
            "status": status,
            "risk": risk,
            "reason": reason,
            "suggestion": suggestion
        })
    
    async def analyze(self, cve_id: str, patches: List[Dict], max_iterations: int = 10) -> str:
        """执行分析"""
        
        # 系统提示
        system_prompt = f"""你是一个专业的 Linux 内核安全工程师。

你的任务是检查 CVE 补丁是否已应用到你本地内核代码中。

**本地内核路径**: {self.kernel_path}

**工具调用**：
你可以调用以下工具来分析代码：
"""
        for tool in self.tools:
            system_prompt += f"\n- {tool.name}: {tool.description}"
        
        system_prompt += """

**分析流程**：
1. 首先检查补丁 commit 是否存在于本地 git 历史 (用 git_log)
2. 如果 commit 存在，用 git_show 查看具体变更
3. 检查相关文件是否存在
4. 综合判断修复状态

**重要**：
- 必须实际调用工具来验证，不要猜测！
- 如果 commit 不存在 → 未修复
- 如果 commit 存在且代码正确 → 已修复
- 如果不确定 → 继续查询

现在请开始分析 CVE {cve_id} 的补丁。
补丁列表：
{patches_str}
"""
        patches_str = "\n".join([f"- {p['commit']}: {p.get('subject', 'N/A')}" for p in patches])
        system_prompt = system_prompt.format(cve_id=cve_id, patches_str=patches_str)
        
        self.messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"请分析 CVE {cve_id} 的修复状态。\n\n补丁列表：\n{patches_str}"}
        ]
        
        # 循环直到得到最终答案
        for i in range(max_iterations):
            # 调用 LLM
            response = await self.llm.chat(self.messages)
            content = response.content
            
            self.messages.append({"role": "assistant", "content": content})
            
            # 检查是否有工具调用
            # MiniMax 不支持 function calling，我们用文本格式
            # 检查是否调用了 final_answer
            if "final_answer" in content or ("修复状态" in content and ("已修复" in content or "未修复" in content or "无法确认" in content)):
                return content
            
            # 解析工具调用
            tool_result = self._parse_tool_calls(content)
            
            if tool_result:
                # 添加用户消息（工具结果）
                self.messages.append({"role": "user", "content": f"工具执行结果：\n{tool_result}"})
            else:
                # 没有工具调用，可能是继续分析
                if i < max_iterations - 1:
                    self.messages.append({"role": "user", "content": "请继续分析。"})
        
        return "分析超时"
    
    def _parse_tool_calls(self, content: str) -> Optional[str]:
        """解析工具调用"""
        import re
        
        results = []
        
        for tool in self.tools:
            if tool.name == "final_answer":
                continue
            
            # 尝试匹配工具调用格式
            # 格式1: git_log(commit="xxx")
            # 格式2: 调用 git_log...
            patterns = [
                rf'{tool.name}\s*\(([^)]*)\)',
                rf'{tool.name}:\s*(.+)',
            ]
            
            for pattern in patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    args_str = match.group(1) if match.groups() else ""
                    
                    # 解析参数
                    args = {}
                    if "commit" in args_str:
                        # 提取 commit
                        commit_match = re.search(r'commit\s*=\s*["\']?([a-fA-F0-9]+)["\']?', args_str)
                        if commit_match:
                            args["commit"] = commit_match.group(1)
                    
                    if "pattern" in args_str:
                        pattern_match = re.search(r'pattern\s*=\s*["\']([^"\']+)["\']', args_str)
                        if pattern_match:
                            args["pattern"] = pattern_match.group(1)
                    
                    if "file" in args_str:
                        file_match = re.search(r'file\s*=\s*["\']([^"\']+)["\']', args_str)
                        if file_match:
                            args["file"] = file_match.group(1)
                    
                    if args:
                        try:
                            result = tool.function(**args)
                            results.append(f"{tool.name}: {result[:500]}")
                        except Exception as e:
                            results.append(f"{tool.name} Error: {e}")
        
        return "\n".join(results) if results else None
