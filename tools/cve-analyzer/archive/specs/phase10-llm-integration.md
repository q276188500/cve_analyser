# Phase 10: 大模型分析集成设计

## 概述

将 LLM (大语言模型) 集成到 CVE Analyzer，提供更智能的漏洞分析、风险评估和修复建议。

---

## 应用场景

### 1. 智能漏洞摘要
- **输入**: CVE 原始描述 + 补丁代码
- **输出**: 简洁的中文漏洞说明、攻击场景、影响范围

### 2. 补丁影响分析
- **输入**: Patch diff + 内核版本信息
- **输出**: 受影响的函数、调用链分析、潜在副作用

### 3. 修复建议生成
- **输入**: CVE 详情 + 当前内核版本
- **输出**: 具体的修复步骤、配置建议、测试用例

### 4. 漏洞关联分析
- **输入**: 多个 CVE 信息
- **输出**: 漏洞之间的依赖关系、组合攻击风险

### 5. Kconfig 智能审计
- **输入**: 内核 .config 文件
- **输出**: 配置项的安全评估、优化建议

---

## 架构设计

```
┌─────────────────────────────────────────────────────────────┐
│                    CVE Analyzer Core                        │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐     │
│  │ CVE Fetcher │    │   Analyzer  │    │   Reporter  │     │
│  └──────┬──────┘    └──────┬──────┘    └──────┬──────┘     │
│         │                  │                  │            │
│         └──────────────────┼──────────────────┘            │
│                            ▼                                │
│                   ┌─────────────────┐                       │
│                   │  LLM Bridge     │                       │
│                   │  (API Gateway)  │                       │
│                   └────────┬────────┘                       │
└────────────────────────────┼────────────────────────────────┘
                             │
        ┌────────────────────┼────────────────────┐
        ▼                    ▼                    ▼
 ┌─────────────┐      ┌─────────────┐      ┌─────────────┐
 │ OpenAI API  │      │ Claude API  │      │ Local LLM   │
 │ GPT-4/GPT-5 │      │  Claude 3   │      │ Ollama/     │
 │             │      │             │      │ vLLM        │
 └─────────────┘      └─────────────┘      └─────────────┘
```

---

## 模块设计

### 1. LLM Bridge (桥接层)

```python
# cve_analyzer/llm/base.py
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from dataclasses import dataclass

@dataclass
class LLMResponse:
    content: str
    model: str
    tokens_used: int
    cost: float
    metadata: Dict[str, Any]

class LLMProvider(ABC):
    """LLM 提供商基类"""
    
    @abstractmethod
    async def chat(self, messages: list, **kwargs) -> LLMResponse:
        pass
    
    @abstractmethod
    async def analyze_code(self, code: str, context: str) -> LLMResponse:
        pass

class OpenAIProvider(LLMProvider):
    """OpenAI GPT 接口"""
    def __init__(self, api_key: str, model: str = "gpt-4"):
        self.api_key = api_key
        self.model = model
    
    async def chat(self, messages: list, **kwargs) -> LLMResponse:
        # 调用 OpenAI API
        pass

class ClaudeProvider(LLMProvider):
    """Anthropic Claude 接口"""
    def __init__(self, api_key: str, model: str = "claude-3-opus"):
        self.api_key = api_key
        self.model = model

class OllamaProvider(LLMProvider):
    """本地 Ollama 接口"""
    def __init__(self, host: str = "http://localhost:11434", model: str = "codellama"):
        self.host = host
        self.model = model
```

### 2. 分析器集成

```python
# cve_analyzer/llm/analyzer.py
from cve_analyzer.llm.base import LLMProvider, LLMResponse
from cve_analyzer.core.models import CVE, Patch

class LLMVulnerabilityAnalyzer:
    """LLM 漏洞分析器"""
    
    def __init__(self, provider: LLMProvider):
        self.provider = provider
    
    async def analyze_cve(self, cve: CVE) -> Dict[str, Any]:
        """分析 CVE 并返回结构化结果"""
        
        prompt = self._build_cve_prompt(cve)
        response = await self.provider.chat([
            {"role": "system", "content": self._get_system_prompt()},
            {"role": "user", "content": prompt}
        ])
        
        return self._parse_response(response)
    
    async def analyze_patch(self, patch: Patch) -> Dict[str, Any]:
        """分析补丁代码"""
        
        prompt = f"""
分析以下 Linux 内核补丁的安全影响：

提交信息: {patch.subject}
作者: {patch.author}

补丁内容:
```diff
{patch.patch_content[:8000]}  # 限制长度
```

请分析：
1. 修复的漏洞类型 (如 use-after-free, buffer overflow 等)
2. 受影响的函数和调用链
3. 攻击向量 (如果可从补丁推断)
4. 可能的副作用或引入的新问题
5. 建议的测试用例

以 JSON 格式输出。
"""
        
        response = await self.provider.chat([
            {"role": "system", "content": "你是一个 Linux 内核安全专家。"},
            {"role": "user", "content": prompt}
        ])
        
        return self._parse_patch_analysis(response)
    
    def _build_cve_prompt(self, cve: CVE) -> str:
        return f"""
分析以下 CVE 漏洞：

CVE ID: {cve.id}
严重程度: {cve.severity}
CVSS 评分: {cve.cvss_score}
描述: {cve.description}

请提供：
1. 简洁的中文漏洞说明 (一句话概括)
2. 详细的攻击场景描述
3. 受影响的系统组件
4. 利用条件 (难度、权限要求)
5. 缓解措施建议
6. 与类似漏洞的关联性

以结构化 JSON 输出。
"""
```

### 3. CLI 集成

```python
# cve_analyzer/cli.py 新增命令

@cli.command()
@click.argument("cve_id")
@click.option("--provider", default="openai", type=click.Choice(["openai", "claude", "ollama"]))
@click.option("--model", help="模型名称 (如 gpt-4, claude-3-opus)")
@click.option("--output", "-o", default="markdown", type=click.Choice(["json", "markdown", "html"]))
@click.pass_context
async def llm_analyze(ctx, cve_id: str, provider: str, model: Optional[str], output: str):
    """
    使用大模型分析 CVE
    
    利用 LLM 提供更深入的漏洞分析和修复建议。
    
    示例:
        cve-analyzer llm-analyze CVE-2024-1234
        cve-analyzer llm-analyze CVE-2024-1234 --provider=claude --model=claude-3-opus
        cve-analyzer llm-analyze CVE-2024-1234 --output=html
    """
    from cve_analyzer.llm import LLMFactory
    from cve_analyzer.llm.analyzer import LLMVulnerabilityAnalyzer
    
    # 初始化 LLM 提供商
    llm_provider = LLMFactory.create(provider, model=model)
    analyzer = LLMVulnerabilityAnalyzer(llm_provider)
    
    # 获取 CVE 数据
    db = get_db()
    with db.session() as session:
        cve = session.query(CVE).filter_by(id=cve_id).first()
        if not cve:
            console.print(f"[red]CVE {cve_id} 不存在[/red]")
            return
    
    # 执行 LLM 分析
    with console.status(f"[bold green]正在使用 {provider} 分析 {cve_id}..."):
        result = await analyzer.analyze_cve(cve)
    
    # 显示结果
    _display_llm_result(result, output)


@cli.command()
@click.argument("patch_file", type=click.Path(exists=True))
@click.option("--provider", default="openai")
@click.option("--context", help="额外上下文信息")
async def llm_review_patch(patch_file: str, provider: str, context: Optional[str]):
    """
    使用 LLM 审查补丁
    
    分析补丁的安全影响和潜在问题。
    
    示例:
        cve-analyzer llm-review-patch fix.patch
        cve-analyzer llm-review-patch fix.patch --context="修复了网络协议栈的use-after-free"
    """
    # 读取补丁文件
    with open(patch_file) as f:
        patch_content = f.read()
    
    # LLM 分析
    # ...
```

### 4. 缓存层 (降低成本)

```python
# cve_analyzer/llm/cache.py
import hashlib
import json
from pathlib import Path
from typing import Optional

class LLMCache:
    """LLM 响应缓存 - 减少 API 调用成本"""
    
    def __init__(self, cache_dir: str = "./data/llm_cache"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
    
    def _get_cache_key(self, prompt: str, model: str) -> str:
        """生成缓存键"""
        content = f"{model}:{prompt}"
        return hashlib.sha256(content.encode()).hexdigest()
    
    def get(self, prompt: str, model: str) -> Optional[dict]:
        """获取缓存结果"""
        key = self._get_cache_key(prompt, model)
        cache_file = self.cache_dir / f"{key}.json"
        
        if cache_file.exists():
            with open(cache_file) as f:
                return json.load(f)
        return None
    
    def set(self, prompt: str, model: str, response: dict):
        """缓存结果"""
        key = self._get_cache_key(prompt, model)
        cache_file = self.cache_dir / f"{key}.json"
        
        with open(cache_file, 'w') as f:
            json.dump(response, f)
```

---

## 配置示例

```yaml
# configs/config.yaml

# LLM 配置
llm:
  # 默认提供商
  default_provider: "openai"
  
  # 缓存配置
  cache_enabled: true
  cache_dir: "./data/llm_cache"
  
  # 提供商配置
  providers:
    openai:
      api_key: "${OPENAI_API_KEY}"  # 从环境变量读取
      model: "gpt-4"
      base_url: "https://api.openai.com/v1"
      max_tokens: 4000
      temperature: 0.3  # 低温度，更确定性的输出
      
    claude:
      api_key: "${ANTHROPIC_API_KEY}"
      model: "claude-3-opus-20240229"
      max_tokens: 4000
      
    ollama:
      host: "http://localhost:11434"
      model: "codellama:34b"
      timeout: 120
  
  # 成本限制 (可选)
  cost_limit:
    daily_usd: 10.0
    monthly_usd: 100.0
```

---

## 成本估算

| 场景 | 输入 Tokens | 输出 Tokens | 单次成本 (GPT-4) |
|------|-------------|-------------|------------------|
| CVE 摘要 | 500 | 300 | ~$0.02 |
| 补丁分析 | 2000 | 800 | ~$0.08 |
| Kconfig 审计 | 3000 | 500 | ~$0.10 |
| 批量报告 (50 CVE) | - | - | ~$5.00 |

**月度预算参考**:
- 小规模 (100 CVE/月): ~$10-20
- 中规模 (500 CVE/月): ~$50-100
- 大规模 (2000 CVE/月): ~$200-400

使用本地 LLM (Ollama) 可降低成本为 0，但需要 GPU 资源。

---

## 实现计划

### Phase 10.1: 基础集成
- [ ] LLM Bridge 接口设计
- [ ] OpenAI/Claude 提供商实现
- [ ] 基础 CVE 分析功能
- [ ] CLI 命令集成

### Phase 10.2: 高级分析
- [ ] 补丁代码分析
- [ ] Kconfig 智能审计
- [ ] 漏洞关联推理
- [ ] 中文报告生成

### Phase 10.3: 本地部署
- [ ] Ollama 集成
- [ ] 模型量化支持
- [ ] 私有部署方案

### Phase 10.4: 优化与扩展
- [ ] 智能缓存策略
- [ ] 成本监控
- [ ] 批量处理优化

---

## 安全与隐私考虑

1. **数据脱敏**: 不上传敏感的内核代码片段
2. **本地优先**: 敏感环境使用本地 LLM
3. **审计日志**: 记录所有 LLM 调用
4. **成本告警**: 防止意外的高额 API 费用

---

## 结论

大模型集成将显著提升 CVE Analyzer 的智能化水平：

- ✅ **降低使用门槛** - 自然语言交互
- ✅ **提升分析深度** - AI 辅助漏洞解读
- ✅ **自动化报告** - 生成高质量中文文档
- ✅ **智能建议** - 修复方案和配置优化

预计开发周期: 2-3 周 (Phase 10.1-10.2)
