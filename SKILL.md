# CVE Review Skill - CVE 漏洞审查与影响评估

## 概述

利用 OpenCLAW 的大模型能力，对 CVE 漏洞进行全面的审查和影响评估。

## 触发条件

用户提及以下内容时自动触发：
- "CVE 检视"、"CVE review"、"漏洞评估"、"CVE 影响分析"
- 分析某个具体的 CVE ID
- 提供时间段进行批量 CVE 分析

---

## 使用模式

### 1. 正常模式
一次性执行完整流程，用户只需提供初始输入。

### 2. 测试模式
当用户明确说明"测试模式"时，采用步骤执行模式，每步暂停等待用户确认。

### 3. 信息冗余模式
当用户明确说明"信息冗余模式"时，打印完整的推理过程和分析细节。

---

## 完整流程

### Step 1: 输入与数据获取

**输入**：时间段 或 CVE ID

**数据获取流程**：
1. 优先从本地 cve-analyzer 获取（路径：`tools/cve-analyzer/data/cve-analyzer.db`）
2. 本地没有则用 sync 命令同步：`python -m cve_analyzer.cli sync --since=YYYY-MM-DD --until=YYYY-MM-DD`

**获取数据**：CVE 描述、关联 patch、Kconfig

---

### Step 2: 代码仓指定与同步

- 用户提供业务代码仓路径
- 每次评估前执行 `git fetch && git merge`

---

### Step 3: 初步筛选

| 条件 | 结果 |
|------|------|
| KCONFIG 未开启 | 无影响 |
| 非内核问题 | 无影响 |

---

### Step 4: 详细评估

**【重要】由 OpenCLAW（内核专家）主导，每个 CVE 独立分析**

#### Step 4.1: 获取 CVE 详情
从 NVD/cve-analyzer 获取 CVSS、描述、引用等

#### Step 4.2: 代码仓查询
必须查询代码仓，检查受影响文件是否存在、patch 是否已应用

#### Step 4.3: Patch 代码分析
以内核专家身份分析，强制要求：
- 展示 patch 关键代码片段
- 读取并引用相关 C 源文件
- 结合实际代码说明影响

#### Step 4.4: 知识库检索
读取 `SKILL/knowledge/` 中的规则进行匹配

#### Step 4.5: 综合判断与报告生成

**【进度提示】开始前打印：
```
════════════════════════════════════════════════════════════════════════════
【分析进度】共 {总数} 个 CVE，当前第 {序号} 个: {CVE_ID}
════════════════════════════════════════════════════════════════════════════
```

**完成后输出**：
```
分析完成，共 {总数} 个 CVE，建议合入 {X} 个，暂不合入 {Y} 个
```

#### Step 4.6: 报告归档
- 目录：`reports/{年份}/{月份}/`
- 文件：`{cve_id}.md`

---

## 报告格式

```markdown
# CVE 分析报告: {cve_id}

## 基本信息
| CVE ID | 严重程度 | CVSS | 披露日期 |

## 漏洞类型
{描述}

## 合入建议（快速获取策略）
**动作**: merge/defer
**理由**: {理由}

## 影响评估
| 维度 | 级别 | 描述 |
|------|------|------|
| 功能影响 | high/medium/low | |
| 性能影响 | high/medium/low | |
| 可靠性影响 | high/medium/low | |

---

## 内核专家详细分析

### Patch 分析
```
{patch 代码}
```

### 关联 C 文件分析
- 文件: xxx.c
- 函数: xxx()
- 调用链: xxx() -> xxx()

### 影响分析（结合代码）
- 条件: ...
- 函数: ...
- 后果: ...

---

*分析者: OpenCLAW (内核专家)*
*分析时间: {timestamp}*
```

---

## 依赖工具

### cve-analyzer

**路径**：`tools/cve-analyzer`

**命令**：
| 命令 | 用途 |
|------|------|
| sync | 同步 CVE 数据 |
| query | 查询本地数据库 |
| analyze | 分析单个 CVE |
| patch-status | 检测补丁状态 |
| kconfig | Kconfig 依赖分析 |
| llm-analyze | LLM 分析 |
| patch-history | 补丁历史追踪 |
| report | 生成报告 |
| check-fix | 检查是否已修复 |

### 领域知识库

**路径**：`knowledge/`

**格式**：YAML，每条规则包含 id、type、title、description、severity、affected_paths

---

## 配置文件

**路径**：`config/config.yaml`

```yaml
kernel_repo:
  path: "~/workspace/linux-kernel/linux-5.10"
  branch: "main"

cve_analyzer:
  path: "tools/cve-analyzer"

knowledge_base:
  path: "knowledge/"
  kconfig_rules: "knowledge/kconfig/"

reports:
  output_dir: "reports/"

analysis:
  default_action: "merge"
  require_reason_on_defer: true
  code_query_enabled: true
  independent_analysis: true
```

---

## 注意事项

1. KCONFIG 筛选必须基于代码仓的 .config
2. 除非有充分理由，否则默认合入
3. 新工具需人工确认后才能使用

---

## 版本

- **v1.2** (2026-03-18): 整理逻辑
- **v1.1** (2026-03-18): 补充步骤要求
- **v1.0** (2026-03-18): 初始版本
