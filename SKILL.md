# CVE Review SKILL - CVE 漏洞审查与影响评估

## 概述

利用 OpenCLAW 的大模型能力，对 CVE 漏洞进行全面的审查和影响评估。

---

## 触发条件

用户提及以下内容时自动触发：
- "CVE 检视"、"CVE review"、"漏洞评估"
- 分析某个具体的 CVE ID
- 提供时间段进行批量 CVE 分析

---

## 使用模式

### 1. 正常模式

一次性执行完整流程，用户只需提供初始输入。

### 2. 测试模式

用户明确说明"测试模式"时，采用步骤执行：
- 每完成一个步骤后，暂停等待用户确认
- 用户可以干预：继续/跳过/停止

### 3. 信息冗余模式

用户明确说明"信息冗余模式"时：
- 打印每个 CVE 的完整推理过程
- 包括：代码查询、知识库匹配、专家分析

---

## 完整流程

### Step 1: 输入与数据获取

**输入**：时间段 或 CVE ID

**数据获取流程**：
1. 优先从本地 `tools/cve-analyzer/data/cve-analyzer.db` 查询
2. 如果没有，使用 sync 命令同步：
   ```bash
   cd tools/cve-analyzer
   python -m cve_analyzer.cli sync --since=YYYY-MM-DD --until=YYYY-MM-DD
   ```

**获取数据**：CVE 描述、patch、Kconfig

---

### Step 2: 代码仓指定与同步

- 用户提供代码仓路径
- 每次评估前执行 `git pull` 同步到最新

---

### Step 3: 初步筛选

**比较对象**：代码仓 `.config`

| 条件 | 结果 | 原因 |
|------|------|------|
| KCONFIG 未开启 | 无影响 | 配置未启用 |
| 非内核问题 | 无影响 | 非内核 CVE |

---

### Step 4: 详细评估

**【重要】开始前打印进度**：
```
══════════════════════════════════════════════════════════════
【分析进度】共 {总数} 个 CVE，当前第 {当前序号} 个: {CVE_ID}
══════════════════════════════════════════════════════════════
```

#### Step 4.1: 获取 CVE 详情

- 从 NVD/cve-analyzer 获取完整信息
- 获取受影响文件列表

#### Step 4.2: 代码仓查询（必须执行）

```bash
# 检查文件是否存在
ls -la ${KERNEL_REPO}/${AFFECTED_FILE}

# 查看相关 commit
git log --oneline -10 -- ${AFFECTED_FILE}

# 对比差异
git diff HEAD -- ${AFFECTED_FILE}
```

#### Step 4.3: Patch 分析

**必须包含**：
1. **Patch 分析** - 展示关键代码片段，对比修改前后
2. **关联 C 文件分析** - 读取源文件，分析函数调用链
3. **影响分析** - 结合代码说明，不能空泛描述

**分析框架**：
- 问题分类：UAF/越界/死锁/数据损坏...
- 利用难度：需要什么条件触发
- 影响范围：哪些场景受影响
- 危害程度：数据泄露/系统崩溃/提权
- 修复质量：补丁是否完整

#### Step 4.4: 知识库检索

读取 `SKILL/knowledge/` 规则，匹配相关约束。

#### Step 4.5: 综合判断与报告生成

- 默认合入，除非有充分理由不合入
- 生成 Markdown 格式报告

**报告格式**：
```markdown
# CVE 分析报告: {cve_id}

## 基本信息
| CVE ID | 严重程度 | 披露日期 |

## 漏洞类型
{描述}

## 受影响文件
{文件列表}

## Kconfig 检查
| 配置 | 状态 |

## 合入建议（快速获取策略）
**动作**: merge/defer
**理由**: {理由}

## 影响评估
| 维度 | 级别 | 描述 |

## 知识库匹配
{匹配规则}

## 详细分析过程
{步骤记录}

## 内核专家详细分析
### Patch 分析
{patch 代码}

### 关联 C 文件分析
{文件、函数、调用链}

### 影响分析（结合代码）
{结合实际代码的影响分析}

---
*分析者: OpenCLAW (内核专家)*
*分析时间: {timestamp}*
```

#### Step 4.6: 报告归档

- 目录：`SKILL/reports/{年份}/{月份}/`
- 文件：`{cve_id}.md`

---

### Step 5: 批量汇总

完成后输出汇总：
```
分析完成，共 {总数} 个 CVE，建议合入 {X} 个，暂不合入 {Y} 个
```

---

## 依赖工具

### 1. cve-analyzer

**路径**：`tools/cve-analyzer`

**常用命令**：

| 命令 | 用途 |
|------|------|
| `sync --since= --until=` | 同步 CVE 数据 |
| `query --severity= --keyword=` | 查询数据库 |
| `analyze <cve_id>` | 分析单个 CVE |
| `patch-status <cve_id> --kernel-path=` | 检测补丁状态 |
| `kconfig <cve_id> --config=` | Kconfig 依赖分析 |
| `llm-analyze <cve_id> --provider=` | LLM 分析 |
| `report <cve_id> --format=markdown` | 生成报告 |

### 2. 领域知识库

**路径**：`SKILL/knowledge/`

**格式**：YAML 文件，包含：
- `id`: 规则 ID
- `type`: constraint/context/reference
- `severity`: critical/high/medium/low
- `affected_paths`: 影响的文件路径

---

## 配置文件

`SKILL/config.yaml`：
```yaml
kernel_repo:
  path: "~/workspace/linux-kernel/linux-5.10"

cve_analyzer:
  path: "tools/cve-analyzer"

knowledge_base:
  path: "knowledge/"

reports:
  output_dir: "reports/"

analysis:
  default_action: "merge"
  require_reason_on_defer: true
```

---

## 注意事项

1. KCONFIG 筛选：必须基于代码仓 .config
2. 默认合入：除非有充分理由
3. 每个 CVE 独立分析，不能批量处理
4. 必须读取实际代码，禁止空泛描述

---

## 补充说明

### 工具开发

流程固定、可提高效率的步骤可生成工具。工具需人工确认后才能正式使用。

### SKILL 测试与优化

测试过程中发现问题：
- 立即提出，等待开发人员确认
- 20s 无反馈：记录建议项，暂不修改

---

## 版本

- **v1.x** (2026-03-18): 当前版本
