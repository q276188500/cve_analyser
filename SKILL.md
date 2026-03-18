# CVE Review Skill - CVE 漏洞审查与影响评估

## 概述

利用 OpenCLAW 的大模型能力，对 CVE 漏洞进行全面的审查和影响评估。

## 触发条件

用户提及以下内容时自动触发：
- "CVE 检视"
- "CVE review"
- "漏洞评估"
- "CVE 影响分析"
- 分析某个具体的 CVE ID
- 提供时间段进行批量 CVE 分析

---

## 完整流程

### Step 1: 输入与数据获取

**输入**：
- 时间段（如：2024-01-01 至 2024-12-31）
- 或 CVE ID（如：CVE-2024-XXXX）

**数据获取（调用 cve-analyzer）**：
- CVE 漏洞描述
- CVE 漏洞关联的修复 patch
- CVE 漏洞关联的 Kconfig（内核配置依赖）

**数据来源**：cve-analyzer 统一获取与管理

---

### Step 2: 代码仓指定与同步

**指定代码仓**：
- 用户提供业务代码仓路径（如：`~/workspace/projects/my-kernel`）
- 该代码仓用于评估 CVE 合入的影响

**同步操作**：
- 每次漏洞评估前，先将代码仓更新到最新
- 执行 `git fetch && git merge` 或 `git pull`

**后续判断**：
- 判断 CVE 漏洞合入对指定代码仓造成的影响

---

### Step 3: 初步筛选

**比较对象**：
- 使用代码仓中的 `.config`（内核配置）作为比较对象

**筛选逻辑**：

| 条件 | 结果 | 原因 |
|------|------|------|
| CVE 相关的 KCONFIG **未开启** | **无影响** | KCONFIG 未开启 |
| CVE 是**非内核问题**（如 GoCD、Jenkins 等） | **无影响** | 非内核问题 |

**目的**：快速过滤掉不相关的 CVE，减少后续深度分析的工作量

---

### Step 4: 详细评估

使用 OpenCLAW Agent 自规划能力进行深度分析。

**重要**：每个 CVE 必须独立分析，不能批量处理。

#### Step 4.1: 获取 CVE 详细信息

- 从 NVD 获取完整 CVE 信息（CVSS、描述、引用等）
- 从 cve-analyzer 获取关联的 patch 内容
- 获取 CVE 影响的文件列表

#### Step 4.2: 代码仓查询

**必须查询代码仓实际代码**：
- 检查 CVE 影响文件是否存在于代码仓中
- 对比 patch 与代码仓当前版本的差异
- 检查 patch 是否已应用

**查询命令示例**：
```bash
# 检查文件是否存在
ls -la ${KERNEL_REPO}/${AFFECTED_FILE}

# 检查 patch 是否已应用
cd ${KERNEL_REPO}
git log --oneline --all -- ${AFFECTED_FILE} | head -10

# 查看文件当前版本
git show HEAD:${AFFECTED_FILE} | head -50
```

#### Step 4.3: Patch 代码分析

- 针对**每一个 patch** 找到其对应的代码文件
- 分析该 patch 解决的问题类型
- 分析可能造成的影响

#### Step 4.4: 领域知识库检索

- 检索 SKILL/knowledge/ 中的规则
- 综合分析该 patch 造成的：
  - 功能影响
  - 性能影响
  - 可靠性影响

#### Step 4.5: 生成单个 CVE 分析报告

**每个 CVE 独立生成报告**，报告格式：

```
╔════════════════════════════════════════════════════════════╗
║          🔍 CVE 漏洞分析报告                              ║
╚════════════════════════════════════════════════════════════╝

📋 CVE: {cve_id}
📊 严重程度: {severity} (CVSS: {cvss})
📅 披露日期: {date}

📌 漏洞描述
   {description}

📌 Patch 信息
   文件: {files}
   变更: +{additions} -{deletions}

📌 代码仓查询结果
   文件存在: {yes/no}
   Patch 状态: {已应用/未应用/部分应用}

📌 Kconfig 信息
   {kconfig_rules}

📌 初步分析
   问题类型: {problem_type}
   可能影响: {impact}

📌 知识库检索结果
   {knowledge_matches}

📌 综合评估
   功能影响: {功能等级} {描述}
   性能影响: {性能等级} {描述}
   可靠性影响: {可靠性等级} {描述}

📌 合入建议
   ✅ 建议合入 / ⚠️ 需确认 / ❌ 暂不合入
   
   理由: {reason}
```

#### Step 4.6: 报告归档

**归档要求**：
- 每个 CVE 独立归档
- 归档目录：`SKILL/reports/{年份}/{月份}/`
- 文件命名：`{cve_id}_{timestamp}.json`

**归档内容**：
- JSON 格式完整报告
- Markdown 格式可读报告

---

### Step 5: 批量汇总

当所有 CVE 分析完成后：
1. 汇总所有 CVE 的评估结果
2. 生成汇总报告
3. 输出最终建议

---

### Step 6: 补充说明

#### 6.1 工具开发

**原则**：流程固定、可提高效率与确定性的步骤可生成工具

**要求**：
- 工具最终是否采用需要**人工确认**
- 工具确认后归档在 `SKILL/tools/` 目录下
- 修改 SKILL 描述，使 Agent 能正确调用

#### 6.2 SKILL 测试与优化

**测试过程中**：
- Agent 发现 SKILL 描述不合理或需要优化的点
- **立即提出**，等待开发人员确认

**反馈机制**：

| 开发人员反馈 | 处理方式 |
|-------------|----------|
| 要修改 | suspend 检视流程 → 讨论修改 → resume 检视流程 |
| 20s 无反馈 | 记录建议项，暂不修改，继续执行 |

---

## 依赖工具

### cve-analyzer

**用途**：获取 CVE 数据、patch、Kconfig

**路径**：`~/workspace/projects/cve-analyzer`

**调用方式**：
```bash
cd ~/workspace/projects/cve-analyzer
python start.py sync --since=2024-01-01 --until=2024-12-31
python start.py analyze CVE-2024-XXXX
```

---

### 领域知识库

**用途**：检索 CVE 相关的领域知识

**路径**：`SKILL/knowledge/`

**格式**：YAML 文件，每条规则包含：
- `id`: 规则 ID
- `type`: 类型 (constraint/context/reference)
- `title`: 标题
- `description`: 描述
- `severity`: 严重级别 (critical/high/medium/low)
- `affected_paths`: 影响的文件路径

---

## 配置文件

**SKILL 配置文件**：`SKILL/config.yaml`

```yaml
# 代码仓配置
kernel_repo:
  path: "~/workspace/projects/my-kernel"
  branch: "main"

# cve-analyzer 配置
cve_analyzer:
  path: "~/workspace/projects/cve-analyzer"

# 知识库配置
knowledge_base:
  path: "SKILL/knowledge/"
  kconfig_rules: "SKILL/knowledge/kconfig/"

# 报告配置
reports:
  output_dir: "SKILL/reports/"
  format:
    - json
    - markdown

# 分析配置
analysis:
  default_action: "merge"  # 默认合入
  require_reason_on_defer: true  # 不合入时必须提供理由
  code_query_enabled: true  # 必须查询代码仓
  independent_analysis: true  # 每个 CVE 独立分析
```

---

## 使用模式

### 正常模式

一次性执行完整流程，用户只需提供初始输入。

### 测试模式

当用户明确说明"测试模式"时，采用步骤执行模式：

**执行方式**：
1. 每完成一个步骤后，暂停等待用户确认
2. 用户可以：
   - 确认继续下一步
   - 干预当前步骤（修改参数、跳过、终止等）
3. 直至所有步骤完成

**适用场景**：
- SKILL 开发和调试
- 验证流程正确性
- 复杂 CVE 需要人工介入判断

**干预命令**：
| 命令 | 说明 |
|------|------|
| `继续` / `next` | 确认当前步骤，继续下一步 |
| `跳过` / `skip` | 跳过当前步骤 |
| `停止` / `stop` | 终止测试模式 |
| `<其他输入>` | 对当前步骤的干预 |

**用户输入**：
```
分析 2024-01-01 到 2024-03-31 的 CVE
代码仓: ~/workspace/projects/my-kernel
```

**执行流程**：
1. cve-analyzer 获取时间段内的 CVE 列表
2. 同步代码仓到最新
3. 初步筛选（KCONFIG 检查、非内核过滤）
4. 对通过的 CVE 详细评估
5. 生成报告

---

## 注意事项

1. **KCONFIG 筛选**：必须基于代码仓的 .config 进行筛选
2. **默认合入**：除非有充分理由，否则建议合入
3. **非内核过滤**：明确区分内核 CVE 和非内核 CVE
4. **工具确认**：新工具需人工确认后才能正式使用

---

## 版本

- **v1.1** (2026-03-18): 补充步骤要求
  - 每个 CVE 独立分析
  - 必须查询代码仓
  - 报告必须归档
- **v1.0** (2026-03-18): 初始版本
