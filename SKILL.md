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

**数据获取**：

**【重要】数据获取流程（必须遵循）**：

1. **优先从本地 cve-analyzer 获取**：
   - 检查 cve-analyzer 数据库是否有所需时间段的数据
   - 路径: `tools/cve-analyzer/data/cve-analyzer.db`
   - 命令: `sqlite3 cve-analyzer.db "SELECT * FROM cves WHERE ..."`

2. **如果本地没有数据，必须从 NVD 获取**：
   - 使用 cve-analyzer 的 sync 命令同步数据
   - 命令: `cd tools/cve-analyzer && python start.py sync --since=YYYY-MM-DD --until=YYYY-MM-DD`
   - 或直接调用 NVD API:
     ```bash
     curl "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={CVE_ID}"
     curl "https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=YYYY-MM-DD&pubEndDate=YYYY-MM-DD"
     ```

**获取的数据**：
- CVE 漏洞描述
- CVE 漏洞关联的修复 patch
- CVE 漏洞关联的 Kconfig（内核配置依赖）

**数据来源**：cve-analyzer → NVD → 统一管理

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

**重要**：由 OpenCLAW Agent（即"我"）主导整个分析过程，LLM 只是辅助工具。

**每个 CVE 必须独立分析**，不能批量处理。

#### Step 4.1: 获取 CVE 详细信息

由"我"执行：
- 从 NVD 获取完整 CVE 信息（CVSS、描述、引用等）
- 从 cve-analyzer 获取关联的 patch 内容
- 获取 CVE 影响的文件列表

#### Step 4.2: 代码仓查询

**必须由"我"主动查询代码仓**：
- 检查 CVE 影响文件是否存在于代码仓中
- 对比 patch 与代码仓当前版本的差异
- 检查 patch 是否已应用

**示例查询**（由我执行）：
```bash
# 检查文件是否存在
ls -la ${KERNEL_REPO}/${AFFECTED_FILE}

# 检查 patch 是否已应用
cd ${KERNEL_REPO}
git log --oneline --all -- ${AFFECTED_FILE} | head -10
git blame ${AFFECTED_FILE} | grep -i "fix\|cve"

# 对比差异
git diff HEAD -- ${AFFECTED_FILE}
```

#### Step 4.3: Patch 代码分析

由"我"（作为内核领域专家）直接分析。

**必须读取代码**：针对每一个 CVE，必须执行以下代码查询：
```bash
# 1. 检查受影响文件是否存在
ls -la ${KERNEL_REPO}/${AFFECTED_FILE}

# 2. 查看问题函数的实际代码
grep -n "FUNCTION_NAME" ${KERNEL_REPO}/${AFFECTED_FILE}

# 3. 查看相关 commit 历史
cd ${KERNEL_REPO}
git log --oneline -10 -- ${AFFECTED_FILE}

# 4. 如有 patch，对比差异
git diff HEAD -- ${AFFECTED_FILE}
```

**内核专家分析框架**：

**【强制要求】必须执行以下步骤，禁止空泛描述：**

```
1. Patch 分析（强制）
   - 展示 patch 关键代码片段
   - 分析 patch 修改的具体逻辑
   - 对比修改前后的差异

2. 关联 C 文件分析（强制）
   - 读取并引用相关 C 源文件
   - 分析问题函数的完整调用链
   - 结合实际代码流程说明影响

3. 影响维度（必须逐项分析）：
   - 利用难度：需要什么条件触发（本地/远程/特殊权限...）
   - 影响范围：哪些场景受影响（容器/虚拟化/特定驱动...）
   - 危害程度：数据泄露/系统崩溃/本地提权/服务中断...
   - 修复质量：补丁是否完整、是否有副作用

4. 影响分析（必须结合代码）
   - 不能只说"可能有风险"
   - 必须说明"在 XXX 函数中，当 XXX 条件满足时，会导致 XXX 后果"
```

**我不依赖 LLM，而是以内核专家的身份直接给出专业判断。**

#### Step 4.4: 领域知识库检索与验证

由"我"（内核专家）执行：
- 读取 SKILL/knowledge/ 中的规则
- 对比当前 CVE 是否匹配已知规则
- 验证我的初步判断是否合理

**我以内核专家的经验来综合评估功能、性能、可靠性影响。**

#### Step 4.5: 综合判断与报告生成

由"我"（内核专家）完成：
- 综合以上所有信息
- 直接给出合入建议（默认合入，除非有充分理由）
- 生成格式化的分析报告

**我不转发给 LLM，而是以内核领域专家的身份直接给出专业判断。**

**报告格式要求（Markdown 格式，人类和 Agent 都方便处理）**：

```markdown
# CVE 分析报告: {cve_id}

## 基本信息

| 字段 | 值 |
|------|-----|
| CVE ID | {cve_id} |
| 严重程度 | {severity} |
| CVSS | {cvss} |
| 披露日期 | {published_date} |

## 漏洞类型

{详细描述漏洞}

## 受影响文件

{文件列表}

## Kconfig 检查

| 配置 | 状态 | 结果 |
|------|------|------|
| CONFIG_XXX | enabled/disabled | affected/not_affected |

结论：{是否受影响}

## 合入建议（快速获取策略）

**动作**: merge/review/defer

**理由**: {建议理由}

## 影响评估

| 维度 | 级别 | 描述 |
|------|------|------|
| 功能影响 | high/medium/low | 描述 |
| 性能影响 | high/medium/low | 描述 |
| 可靠性影响 | high/medium/low | 描述 |

## 知识库匹配

- 匹配规则：{rule_id}
- 描述：{description}

## 详细分析过程

1. **Step 1 - 获取 CVE 详情**: {result}
2. **Step 2 - 查询代码仓**: {result}
3. **Step 3 - Kconfig 检查**: {result}
4. **Step 4 - 知识库匹配**: {result}
5. **Step 5 - 综合判断**: {result}

---

## 内核专家详细分析（强制要求）

**【重要】必须包含以下内容，禁止空泛描述：**

### 1. Patch 分析（强制）
- 展示 patch 关键代码片段
- 分析 patch 修改的具体逻辑
- 对比修改前后的差异

### 2. 关联 C 文件分析（强制）
- 读取并引用相关 C 源文件
- 分析问题函数的完整调用链
- 结合实际代码流程说明影响

### 3. 影响分析（必须结合代码）
- 不能只说"可能有风险"
- 必须说明"在 XXX 函数中，当 XXX 条件满足时，会导致 XXX 后果"

### 4. 格式要求
```
## 内核专家详细分析

### Patch 分析
\`\`\`
[paste patch 关键代码]
\`\`\`

### 关联 C 文件分析
- 文件: xxx.c
- 问题函数: xxx()
- 调用链: xxx() -> xxx() -> xxx()
- 关键代码片段:
\`\`\`c
[引用实际代码]
\`\`\`

### 影响分析（结合代码）
- 当 [具体条件] 时
- 在 [具体函数] 中
- 会导致 [具体后果]
- 原因: [从代码角度分析]
```

作为内核领域专家，我对这个 CVE 的详细分析如下：

{详细分析内容}

---

*分析者: OpenCLAW (内核专家)*
*分析时间: {analyzed_at}*
```

**格式要点**：
- 采用 Markdown 格式，方便人类阅读
- 结构化表格呈现关键信息
- 详细分析作为最后章节
- 保留 metadata 信息

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

**用途**：获取 CVE 数据、patch、Kconfig、补丁状态检测

**路径**：`tools/cve-analyzer`

**调用方式**：
```bash
cd tools/cve-analyzer
python -m cve_analyzer.cli <command>
```

**【重要】以下命令必须知道并灵活使用**：

#### 1. sync - 同步 CVE 数据
```bash
# 同步指定时间段
python -m cve_analyzer.cli sync --since=2025-12-01 --until=2025-12-31

# 同步最近 30 天
python -m cve_analyzer.cli sync

# 断点续传
python -m cve_analyzer.cli sync --resume
```

#### 2. query - 查询本地数据库
```bash
# 按严重程度查询
python -m cve_analyzer.cli query --severity=high --limit=50

# 按关键词搜索
python -m cve_analyzer.cli query --keyword="use-after-free" --limit=20

# 按日期查询
python -m cve_analyzer.cli query --since=2026-01-01 --format=json

# 组合查询
python -m cve_analyzer.cli query --severity=critical --keyword=linux --limit=10
```

#### 3. analyze - 分析单个 CVE
```bash
# 基本分析
python -m cve_analyzer.cli analyze CVE-2024-1234

# 深度分析
python -m cve_analyzer.cli analyze CVE-2024-1234 --deep
```

#### 4. patch-status - 检测补丁状态
```bash
# 检测补丁是否已应用
python -m cve_analyzer.cli patch-status CVE-2024-1234 --kernel-path=/path/to/linux

# 指定检测策略
python -m cve_analyzer.cli patch-status CVE-2024-1234 --kernel-path=/path/to/linux --detection=both
```

#### 5. kconfig - Kconfig 依赖分析
```bash
# 分析 CVE 的 Kconfig 依赖
python -m cve_analyzer.cli kconfig CVE-2024-1234

# 对比指定配置文件
python -m cve_analyzer.cli kconfig CVE-2024-1234 --config=/path/to/.config

# 审计当前配置
python -m cve_analyzer.cli kconfig --audit --config=/path/to/.config
```

#### 6. extract-patches - 提取补丁信息
```bash
# 提取所有 CVE 的补丁
python -m cve_analyzer.cli extract-patches

# 只处理指定 CVE
python -m cve_analyzer.cli extract-patches --cve-id=CVE-2024-1234
```

#### 7. generate-kconfig-rule - 生成 Kconfig 规则
```bash
# 生成指定 CVE 的 Kconfig 规则
python -m cve_analyzer.cli generate-kconfig-rule CVE-2024-1234

# 批量生成
python -m cve_analyzer.cli batch-generate-kconfig --severity=high --limit=50
```

#### 8. llm-analyze - LLM 分析
```bash
# 使用 LLM 分析
python -m cve_analyzer.cli llm-analyze CVE-2024-1234

# 指定 LLM 提供商
python -m cve_analyzer.cli llm-analyze CVE-2024-1234 --provider=minimax --model=MiniMax-M2.1
```

#### 9. patch-history - 补丁历史追踪
```bash
# 查看补丁历史
python -m cve_analyzer.cli patch-history CVE-2024-1234

# 显示 revert
python -m cve_analyzer.cli patch-history CVE-2024-1234 --show-reverts
```

#### 10. report - 生成报告
```bash
# 生成 Markdown 报告
python -m cve_analyzer.cli report CVE-2024-1234 --format=markdown

# 生成 JSON 报告
python -m cve_analyzer.cli report CVE-2024-1234 --format=json --output=./reports
```

#### 11. check-fix - 检查是否已修复
```bash
# 检查是否已修复
python -m cve_analyzer.cli check-fix CVE-2024-1234 --kernel-path=/path/to/linux
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
  path: "tools/cve-analyzer"

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

**干预命令**：
| 命令 | 说明 |
|------|------|
| `继续` / `next` | 确认当前步骤，继续下一步 |
| `跳过` / `skip` | 跳过当前步骤 |
| `停止` / `stop` | 终止测试模式 |
| `<其他输入>` | 对当前步骤的干预 |

### 信息冗余模式

当用户明确说明"信息冗余模式"时，会打印每个 CVE 的完整分析过程：

**输出内容**：
1. **推理过程**：每个分析步骤的详细思考
2. **代码查询**：实际执行的命令和结果
3. **知识库检索**：匹配的规则详情
4. **专家分析**：内核专家的完整推理逻辑
5. **最终报告**：结构化的 Markdown 报告

**使用方式**：
```
信息冗余模式 分析 2026-01-01 ~ 2026-01-15
```

**示例输出**：
```
=== CVE-2025-68760 分析 ===

--- 推理过程 ---
Step 1: 获取 CVE 详情
  - CVE ID: CVE-2025-68760
  - 问题: iommu/amd 越界读取
  - 初步判断: 需要检查 AMD IOMMU 配置

Step 2: 查询代码仓
  - 执行: ls -la drivers/iommu/amd/
  - 结果: 文件存在

Step 3: Kconfig 检查
  - 执行: grep AMD_IOMMU .config
  - 结果: 未明确设置，但 AMD IOMMU 是常见服务器配置
  
--- 知识库检索 ---
  - 匹配规则: iommu_amd
  - 风险等级: medium

--- 专家分析 ---
  利用难度：需要本地访问
  影响范围：使用 AMD IOMMU 的服务器
  危害程度：可能信息泄露
  修复质量：边界检查修复，完整

--- 最终报告 ---
[Markdown 格式报告]
```

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
