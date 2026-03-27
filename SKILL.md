---
name: cve-review
description: CVE 漏洞审查与影响评估。用于分析 Linux 内核 CVE 漏洞，触发条件：(1) 用户提及 "CVE 检视"、"漏洞评估" (2) 分析具体 CVE ID
---

# CVE Review SKILL - CVE 漏洞审查与影响评估

## 概述

利用 **我（OpenCLAW）作为内核领域专家**，对 CVE 漏洞进行全面的审查和影响评估。

**核心定位**：我是一个内核领域专家，能够主动分析代码、查询仓库、综合判断，而不是简单的问题转发器。

**分析模式**：每次只分析 **一个** CVE ID，逐个完成。

---

## 触发条件

用户提及以下内容时自动触发：
- "CVE 检视"、"CVE review"、"漏洞评估"、"分析CVE"、"分析漏洞"
- 分析某个具体的 CVE ID

---

## 【重要】我的角色定位

**我（OpenCLAW）作为内核专家**：

1. **主导整个分析过程**
2. **主动读取代码**，查询代码仓实际内容
3. **以内核专家身份直接给出专业判断**
4. **调用 cve-analyzer 工具**获取数据，但分析必须由我完成

---

## 使用模式

### 1. 正常模式

一次性执行完整流程，用户只需提供初始输入。

### 2. 测试模式

用户明确说明"测试模式"时，采用步骤执行：
- 每完成一个步骤后，暂停等待用户确认
- 用户可以干预：继续/跳过/停止

---

## 完整流程

### Step 1: 代码仓指定与同步

**【强制】代码仓检查**：
1. 读取 `config/config.yaml` 获取配置的代码仓路径
2. 检查代码仓目录是否存在
3. **如果不存在**，立即停止并提示用户获取：
   ```
   ⚠️ 代码仓不存在，请提供内核代码仓路径
   可选择：
   - 指定已有代码仓路径
   - 我帮你克隆官方仓库 (需要较长时间)
   ```

**【强制】代码仓同步**：
- 每次评估前执行 `git pull` 同步到最新
- 如果是只读仓库/本地仓库，记录警告但继续分析

---

### Step 2: Kconfig 门控筛选

**目的**：判断漏洞是否在当前配置下可触发，过滤掉不受影响的场景。

**比较对象**：`kernel_config` 指定的 `.config` 文件（如未指定则用 `{kernel_repo.path}/.config`）

**执行方式**：
```bash
python3 scripts/cve-analyzer/start.py kconfig <cve_id> --config=/path/to/.config
```

**判定结果**：

| 条件 | 结果 | 后续 |
|------|------|------|
| KCONFIG 未开启 | **defer**（不分析） | 直接生成简化报告，结束 |
| 非内核问题 | **defer**（不分析） | 直接生成简化报告，结束 |
| KCONFIG 已开启 | **merge**（继续分析） | 进入 Step 3 |

**defer 报告格式（Kconfig 未开启时生成）**：
```markdown
# CVE 分析报告: {cve_id}

## 基本信息
| CVE ID | 严重程度 | 披露日期 |

## 漏洞类型
{描述}

## Kconfig 检查
| 配置 | 状态 | 结果 |
|------|------|------|
| CONFIG_XXX | 未设置 | not_affected |

## 合入建议
**动作**: defer
**理由**: {简要说明原因}
```

---

### Step 3: 详细评估

**【重要】由我（OpenCLAW 内核专家）主导整个分析过程。**

**【强制约束】禁止跳步骤，禁止简化**：
- ❌ 禁止：不读代码就下结论
- ❌ 禁止：只看 CVE 描述就写报告
- ❌ 禁止：受限于篇幅而简化报告
- ✅ 必须：每个步骤完成后才能下一步
- ✅ 可以：拆分多轮对话完成分析（记录进度）


**记录进度**：
- 每完成一个 CVE，记录当前进度
- 下一轮从下一个 CVE 继续

**示例**：
```
第一轮：CVE-1 (完成)
第二轮：CVE-2 (完成)
第三轮：CVE-3 (完成)
```

**每个 CVE 必须完成以下全部步骤（打勾确认）**：
```
[ ] Step 3.1: 用 cve-analyzer 获取 CVE 详情
[ ] Step 3.2: 执行代码仓查询，分析patch对应代码上下文并分析影响
[ ] Step 3.3: 检索知识库
```

**开始前打印进度**：
```
══════════════════════════════════════════════════════════════
【分析进度】当前 CVE: {CVE_ID}
══════════════════════════════════════════════════════════════
```

#### Step 3.1: 获取 CVE 详情

**【强制】必须用 cve-analyzer 查询**：
```bash
# 精确获取 CVE 详情（推荐）
python3 scripts/cve-analyzer/start.py analyze CVE-2025-40214

# 如果数据库中没有，再同步时间范围（sync 不支持指定单个 CVE ID）
python3 scripts/cve-analyzer/start.py sync --since=2025-12-01 --until=2025-12-31
```

**限制**：
- `sync` 命令只支持时间范围同步，无法指定单个 CVE ID
- 如果用户只想补充某个特定 CVE，需要同步包含该 CVE 的时间范围

**禁止**：
- ❌ 直接用 curl 从 NVD 获取
- ❌ 跳过 cve-analyzer

**获取**：
- CVE 完整描述
- 受影响文件列表
- 关联 patch


#### Step 3.2: Patch 代码与影响分析

**【强制】由我（内核专家）执行**：
1. 展示 patch 关键代码片段
2. 分析 patch 修改的具体逻辑
3. patch 修改文件上下文分析
4. 对比修改前后的差异
5. 漏洞触发条件与利用可行性分析


**分析维度**：
- 问题分类：UAF/越界/死锁/数据损坏...
- 利用难度：需要什么条件触发
- 影响范围：哪些场景受影响
- 危害程度：数据泄露/系统崩溃/提权
- 修复质量：补丁是否完整

#### Step 3.3: 知识库检索

读取 `SKILL/knowledge/` 规则，匹配相关约束。


### Step 4: 综合判断与报告生成

**由我（内核专家）完成**：
- 综合以上所有信息
- 直接给出合入建议（默认合入，除非有充分理由）
- 生成 Markdown 格式报告

**我不转发给 LLM，而是以内核专家的身份直接给出专业判断。**

**报告格式**：
```markdown
# CVE 分析报告: {cve_id}

## 基本信息
| CVE ID | 严重程度 | 披露日期 |

## 漏洞类型
{描述}

## 受影响文件
{文件列表}

## 合入建议
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

### 影响分析（结合代码）- 最重要章节

**【强制要求】影响分析必须详细阐述，不能有一句话结论**

必须包含以下内容：
1. **具体场景分析**：漏洞触发时的完整执行流程
2. **触发条件**：需要什么条件才能触发漏洞
3. **后果**：对系统/数据/安全的具体影响
4. **利用条件**：攻击者需要什么能力/权限
5. **影响范围**：哪些系统/场景受影响

**禁止**：
- ❌ 一句话结论（如"导致数据损坏"）
- ❌ 空泛描述（如"可能有风险"）
- ❌ 省略场景分析

**正确示例**：
```
### 影响分析（详细阐述）

1. 具体场景：xxx
   - 步骤1：xxx
   - 步骤2：xxx
   
2. 触发条件：xxx

3. 后果：xxx
   - xxx

...
```

---
*分析者: CVE影响评估Agent*
*分析时间: {timestamp}*
```

### Step 5: 报告校验（红线要求）

**【红线要求】校验不通过绝不能跳过，宁愿不完成也不能放水**

**根据合入建议类型，采用不同的校验标准**：

#### defer 报告校验项：
> defer 报告由 Step 2 直接生成，此处仅复核格式完整性。

```
[ ] 基本信息完整 (CVE ID, 严重程度, 日期)
[ ] 漏洞类型描述
[ ] Kconfig 检查结果
[ ] 合入建议 (defer + 理由)
```

#### merge 报告校验项：
> 仅在 Step 2 通过 Kconfig 门控后，进入 Step 3~4 分析并生成报告。

```
[ ] 基本信息完整 (CVE ID, 严重程度, 日期)
[ ] 漏洞类型描述
[ ] 受影响文件列表
[ ] 知识库匹配结果
[ ] 合入建议 (merge + 理由)
[ ] 影响评估表格
[ ] 内核专家详细分析:
    [ ] Patch 分析 - 有代码片段
    [ ] 关联 C 文件分析 - 有文件、函数、调用链
    [ ] 影响分析 - 结合代码具体分析
```

**校验规则（红线）**：
- 任何一项不满足 → **立即停止，从 Step 3.1 重新开始**
- 有步骤跳过 → **立即停止，从 Step 3.1 重新开始**
- 报告内容与建议类型不匹配 → **立即停止**
- **绝不能：降级处理、带病归档**

**如果校验失败**：
1. 停止当前分析
2. 记录失败原因
3. 从 Step 3.1 重新开始完整分析

### Step 6: 报告归档

- 目录：`scripts/cve-analyzer/reports/{年份}/{月份}/`（由 config.yaml 中 `output.report_dir` 配置决定）
- 文件：`{cve_id}.md`

---

### Step 7: 批量汇总

完成后输出汇总：
```
CVE 分析完成，共 {总数} 个 CVE，建议合入 {X} 个，暂不合入 {Y} 个
```

---

## 依赖工具

### 1. cve-analyzer

**路径**：`scripts/cve-analyzer`

**常用命令**：

| 命令 | 用途 |
|------|------|
| `python3 scripts/cve-analyzer/start.py sync --since= --until=` | 同步 CVE 数据 |
| `python3 scripts/cve-analyzer/start.py query --severity= --keyword=` | 查询数据库 |
| `python3 scripts/cve-analyzer/start.py analyze <cve_id>` | 分析单个 CVE |
| `python3 scripts/cve-analyzer/start.py extract-patches --cve-id=<cve_id>` | 从 CVE 引用中提取 patch 信息入库 |
| `python3 scripts/cve-analyzer/start.py patch-status <cve_id> --kernel-path=` | 检测补丁状态（**必须指定 --kernel-path**） |
| `python3 scripts/cve-analyzer/start.py kconfig <cve_id> --config=` | Kconfig 依赖分析 |
| `python3 scripts/cve-analyzer/start.py llm-analyze <cve_id> --provider=` | LLM 分析 |
| `python3 scripts/cve-analyzer/start.py report <cve_id> --format=markdown` | 生成报告 |

### 2. 领域知识库

**路径**：`SKILL/knowledge/`

**格式**：YAML 文件，包含：
- `id`: 规则 ID
- `type`: constraint/context/reference
- `severity`: critical/high/medium/low
- `affected_paths`: 影响的文件路径

---

## 配置文件

**注意：存在两套各自独立配置的配置文件，作用域不同。**

### 1. cve-analyzer 工具配置（工具自带）

**路径**：`scripts/cve-analyzer/configs/config.yaml`（cve-analyzer CLI 自动读取）

这是 cve-analyzer 工具自己的配置文件，工具运行时自动加载，**不是 agent 自己读的**。

常用配置项：
```yaml
# 内核源码目录（需含 .config 文件）
kernel:
  mode: "user_provided"
  path: "/path/to/linux-5.10"      # ← 内核源码树根目录

# 数据库路径
data_dir: "./data"
database_path: "./data/cve-analyzer.db"

# 输出报告目录
output:
  report_dir: "./reports"
```

### 2. SKILL 配置（agent 自己使用）

以下配置由 agent 自己维护和管理，**不是文件，是运行时的配置参考**：

| 配置项 | 说明 | 来源 |
|--------|------|------|
| `kernel_repo.path` | 内核源码目录 | 用户提供或工具配置 |
| `kernel_config` | 内核 .config 文件完整路径 | **用户启动时提供**，如未提供则用 `{kernel_repo.path}/.config` |
| `cve_analyzer.path` | 工具目录 | 固定为 `scripts/cve-analyzer` |
| `knowledge_base.path` | 知识库目录 | 固定为 `SKILL/knowledge/` |
| `reports.output_dir` | 报告输出根目录 | 来自工具配置 |

**.config 文件指定方式**：
- 启动 agent 时由用户传入 `kernel_config` 参数
- 如未传入，默认为 `{kernel_repo.path}/.config`
- cve-analyzer 的 `kconfig` 命令需要此路径：
  ```bash
  python3 scripts/cve-analyzer/start.py kconfig <cve_id> --config=/path/to/.config
  ```

---

## 注意事项

1. KCONFIG 筛选：必须基于代码仓 .config
2. 默认合入：除非有充分理由
3. 每次只分析一个 CVE，不支持批量并行
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
