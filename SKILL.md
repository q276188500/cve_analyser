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

## 数据来源原则

> ⚠️ **数据库是所有数据的单一数据源（Single Source of Truth）**

- **对外提供的数据**（报告、patch 文件等）—— 必须从数据库读取
- **内部分析过程** —— patch 信息、commit hash 等也必须从数据库读取，不再直接访问外部网络获取
- **数据库未收录的 CVE/patch** —— 先通过 cve-analyzer sync 补全数据库，再继续分析
- **禁止**：直接 curl/wget 从 NVD/GitHub/kernel.org 获取数据用于分析流程

> 当前数据库 `patches.body` 字段暂未补全，补全后所有 patch 内容均从数据库获取。

---

## 【重要】我的角色定位

**我（OpenCLAW）作为内核专家**：

1. **主导整个分析过程**
2. **主动读取代码**，查询代码仓实际内容
3. **以内核专家身份直接给出专业判断**
4. **调用 cve-analyzer 工具**获取数据，但分析必须由我完成

---

## 完整流程

**开始前打印进度**：
```
══════════════════════════════════════════════════════════════
【分析进度】当前 CVE: {CVE_ID}
══════════════════════════════════════════════════════════════
```
### Step 1: 检查代码仓
[Step 1/5] 检查代码仓
**【强制】代码仓检查**：
1. 读取 `config/config.yaml` 获取配置的代码仓路径
2. 检查代码仓目录是否存在
3. **如果不存在**，立即停止并提示用户获取：

---

### Step 2: Kconfig 门控筛选
[Step 2/5] Kconfig 门控筛选

**目的**：判断漏洞是否在当前配置下可触发，过滤掉不受影响的场景。
**比较对象**：`kernel_config.path` 指定的文件（如未指定则用 `{kernel_repo.path}/.config`）
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
[Step 3/5] 详细评估
**【重要】由我（OpenCLAW 内核专家）主导整个分析过程。**
**【强制约束】禁止跳步骤，禁止简化**：
- ❌ 禁止：不读代码就下结论
- ❌ 禁止：只看 CVE 描述就写报告
- ❌ 禁止：受限于篇幅而简化报告
- ✅ 必须：每个步骤完成后才能下一步

#### Step 3.1: 获取 CVE 详情
  → [Step 3.1/5] 获取 CVE 详情

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
  → [Step 3.2/5] Patch 代码与影响分析

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
  → [Step 3.3/5] 知识库检索

读取 `knowledge/` 规则，匹配相关约束。


### Step 4: 综合判断与报告生成
[Step 4/5] 综合判断与报告生成
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

---
*分析者: CVE影响评估Agent*
*分析时间: {timestamp}*
```

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

---

**[自检清单]** 生成报告后逐项确认：
- [ ] 基本信息完整 (CVE ID, 严重程度, 日期)
- [ ] 漏洞类型描述清晰
- [ ] 受影响文件列表准确
- [ ] Patch 分析有代码片段支撑
- [ ] 影响分析包含具体场景、触发条件、后果、利用条件
- [ ] 合入建议有明确理由

> 如自检不通过，修订报告后再继续。

### Step 5: 报告归档
[Step 5/5] 报告归档
如果目录下已有相同报告则进行覆盖写入

- 目录：`scripts/cve-analyzer/reports/{年份}/{月份}/`（由 config.yaml 中 `output.report_dir` 配置决定）
- 文件：`{cve_id}.md`

---

### 主流程结束

---

## Patch 生成（如需）

> ⚠️ **此步骤为可选项**，仅在用户明确要求生成 patch 时执行。正常报告分析流程到此结束。

**触发条件**：用户说明"生成 patch"或"生成 CVE-XXXX-XXXX.patch"时执行。

**前置条件**：Step 4 决策为 merge，报告已生成。

**目标**：将上游 CVE patch 适配到本地代码仓，生成待人工审核的本地 patch 文件。

**执行流程**：

**Step P1: 从数据库获取 Patch 元数据**
- 查 `scripts/cve-analyzer/data/cve-analyzer.db` 的 `patches` 表：
  ```bash
  python3 scripts/cve-analyzer/start.py query --keyword={cve_id}
  ```
- 确认 `patches` 表中该 CVE 关联的 `commit_hash` 列表
- 检查 `patches.body` 是否有内容：
  - **有内容** → 直接使用数据库中的 body
  - **无内容** → 从上游获取（见 Step P1.5）

**Step P1.5: 从上游获取 Patch（如数据库 body 为空）**
- 用 commit hash 从 git mirror 获取 patch body：
  ```bash
  git -C {kernel_mirror_path} show {commit_hash} --format= > upstream.patch
  ```
- 存入 `reports/patches/{cve_id}/upstream.patch`

**Step P2: 定位本地待修改文件**
- 从 patch 内容中提取 `diff --git a/... b/...` 的文件路径
- 确认本地代码仓中对应文件是否存在
  ```bash
  ls {kernel_repo_path}/{affected_file}
  ```

**Step P3: 尝试应用上游 Patch**
```bash
cd {kernel_repo_path}
git apply --check reports/patches/{cve_id}/upstream.patch
```
- 如果**直接应用成功** → 跳到 Step P5
- 如果**有冲突或部分不适用** → 进入 Step P3.5

**Step P3.5: 检测本地是否已修复**
在尝试适配前，先检查本地代码是否已包含该修复。

- 读取本地源文件内容
- 对比上游 patch 的关键修改点（如函数返回值路径中是否已添加 fdput 调用）
- 如果本地代码**已包含修复**：生成标记文件，文件名加 `already-fixed` 前缀，跳过 Step P4

**检测结果处理**：

| 情况 | 后续操作 | 文件名 |
|------|---------|--------|
| 本地已修复 | 生成 `already-fixed` 标记，跳过 Step P4 | `CVE-XXXX-XXXX-already-fixed.patch` |
| 部分已修复 | 继续 Step P4，仅处理未修复部分 | `CVE-XXXX-XXXX.patch` |
| 本地未修复 | 继续 Step P4，完整适配 | `CVE-XXXX-XXXX.patch` |

**Step P4: 冲突分析与适配**
- 用 `git apply --3way --reject` 保留无法合并的部分
- 分析每个 `.rej` 文件（未成功应用的 hunk）
- 读取原始文件内容，在对应位置手工修改代码以适配
- 删除所有 `.orig` 和 `.rej` 文件
- 用 `git diff` 确认修改内容正确

**Step P5: 生成本地 Patch**
```bash
cd {kernel_repo_path}
git diff HEAD -- {modified_files} > "reports/patches/{cve_id}/{cve_id}.patch"
```

**Step P6: 归档**
- 目录结构：
  ```
  reports/patches/{cve_id}/
  ├── CVE-XXXX-XXXX-upstream.patch   # 上游原始 patch（带 CVE ID 前缀）
  ├── CVE-XXXX-XXXX.patch           # 适配后本地 patch（需修复的部分）
  └── CVE-XXXX-XXXX-already-fixed.patch  # 已修复标记（无需再合入）
  ```
- 文件名中含 `already-fixed` 表示本地代码已包含修复，人工无需处理
- patch 文件状态统一标记为**待人工审核**，不自动合入

**禁止**：
- ❌ 确认冲突内容前不擅自合入
- ❌ 自动 commit 到本地代码仓
- ❌ patch review 前直接应用
- ❌ 对已标记 `already-fixed` 的 CVE 重复生成 patch

---

## 路径约定

> ⚠️ **除特别说明外，本 SKILL 中所有路径均相对于本 SKILL 所在目录（即 `SKILL.md` 所在目录）。**
>
> 例如 `scripts/cve-analyzer/start.py` 完整路径为 `{SKILL目录}/scripts/cve-analyzer/start.py`

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

**路径**：`knowledge/`

**格式**：YAML 文件，包含：
- `id`: 规则 ID
- `type`: constraint/context/reference
- `severity`: critical/high/medium/low
- `affected_paths`: 影响的文件路径

