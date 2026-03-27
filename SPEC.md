# CVE Analyser Next Phase - SPEC

**版本**: v1.0  
**日期**: 2026-03-27  
**目标**: 完善 patch body 补充 + 优化分析能力

---

## 1. 现状分析

### 1.1 数据库状态

| 表 | 记录数 | 状态 |
|---|---|---|
| `cves` | 2345 | ✅ 正常 (2025-10-01 ~ 2026-03-20) |
| `patches` | 2256 | ⚠️ **body 字段 2243/2256 为空** |
| `file_changes` | 0 | ❌ 无数据 |
| `kconfig_rules` | 0 | ❌ 无数据 |

### 1.2 核心问题

**Patch Body 缺失**是最大瓶颈。`patches.body` 是 TEXT 字段，设计上存完整 diff，但 2243/2256 条为空。

**根本原因**：
- git.kernel.org 有 bot 检测，直接爬取返回 403
- GitHub 匿名 API 限流 60 req/hr，2243 条需要 **37+ 小时**串行
- `file_changes` 表无数据，因依赖 patch body 解析

---

## 2. 入口脚本

**文件**: `SKILL/cve-analyzer` (shell 脚本)

```bash
# 用法
./cve-analyzer query --severity=high --limit=10
./cve-analyzer sync --since=2026-01-01
./cve-analyzer analyze CVE-2026-23193
```

**特性**:
- 无需 `pip install`，直接调用
- PYTHONPATH 自动设置
- 数据库和配置路径自动解析到 `scripts/cve-analyzer/data/`
- 支持从任意目录调用

---

## 3. Patch Body 获取方案

### 3.1 本地 Git Clone 方案

**思路**：在 `data/` 目录下 clone stable Linux 仓库镜像，用 `git show` 本地读取 patch 内容。

**实现**：

```python
GIT_CLONE_URL = "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git"
LOCAL_REPO_PATH = Path(__file__).parent / "linux-stable.git"

def ensure_git_clone():
    """确保本地有 stable 仓库镜像"""
    if not LOCAL_REPO_PATH.exists():
        subprocess.run([
            "git", "clone", "--mirror", GIT_CLONE_URL, str(LOCAL_REPO_PATH)
        ], check=True)
    else:
        subprocess.run(["git", "remote", "update", "--prune"],
                      cwd=LOCAL_REPO_PATH)

def fetch_patch_body(commit_hash: str) -> str | None:
    """从本地 git 仓库读取 patch"""
    result = subprocess.run(
        ["git", "show", "--format=", commit_hash],
        capture_output=True, text=True,
        cwd=LOCAL_REPO_PATH
    )
    if result.returncode == 0 and len(result.stdout) > 100:
        return result.stdout
    return None
```

**优点**：
- 无网络限流，本地读取速度极快
- git.kernel.org 只被访问一次（clone/mirror update）
- 2256 条 patch 可在 **数分钟内** 完成

**缺点**：
- 首次需要 clone ~2GB 仓库
- 需要磁盘空间 (~3-5GB for mirror)

---

## 4. 实施计划

### Phase A: Patch Body 获取（最高优先级）

**Step A.1**: 编写 `git_mirror.py`，提供 clone/update 功能
**Step A.2**: 重写 `fetch_patch_bodies.py`，切换到本地 git 方案
**Step A.3**: 运行 fetch，确认所有 2256 条 patch body 入库
**Step A.4**: 验证 — `SELECT COUNT(*) FROM patches WHERE body IS NOT NULL` 应为 2256

### Phase B: File Changes 解析

**Step B.1**: 编写 `parse_patch_diff()` 函数
**Step B.2**: 批量解析所有 patch body，更新 `file_changes` 表
**Step B.3**: 验证 — `SELECT COUNT(*) FROM file_changes` > 0

### Phase C: Kconfig 推断

**Step C.1**: 建立内置文件→Kconfig 映射表
**Step C.2**: 对无 `kconfig_rules` 的 CVE，批量推断并写入
**Step C.3**: 验证 — `SELECT COUNT(*) FROM kconfig_rules` > 0

### Phase D: CLI 整合

**Step D.1**: 创建统一 CLI 命令 `fetch-all` 一键完成 A+B+C
**Step D.2**: 更新 `SKILL.md` 文档
**Step D.3**: 提交 git

---

## 5. 数据库 Schema 增强（可选）

```sql
-- 文件路径到 Kconfig 的映射规则
CREATE TABLE kconfig_mappings (
    id INTEGER PRIMARY KEY,
    file_pattern TEXT NOT NULL,      -- 如 'fs/btrfs/%'
    kconfig_name TEXT NOT NULL,     -- 如 'CONFIG_BTRFS_FS'
    confidence REAL DEFAULT 1.0,
    source TEXT DEFAULT 'builtin',   -- builtin/llm/manual
    created_at DATETIME
);

-- 从 patch body 解析出的文件变更
CREATE TABLE patch_files (
    id INTEGER PRIMARY KEY,
    patch_id INTEGER REFERENCES patches(id),
    filename TEXT NOT NULL,
    status TEXT,                    -- added/deleted/modified/renamed
    additions INTEGER DEFAULT 0,
    deletions INTEGER DEFAULT 0,
    function_name TEXT,
    created_at DATETIME
);
```

---

## 6. 验收标准

| 指标 | 目标 |
|---|---|
| `patches.body` 非空率 | ≥ 99% |
| `file_changes` 记录数 | ≥ 5000 |
| `kconfig_rules` 覆盖 | ≥ 500 CVE |
| Fetch 脚本耗时 | < 30 分钟（含首次 git clone） |
| 数据库总大小 | < 500 MB |

---

## 7. 风险与对策

| 风险 | 对策 |
|---|---|
| git.kernel.org 访问慢/超时 | 改用 GitHub mirror `https://github.com/torvalds/linux.git` |
| 首次 clone 需要 2GB | 显示进度条，允许 Ctrl+C 中断后恢复 |
| 部分 commit 在 stable 不存在 | 用 `git branch -a --contains` 查找所属分支 |

---

## 8. 依赖关系

```
Phase A (Patch Body)
    ↓
Phase B (File Changes) ←── 依赖 Phase A 完成
    ↓
Phase C (Kconfig) ←── 依赖 Phase B 完成
    ↓
Phase D (CLI 整合)
```
