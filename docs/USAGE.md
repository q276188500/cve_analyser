# CVE Analyzer 使用文档

> Linux 内核 CVE 漏洞分析工具 - 自动化采集、分析、报告

---

## 📋 目录

1. [安装](#安装)
2. [快速开始](#快速开始)
3. [CLI 命令详解](#cli-命令详解)
4. [配置说明](#配置说明)
5. [使用示例](#使用示例)
6. [报告系统](#报告系统)

---

## 安装

### 环境要求

- Python 3.10+
- SQLite 3
- Git (用于补丁分析)

### 从源码安装

```bash
# 克隆仓库
git clone https://github.com/q276188500/cve_analyser.git
cd cve_analyser

# 创建虚拟环境
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 安装依赖
pip install -e ".[dev]"

# 验证安装
cve-analyzer version
```

---

## 快速开始

### 1. 初始化环境

```bash
# 初始化数据库和目录结构
cve-analyzer init

# 或指定自定义数据目录
cve-analyzer init --data-dir=/path/to/data
```

### 2. 同步 CVE 数据

```bash
# 同步最近30天的 CVE
cve-analyzer sync --since=2026-01-01

# 同步指定时间段
cve-analyzer sync --since=2026-01-01 --until=2026-03-31

# 断点续传 (中断后恢复)
cve-analyzer sync --since=2026-01-01 --resume
```

### 3. 分析 CVE

```bash
# 分析指定 CVE
cve-analyzer analyze CVE-2024-XXXX

# 深度分析 (包含补丁历史)
cve-analyzer analyze CVE-2024-XXXX --deep
```

### 4. 生成报告

```bash
# 生成单个 CVE 报告
cve-analyzer report CVE-2024-XXXX --format=html --output=./reports

# 生成摘要报告
cve-analyzer report --summary --format=markdown
```

---

## CLI 命令详解

### `init` - 初始化环境

初始化工作环境，创建数据库和目录结构。

```bash
cve-analyzer init [OPTIONS]

选项:
  --kernel-path PATH    指定内核源码路径
  --data-dir PATH       指定数据目录 (默认: ./data)
  --config PATH         指定配置文件路径
```

**示例:**
```bash
# 基础初始化
cve-analyzer init

# 指定内核路径
cve-analyzer init --kernel-path=/path/to/linux

# 自定义数据目录
cve-analyzer init --data-dir=/var/lib/cve-analyzer
```

---

### `sync` - 同步 CVE 数据

从 NVD 和 CVE.org 同步 CVE 数据到本地数据库。

```bash
cve-analyzer sync [OPTIONS]

选项:
  --since DATE          起始日期 (YYYY-MM-DD)
  --until DATE          结束日期 (YYYY-MM-DD)
  --cve CVE_ID          同步指定 CVE
  --source SOURCE       数据源 (nvd/cve_org/all)
  --resume              断点续传模式
  --dry-run             模拟运行 (不保存数据)
```

**示例:**
```bash
# 同步最近一个月
cve-analyzer sync --since=2026-02-01

# 同步指定时间段
cve-analyzer sync --since=2026-01-01 --until=2026-03-31

# 同步单个 CVE
cve-analyzer sync --cve=CVE-2024-1234

# 仅使用 NVD 数据源
cve-analyzer sync --since=2026-01-01 --source=nvd

# 断点续传
cve-analyzer sync --since=2026-01-01 --resume
```

---

### `analyze` - 分析 CVE

分析指定 CVE 的补丁信息和影响范围。

```bash
cve-analyzer analyze CVE_ID [OPTIONS]

参数:
  CVE_ID                要分析的 CVE ID

选项:
  --deep                深度分析 (包含补丁历史)
  --kernel-version VER  指定目标内核版本
  --output FORMAT       输出格式 (json/markdown/html)
```

**示例:**
```bash
# 基础分析
cve-analyzer analyze CVE-2024-1234

# 深度分析
cve-analyzer analyze CVE-2024-1234 --deep

# 指定目标版本
cve-analyzer analyze CVE-2024-1234 --kernel-version=5.15.100
```

---

### `patch-status` - 检测补丁状态

检测补丁是否已应用到目标内核。

```bash
cve-analyzer patch-status CVE_ID [OPTIONS]

参数:
  CVE_ID                要检测的 CVE ID

选项:
  --kernel-path PATH    目标内核源码路径
  --version VERSION     目标内核版本
  --strategy STRATEGY   检测策略 (strict/fuzzy/both)
  --confidence FLOAT    最低置信度 (默认: 0.7)
```

**示例:**
```bash
# 检测单个 CVE
cve-analyzer patch-status CVE-2024-1234 --kernel-path=/path/to/kernel

# 批量检测
cve-analyzer patch-status --batch --file=cves.txt --kernel-path=/path/to/kernel
```

---

### `kconfig` - Kconfig 配置分析

分析漏洞触发的内核配置依赖。

```bash
cve-analyzer kconfig CVE_ID [OPTIONS]

参数:
  CVE_ID                要分析的 CVE ID

选项:
  --kernel-version VER  内核版本
  --config PATH         .config 文件路径
  --audit               审计当前配置的漏洞暴露面
```

**示例:**
```bash
# 分析 CVE 的 Kconfig 依赖
cve-analyzer kconfig CVE-2024-1234 --kernel-version=5.15.100

# 审计配置
cve-analyzer kconfig --audit --config=/path/to/.config
```

---

### `patch-history` - 补丁历史追踪

追踪补丁后的 fixup/revert/重构等后续修改。

```bash
cve-analyzer patch-history CVE_ID COMMIT_HASH [OPTIONS]

参数:
  CVE_ID                CVE ID
  COMMIT_HASH           补丁提交哈希

选项:
  --kernel-path PATH    内核源码路径
  --limit N             显示条目数 (默认: 20)
  --show-fixups         仅显示 fixup 变更
  --show-reverts        仅显示 revert 变更
```

**示例:**
```bash
# 追踪补丁历史
cve-analyzer patch-history CVE-2024-1234 abc123def --kernel-path=/path/to/linux

# 仅显示 revert
cve-analyzer patch-history CVE-2024-1234 abc123def --show-reverts
```

---

### `report` - 生成报告

生成 CVE 分析报告 (JSON/Markdown/HTML)。

```bash
cve-analyzer report [CVE_ID] [OPTIONS]

参数:
  CVE_ID                CVE ID (可选，与 --summary/--cve-list 互斥)

选项:
  --format FORMAT       报告格式 (json/markdown/html，默认: markdown)
  --output PATH         输出目录 (默认: .)
  --cve-list PATH       CVE ID 列表文件
  --summary             生成摘要报告
```

**示例:**
```bash
# 生成单个 CVE 的 HTML 报告
cve-analyzer report CVE-2024-1234 --format=html --output=./reports

# 生成 Markdown 摘要
cve-analyzer report --summary --format=markdown

# 批量生成 JSON 报告
cve-analyzer report --cve-list=cves.txt --format=json --output=./batch_reports

# 生成所有高危 CVE 的 HTML 报告
cve-analyzer report --summary --format=html --output=./high_risk_reports
```

---

### `query` - 查询漏洞数据库

按条件查询本地 CVE 数据库。

```bash
cve-analyzer query [OPTIONS]

选项:
  --severity LEVEL      按严重程度过滤 (critical/high/medium/low)
  --since DATE          起始日期
  --keyword KEYWORD     关键词搜索
  --limit N             返回数量限制 (默认: 100)
```

**示例:**
```bash
# 查询高危漏洞
cve-analyzer query --severity=high --limit=50

# 关键词搜索
cve-analyzer query --keyword="use-after-free" --limit=20
```

---

### `version` - 显示版本

```bash
cve-analyzer version
```

---

## 配置说明

### 配置文件位置

默认配置文件路径：`configs/config.yaml`

### 配置示例

```yaml
# 数据目录配置
data_dir: "./data"
database_path: "./data/cve-analyzer.db"

# 日志配置
log_level: "INFO"  # DEBUG/INFO/WARNING/ERROR
log_file: "./data/cve-analyzer.log"

# 内核配置
kernel:
  mode: "user_provided"  # 或 "auto_download"
  path: "/path/to/your/kernel"  # 用户提供模式
  
  # auto_download 模式配置
  repo_url: "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git"
  local_path: "./data/linux"

# 数据源配置
data_sources:
  nvd:
    enabled: true
    api_key: "your-nvd-api-key"  # 可选，提高请求频率
  cve_org:
    enabled: true

# 分析配置
analysis:
  patch_detection:
    strategy: "both"      # strict | fuzzy | both
    min_confidence: 0.7   # 最低置信度
  
  # 网络请求配置
  request:
    timeout: 30
    retries: 3
    rate_limit: 6  # 每秒请求数
```

### 环境变量

| 变量名 | 说明 | 示例 |
|--------|------|------|
| `CVE_ANALYZER_CONFIG` | 配置文件路径 | `/path/to/config.yaml` |
| `CVE_ANALYZER_DATA_DIR` | 数据目录 | `/var/lib/cve-analyzer` |
| `NVD_API_KEY` | NVD API Key | `your-api-key` |

---

## 使用示例

### 场景 1: 评估生产环境漏洞风险

```bash
# 1. 初始化
cve-analyzer init --kernel-path=/path/to/production/kernel

# 2. 同步最新 CVE
cve-analyzer sync --since=2026-01-01

# 3. 分析高危 CVE
cve-analyzer query --severity=high --limit=50 > high_risk_cves.txt

# 4. 检测补丁状态
cve-analyzer patch-status --batch --file=high_risk_cves.txt \
    --kernel-path=/path/to/production/kernel \
    --version=5.15.100

# 5. 生成 HTML 报告
cve-analyzer report --summary --format=html --output=./risk_assessment
```

### 场景 2: 新内核版本安全评估

```bash
# 1. 分析特定版本的漏洞暴露面
cve-analyzer kconfig --audit --config=/path/to/new/kernel/.config

# 2. 检查未修复的高危漏洞
cve-analyzer query --severity=high | while read cve; do
    cve-analyzer patch-status "$cve" --kernel-path=/path/to/new/kernel
done
```

### 场景 3: 定期安全监控

```bash
#!/bin/bash
# daily-scan.sh

DATE=$(date +%Y-%m-%d)
REPORT_DIR="./reports/$DATE"

# 同步最新 CVE
cve-analyzer sync --since=$(date -d '7 days ago' +%Y-%m-%d)

# 生成日报
cve-analyzer report --summary --format=html --output="$REPORT_DIR"

# 发送邮件 (需配置邮件客户端)
mail -s "CVE Daily Report $DATE" security@company.com < "$REPORT_DIR/summary_report.html"
```

---

## 报告系统

### 报告格式对比

| 格式 | 用途 | 特点 |
|------|------|------|
| **JSON** | 自动化处理 | 机器可读，包含完整数据 |
| **Markdown** | 人工阅读 | 简洁，适合邮件/文档 |
| **HTML** | 展示分享 | 带样式，适合浏览器查看 |

### 报告内容

单个 CVE 报告包含:
- **基本信息** - CVE ID、描述、严重程度、CVSS 评分
- **补丁信息** - 提交哈希、作者、受影响文件/函数
- **版本影响** - 主线/稳定版/长期支持版受影响情况
- **Kconfig 分析** - 配置依赖、风险评估
- **补丁历史** - fixup/revert/backport 追踪
- **检测状态** - 补丁是否已应用到目标内核

---

## 故障排除

### 数据库锁定错误

```bash
# 删除 WAL 文件
rm data/*.db-wal data/*.db-shm

# 重新初始化
cve-analyzer init
```

### NVD API 限流

```bash
# 1. 申请 NVD API Key (https://nvd.nist.gov/developers/request-an-api-key)
# 2. 配置 API Key
export NVD_API_KEY=your-api-key

# 或使用低频率模式
cve-analyzer sync --since=2026-01-01 --rate-limit=3
```

### Git 操作失败

```bash
# 检查内核源码路径
cve-analyzer init --kernel-path=/valid/path/to/linux

# 确保有 Git 历史
cd /path/to/linux && git log --oneline -5
```

---

## 开发贡献

### 运行测试

```bash
# 运行所有测试
pytest tests/

# 运行特定测试
pytest tests/test_reporter.py -v

# 生成覆盖率报告
pytest --cov=cve_analyzer tests/
```

---

## 获取帮助

```bash
# 查看帮助
cve-analyzer --help

# 查看子命令帮助
cve-analyzer sync --help
cve-analyzer report --help
```

---

**版本**: v0.4.0  
**文档更新**: 2026-03-16  
**作者**: 小葱明 🌱
