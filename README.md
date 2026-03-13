# CVE Analyzer - Linux 内核 CVE 漏洞分析工具

[![Python Version](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Linux 内核 CVE 漏洞分析工具，自动化采集、分析、报告 CVE 漏洞。

## 功能特性

- **CVE 数据采集**: 从 NVD、CVE.org 等权威源自动抓取 CVE 数据
- **补丁关联分析**: 自动关联 Git commit，提取变更文件和函数
- **补丁状态检测**: 检测当前代码是否已包含修复补丁 (支持严格哈希 + 模糊匹配)
- **Kconfig 分析**: 分析漏洞触发的内核配置依赖，评估暴露风险
- **补丁历史追踪**: 追踪补丁后的 fixup/revert/重构等后续修改
- **版本影响分析**: 分析漏洞影响的内核版本范围 (mainline/stable/longterm)
- **多格式报告**: 支持 JSON/Markdown/HTML 格式报告输出

## 快速开始

### 安装

```bash
# 克隆仓库
git clone https://github.com/yourusername/cve-analyzer.git
cd cve-analyzer

# 创建虚拟环境
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 安装依赖
pip install -e ".[dev]"
```

### 初始化

```bash
# 初始化工作环境 (创建数据库等)
cve-analyzer init

# 或使用自定义配置
cve-analyzer init --config=/path/to/config.yaml

# 指定内核路径
cve-analyzer init --kernel-path=/path/to/linux
```

### 同步 CVE 数据

```bash
# 同步最近 30 天的 CVE
cve-analyzer sync --since=2024-01-01

# 同步指定 CVE
cve-analyzer sync --cve=CVE-2024-XXXX
```

### 分析 CVE

```bash
# 分析指定 CVE
cve-analyzer analyze CVE-2024-XXXX

# 深度分析
cve-analyzer analyze CVE-2024-XXXX --deep
```

### 补丁状态检测

```bash
# 检测补丁是否已应用到目标内核
cve-analyzer patch-status CVE-2024-XXXX \
    --kernel-path=/path/to/kernel \
    --version=5.15.100

# 批量检测
cve-analyzer patch-status --batch --file=cves.txt --kernel-path=/path/to/kernel
```

### Kconfig 分析

```bash
# 分析漏洞触发的配置依赖
cve-analyzer kconfig CVE-2024-XXXX \
    --kernel-version=5.15.100 \
    --config=/path/to/.config

# 审计当前配置的漏洞暴露面
cve-analyzer kconfig --audit --config=/path/to/.config
```

### 生成报告

```bash
# 生成 JSON 报告
cve-analyzer report --format=json --output=./reports/

# 生成 HTML 报告
cve-analyzer report --format=html --output=./reports/
```

## 配置

配置文件路径: `configs/config.yaml`

```yaml
# 数据目录
data_dir: "./data"
database_path: "./data/cve-analyzer.db"

# 内核配置
kernel:
  mode: "user_provided"  # 或 "auto_download"
  path: "/path/to/your/kernel"  # 用户提供模式
  # auto_download 模式配置
  repo_url: "https://git.kernel.org/.../torvalds/linux.git"
  local_path: "./data/linux"

# 数据源
data_sources:
  nvd:
    enabled: true
    api_key: "your-nvd-api-key"
  cve_org:
    enabled: true

# 分析配置
analysis:
  patch_detection:
    strategy: "both"      # strict | fuzzy | both
    min_confidence: 0.7
```

## 项目结构

```
cve-analyzer/
├── cve_analyzer/
│   ├── core/
│   │   ├── config.py       # 配置管理 (Pydantic)
│   │   ├── models.py       # 数据模型 (SQLAlchemy)
│   │   └── database.py     # 数据库操作
│   ├── fetcher/            # CVE 数据采集
│   ├── analyzer/           # 补丁分析
│   ├── patchstatus/        # 补丁状态检测
│   ├── kconfig/            # Kconfig 分析
│   ├── reporter/           # 报告生成
│   ├── utils/
│   │   └── git.py          # Git 操作封装
│   └── cli.py              # CLI 入口 (Click)
├── configs/                # 配置文件模板
├── data/                   # 数据目录 (gitignore)
├── pyproject.toml          # Python 项目配置
└── README.md
```

## 开发计划

- [x] Phase 1: 基础框架 (Week 1-2)
  - [x] 项目脚手架搭建
  - [x] 配置管理系统 (Pydantic)
  - [x] 数据库模型和存储层 (SQLAlchemy + SQLite)
  - [x] Git 操作封装 (GitPython)
  - [x] CLI 命令框架 (Click)
  - [x] 各模块接口定义
- [ ] Phase 2: CVE 数据采集 (Week 2-3)
- [ ] Phase 3: 核心分析 (Week 3-4)
- [ ] Phase 4: 补丁状态检测 (Week 4-5)
- [ ] Phase 5: Kconfig 分析 (Week 5-6)
- [ ] Phase 6: 补丁历史追踪 (Week 6-7)
- [ ] Phase 7: 报告系统 (Week 7-8)
- [ ] Phase 8: CLI 完善 (Week 8-9)
- [ ] Phase 9: 测试优化 (Week 9-10)

## 技术栈

- **Python 3.10+**
- **SQLAlchemy 2.0** - ORM
- **SQLite** - 嵌入式数据库
- **GitPython** - Git 操作
- **Click** - CLI 框架
- **Pydantic** - 配置验证
- **Rich** - 终端美化

## 贡献

欢迎贡献！请查看 [CONTRIBUTING.md](CONTRIBUTING.md) 了解如何参与。

## 许可证

[MIT License](LICENSE)

## 致谢

- [NVD](https://nvd.nist.gov/) - 国家漏洞数据库
- [CVE.org](https://www.cve.org/) - CVE 项目
- [Linux Kernel](https://www.kernel.org/) - Linux 内核
