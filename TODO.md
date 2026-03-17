# CVE Analyzer 待实现功能

## 待测试功能 (已实现 CLI)
- [ ] patch-history - 追踪补丁历史
- [ ] kconfig - 分析 Kconfig 配置依赖
- [ ] report - 生成报告
- [ ] llm-analyze - 大模型分析

## 待开发功能

### 1. 补丁信息抓取
- **优先级**: 高
- **描述**: sync 命令需要添加补丁抓取功能，从 Git Security 获取补丁 commit
- **待添加选项**: `--fetch-patches`
- **数据源**: git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git
- **状态**: 未实现

### 2. 暂无补丁数据的 CVE 测试
- **说明**: 当前 487 条 CVE 都无补丁信息，需要有补丁的 CVE 来测试 patch-status 功能

---

_Last updated: 2026-03-17_
