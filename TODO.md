# CVE Analyzer 待实现功能

## 待测试功能 (已实现 CLI)
- [x] version - 版本信息
- [x] init - 初始化环境
- [x] query - 查询 CVE
- [x] sync - 同步 CVE 数据
- [x] analyze - 分析 CVE
- [x] patch-status - 补丁检测 (显示部分，需完善)
- [ ] patch-status - 内核源码检测 (需完善)
- [ ] kconfig - Kconfig 分析 (待实现)
- [ ] patch-history - 追踪补丁历史
- [ ] report - 生成报告
- [ ] llm-analyze - 大模型分析

## 待开发功能

### 1. patch-status 内核源码检测
- **优先级**: 高
- **描述**: 基于内核源码检测补丁是否已应用
- **依赖**: 需要内核源码目录
- **功能**:
  - 使用 CommitHashDetector 检测 commit 是否存在
  - 使用 FileHashDetector 检测文件修改
  - 使用 ContentMatcher 检测代码特征
- **状态**: CLI 有接口，检测逻辑需完善

### 2. kconfig 配置分析
- **优先级**: 中
- **描述**: 分析 CVE 触发的内核配置依赖
- **依赖**: 需要 .config 配置文件
- **状态**: 待实现

### 3. 补丁信息抓取
- **状态**: ✅ 已完成 (2251 个补丁)

---

_Last updated: 2026-03-17_
