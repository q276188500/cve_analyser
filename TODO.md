# CVE Analyzer 待实现功能

## 待测试功能 (已实现 CLI)
- [x] version - 版本信息
- [x] init - 初始化环境
- [x] query - 查询 CVE
- [x] sync - 同步 CVE 数据
- [x] analyze - 分析 CVE
- [x] patch-status - 补丁检测
- [x] kconfig - Kconfig 分析 (已实现基础框架)
- [ ] patch-history - 追踪补丁历史
- [ ] report - 生成报告
- [ ] llm-analyze - 大模型分析

## 待开发功能

### 1. Kconfig 规则自动生成 (严格模式)
- **优先级**: 高
- **原则**: 宁可漏报，不可误报
- **数据来源**:
  1. 补丁修改的文件路径 → 推断 Kconfig
  2. CVE 描述关键词 (明确提到)
  3. NVD CWE 信息
- **不推断的情况**:
  - 描述中没有明确提到配置项
  - 无法确定文件对应的 Kconfig
- **映射规则**:
  - fs/* → CONFIG_FS (需要细分)
  - net/* → CONFIG_NET
  - drivers/virtio/* → CONFIG_VIRTIO
  - 明确提到的 CONFIG_XXX → 直接采用
- **状态**: 待实现

### 2. patch-status 内核源码检测
- **优先级**: 高
- **描述**: 基于内核源码检测补丁是否已应用
- **状态**: CLI 有接口，检测逻辑需完善

### 3. 完整报告生成
- **优先级**: 中
- **描述**: 整合 CVE 信息 + Kconfig 风险 + 补丁状态
- **状态**: 待完善

---

_Last updated: 2026-03-17_
