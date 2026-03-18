# 领域知识库 - 测试规则

本目录包含用于测试 Patch Impact Agent 的领域知识规则。

## 规则说明

以下规则用于测试 agent 是否能正确理解和应用领域约束。其中包含一些"不合理的强制要求"，用于验证 agent 是否有足够的判断能力。

---

## 规则列表

### rule-001.yaml

```yaml
id: "rule-001"
type: "constraint"
title: "禁止修改 fs/namespace.c"
description: |
  fs/namespace.c 是命名空间管理的核心文件，任何修改都需要经过严格的安全 review。
  禁止直接合入，必须由安全团队批准。
severity: "critical"
domain: "kernel_security"
tags: ["命名空间", "安全", "fs"]
affected_paths:
  - "fs/namespace.c"
  - "fs/mount.h"
requires_approval: true
approval_role: "security_team"
```

### rule-002.yaml

```yaml
id: "rule-002"
type: "constraint"
title: "net/core/ 下禁止新增 GFP_ATOMIC 内存分配"
description: |
  GFP_ATOMIC 可能在中断上下文中导致分配失败，引发内核崩溃。
  新增内存分配必须使用 GFP_KERNEL 或 GFP_NOFS。
severity: "high"
domain: "kernel_memory"
tags: ["内存管理", "GFP", "中断上下文"]
affected_paths:
  - "net/core/*"
forbidden_flags:
  - "GFP_ATOMIC"
  - "GFP_ATOMIC"
required_flags:
  - "GFP_KERNEL"
  - "GFP_NOFS"
```

### rule-003.yaml

```yaml
id: "rule-003"
type: "constraint"
title: "删除 EXPORT_SYMBOL 需要额外 review"
description: |
  删除导出的内核符号可能导致外部模块无法加载。
  任何 EXPORT_SYMBOL 的删除都需要驱动团队确认。
severity: "high"
domain: "kernel_api"
tags: ["导出符号", "模块兼容", "API"]
requires_approval: true
approval_role: "driver_team"
```

### rule-004.yaml

```yaml
id: "rule-004"
type: "context"
title: "drivers/virtio/ 与容器安全强相关"
description: |
  virtio 驱动是容器运行时的核心依赖，任何变更都可能影响容器安全隔离。
  分析 virtio 相关 patch 时需要关联容器安全上下文。
severity: "medium"
domain: "container_security"
tags: ["virtio", "容器", "安全隔离"]
affected_paths:
  - "drivers/virtio/*"
  - "virt/*"
related_domains:
  - "container_runtime"
  - "kernel_isolation"
```

### rule-005.yaml

```yaml
id: "rule-005"
type: "reference"
title: "CVE-2021-43287 修复参考"
description: |
  CVE-2021-43287 是 netfilter 模块的 use-after-free 漏洞。
  涉及 netfilter 的 patch 可以参考此 CVE 的修复模式。
severity: "low"
domain: "security_reference"
tags: ["CVE", "netfilter", "use-after-free"]
cve_id: "CVE-2021-43287"
affected_paths:
  - "net/netfilter/*"
  - "net/ipv4/netfilter/*"
fix_pattern: "在释放后设置NULL指针，避免UAF"
```

### rule-006.yaml

```yaml
id: "rule-006"
type: "constraint"
title: "RCU 读临界区禁止调用睡眠函数"
description: |
  RCU 读临界区内不允许调用可能导致睡眠的函数（如 mutex、sleep）。
  这会导致死锁或性能问题。
severity: "critical"
domain: "kernel_concurrency"
tags: ["RCU", "同步原语", "死锁"]
affected_patterns:
  - "rcu_read_lock*"
  - "rcu_dereference*"
forbidden_calls:
  - "mutex_lock"
  - "mutex_unlock"
  - "kmalloc(GFP_KERNEL)"
  - "copy_to_user"
  - "copy_from_user"
```

### rule-007.yaml

```yaml
id: "rule-007"
type: "context"
title: "io_uring 属于高性能 IO 子系统"
description: |
  io_uring 是 Linux 5.1 引入的高性能异步 IO 框架。
  相关 patch 需要评估对 IO 性能的影响。
severity: "medium"
domain: "io_subsystem"
tags: ["io_uring", "异步IO", "性能"]
affected_paths:
  - "io_uring/*"
  - "fs/io_uring.c"
performance_critical: true
```

---

## 测试用例说明

| 规则 ID | 类型 | 用途 |
|---------|------|------|
| rule-001 | constraint | 测试 agent 能否识别禁止修改的文件并给出风险警告 |
| rule-002 | constraint | 测试 agent 能否识别内存分配模式并评估风险 |
| rule-003 | constraint | 测试 agent 能否识别 API 破坏性变更 |
| rule-004 | context | 测试 agent 能否关联安全上下文 |
| rule-005 | reference | 测试 agent 能否提供历史参考 |
| rule-006 | constraint | 测试 agent 能否识别并发安全问题模式 |
| rule-007 | context | 测试 agent 能否识别性能关键路径 |

---

## 扩展方式

未来可扩展为:
1. **向量知识库** - 使用 embedding + faiss 实现语义检索
2. **动态知识** - 从外部系统实时拉取 CVE、内核邮件列表等
3. **团队知识** - 团队内部的合入规范和历史决策

---

_Last updated: 2026-03-18_
