# Patch Impact Agent - 技术规范

## 1. 项目概述

**项目名称**: Patch Impact Agent  
**类型**: 领域专用 Agent (Linux 内核补丁影响分析)  
**核心目标**: 接收社区 patch，分析其对业务的影响，评估合入必要性

---

## 2. 功能需求

### 2.1 核心能力

| 能力 | 描述 | 优先级 |
|------|------|--------|
| **Patch 解析** | 解析 diff 内容，提取变更文件、函数、代码块 | P0 |
| **自规划分析** | 根据 patch 内容自动规划分析步骤 | P0 |
| **影响评估** | 从功能、性能、兼容性角度评估影响 | P0 |
| **知识检索** | 从领域知识库检索相关约束和上下文 | P0 |
| **合入建议** | 给出是否合入的建议及详细理由 | P0 |
| **报告输出** | 终端友好输出 + 文件归档 | P0 |

### 2.2 输入输出

**输入**:
- Patch diff 字符串 (直接粘贴)
- Patch 文件路径 (本地文件)
- (可选) 上下文信息

**输出**:
- 终端彩色输出 (人类友好)
- JSON 格式报告 (归档)
- Markdown 格式报告 (归档)

---

## 3. 架构设计

### 3.1 系统架构

```
┌─────────────────────────────────────────────────────────────┐
│                    Patch Impact Agent                        │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    │
│  │   Input     │───▶│  Analyzer   │───▶│   Output    │    │
│  │  Parser     │    │   Engine    │    │  Formatter  │    │
│  └─────────────┘    └──────┬──────┘    └─────────────┘    │
│                            │                                │
│                     ┌──────▼──────┐                        │
│                     │  Knowledge  │                        │
│                     │   Base      │                        │
│                     │  (RAG)      │                        │
│                     └─────────────┘                        │
└─────────────────────────────────────────────────────────────┘
```

### 2.2 核心模块

```
patch-impact-agent/
├── agent/
│   ├── __init__.py
│   ├── parser.py        # Patch 解析器
│   ├── planner.py       # 自规划引擎
│   ├── analyzer.py      # 影响分析器
│   ├── knowledge.py     # 知识库检索
│   └── recommender.py   # 合入建议生成
├── knowledge/
│   ├── __init__.py
│   ├── base.py          # 知识库基类
│   ├── loader.py        # 知识加载器
│   └── rules/           # 领域规则 (测试用)
├── output/
│   ├── __init__.py
│   ├── terminal.py      # 终端输出
│   └── report.py        # 报告生成
├── cli.py               # CLI 入口
├── api.py               # API 服务 (可选)
└── deploy.py            # 部署脚本
```

---

## 4. 知识库设计

### 4.1 知识条目结构

```yaml
# 知识库条目示例
id: "rule-001"
type: "constraint"  # constraint | context | reference
title: "禁止使用可变参数宏"
description: "不允许使用 ##__VA_ARGS__ 等可变参数宏，存在安全风险"
severity: "critical  # critical | high | medium | low
domain: "coding_style"
tags: ["安全", "宏", "代码规范"]
```

### 4.2 测试知识库 (初始)

| ID | 类型 | 规则内容 | 期望 Agent 行为 |
|----|------|----------|-----------------|
| rule-001 | constraint | 禁止修改 fs/namespace.c | 检测到修改则标记风险 |
| rule-001 | constraint | net/core/ 下禁止新增 GFP_ATOMIC 分配 | 评估内存分配策略影响 |
| rule-003 | constraint | 删除 EXPORT_SYMBOL 需要 review 通过 | 给出合入风险警告 |
| rule-004 | context |drivers/virtio/ 与容器安全相关 | 关联安全上下文 |
| rule-005 | reference | 类似 CVE-2021-43287 修复 | 提供历史参考 |

---

## 5. 分析流程

### 5.1 自规划流程

```
1. 接收 Patch
      │
      ▼
2. 解析 Diff
   - 提取文件列表
   - 提取函数变更
   - 识别变更类型 (add/modify/delete)
      │
      ▼
3. 规划分析任务
   [基础分析] 必选
   [性能分析] 涉及循环/内存操作时触发
   [安全分析] 涉及用户输入/权限时触发
   [兼容性分析] 涉及 API 变更时触发
      │
      ▼
4. 执行分析
   - 并行: 代码理解 + 知识检索
   - 综合评估
      │
      ▼
5. 生成建议
```

### 5.2 评估维度

| 维度 | 评估内容 | 输出等级 |
|------|----------|----------|
| **功能影响** | 变更的功能是什么？是否为核心功能？ | 🔴高 / 🟡中 / 🟢低 |
| **性能影响** | 是否有性能退化风险？复杂度变化？ | 🔴高 / 🟡中 / 🟢低 |
| **兼容性** | 是否破坏 API/ABI？是否影响升级？ | 🔴高 / 🟡中 / 🟢低 |
| **安全影响** | 是否有安全风险？是否修复安全漏洞？ | 🔴高 / 🟡中 / 🟢低 |
| **合入建议** | 建议合入 / 需 review / 暂不 合入 | ✅建议 / ⚠️谨慎 / ❌不推荐 |

---

## 6. 输出格式

### 6.1 终端输出

```
╔════════════════════════════════════════════════════════════╗
║          🔍 Patch 影响分析报告                              ║
╠════════════════════════════════════════════════════════════╣
║ 📄 文件: net/core/skbuff.c                                   ║
║ 📝 提交: a1b2c3d4e5f6 (fix: prevent use-after-free)         ║
║ 📊 变更: +15 -8 (23 行)                                      ║
╠════════════════════════════════════════════════════════════╣
║ 📌 功能影响: 🟡 中                                            ║
║    - 修改了 skb_release_data() 释放逻辑                     ║
║    - 涉及内存管理，属于核心网络栈                            ║
╠════════════════════════════════════════════════════════════╣
║ 📌 性能影响: 🟢 低                                            ║
║    - 未引入新循环，未增加复杂度                              ║
║    - 释放逻辑优化，可能提升性能                              ║
╠════════════════════════════════════════════════════════════╣
║ 📌 安全影响: 🔴 高                                            ║
║    - 修复 use-after-free (CVE-2024-XXXX)                    ║
║    - 建议优先合入                                            ║
╠════════════════════════════════════════════════════════════╣
║ 📌 合入建议: ✅ 建议合入                                       ║
║    理由: 安全修复，影响范围可控，建议优先合入                ║
╚════════════════════════════════════════════════════════════╝
```

### 6.2 JSON 报告

```json
{
  "metadata": {
    "analyzer": "patch-impact-agent",
    "version": "0.1.0",
    "timestamp": "2026-03-18T09:00:00Z",
    "input_type": "diff_string"
  },
  "patch_summary": {
    "files_changed": ["net/core/skbuff.c"],
    "lines_added": 15,
    "lines_deleted": 8,
    "commit": "a1b2c3d4e5f6"
  },
  "analysis": {
    "functional_impact": {
      "level": "medium",
      "description": "修改了 skb_release_data() 释放逻辑",
      "risk_factors": ["涉及内存管理", "核心网络栈"]
    },
    "performance_impact": {
      "level": "low",
      "description": "未引入新循环，释放逻辑优化"
    },
    "security_impact": {
      "level": "high",
      "cve_fixes": ["CVE-2024-XXXX"],
      "description": "修复 use-after-free"
    },
    "compatibility_impact": {
      "level": "low",
      "description": "内部实现变更，未影响 API"
    }
  },
  "recommendation": {
    "action": "merge",
    "confidence": 0.9,
    "reason": "安全修复，影响范围可控，建议优先合入",
    "requires_review": false
  },
  "knowledge_matches": [
    {
      "rule_id": "rule-004",
      "title": "drivers/virtio/ 与容器安全相关",
      "relevance": "low"
    }
  ]
}
```

---

## 7. 部署设计

### 7.1 独立部署

```bash
# 方式1: 直接运行
pip install -e .
patch-agent analyze -f patch.diff

# 方式2: Docker
docker build -t patch-agent .
docker run patch-agent analyze -f patch.diff
```

### 7.2 与 cve-analyzer 集成

```bash
# 一键统一部署
./deploy.py --project cve-analyzer
```

部署后 cve-analyzer 可通过 API 调用 agent:

```python
from cve_analyzer.integrations import PatchImpactAgent

agent = PatchImpactAgent()
result = agent.analyze(patch_content)
```

### 7.3 依赖

- Python 3.10+
- openai / anthropic (可配置)
- 知识库: 本地 Markdown/JSON 文件 (可扩展向量库)

---

## 8. 验收标准

### 功能验收

- [ ] 能解析标准 diff 格式
- [ ] 能解析 git format-patch 格式
- [ ] 自规划能力: 根据 patch 内容选择分析路径
- [ ] 知识检索: 能从知识库匹配相关规则
- [ ] 影响评估: 给出功能/性能/安全/兼容性评估
- [ ] 合入建议: 给出明确建议及理由

### 输出验收

- [ ] 终端输出美观易读
- [ ] JSON 报告格式正确
- [ ] 报告自动归档到 `reports/` 目录
- [ ] 文件命名: `patch-analysis-{timestamp}.json`

### 部署验收

- [ ] 独立 CLI 可运行
- [ ] 一键部署脚本正常
- [ ] cve-analyzer 能调用 agent

---

## 9. 下一步

1. 创建测试知识库 (rules/)
2. 实现核心模块
3. 编写测试用例
4. 部署验证

---

_Last updated: 2026-03-18_
