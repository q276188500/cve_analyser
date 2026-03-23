# Phase 7: 报告系统开发计划

## 目标
实现 CVE 分析报告生成，支持 JSON/Markdown/HTML 三种格式。

## 功能需求

### 1. 报告内容
- CVE 基本信息（ID、描述、严重程度、CVSS）
- 补丁分析（提交哈希、受影响文件/函数）
- 版本影响分析（主线/稳定版受影响情况）
- Kconfig 配置分析（触发条件、配置依赖）
- 补丁历史追踪（fixup/revert/backport）
- 检测状态汇总

### 2. 输出格式
- **JSON**: 机器可读，包含完整数据
- **Markdown**: 人工可读，适合文档/邮件
- **HTML**: 网页展示，带样式

### 3. CLI 命令
```bash
# 生成单个 CVE 报告
cve-analyzer report CVE-2024-XXXX --format=json --output=./report.json

# 生成批量报告
cve-analyzer report --cve-list=cves.txt --format=html --output=./reports/

# 生成摘要报告
cve-analyzer report --summary --format=markdown --output=./summary.md
```

## 开发步骤
1. 设计报告数据模型
2. 实现报告生成器基类
3. 实现 JSON/Markdown/HTML 生成器
4. 添加 CLI report 命令
5. 编写测试
6. 更新 ARCHIVE.md
