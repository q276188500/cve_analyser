# Output Formatter - 输出格式化

import json
from datetime import datetime
from typing import Dict, Any

# 颜色代码
class Colors:
    RESET = "\033[0m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    DIM = "\033[2m"


LEVEL_ICONS = {
    "high": "🔴",
    "medium": "🟡", 
    "low": "🟢"
}

ACTION_ICONS = {
    "merge": "✅",
    "review": "⚠️",
    "defer": "❌"
}

def _level_color(level: str) -> str:
    """获取等级对应的颜色"""
    if level == "high":
        return Colors.RED
    elif level == "medium":
        return Colors.YELLOW
    return Colors.GREEN


def format_terminal(result) -> str:
    """格式化终端输出"""
    lines = []
    
    # 标题
    lines.append("")
    lines.append(f"{Colors.BOLD}{Colors.CYAN}╔════════════════════════════════════════════════════════════╗{Colors.RESET}")
    lines.append(f"{Colors.BOLD}{Colors.CYAN}║          🔍 Patch 影响分析报告                              ║{Colors.RESET}")
    if result.llm_enabled:
        lines.append(f"{Colors.BOLD}{Colors.CYAN}║          🤖 LLM 增强分析                                    ║{Colors.RESET}")
    lines.append(f"{Colors.BOLD}{Colors.CYAN}╚════════════════════════════════════════════════════════════╝{Colors.RESET}")
    lines.append("")
    
    # LLM 元数据
    if result.llm_enabled and result.llm_result.get("_metadata"):
        meta = result.llm_result["_metadata"]
        lines.append(f"  🤖 模型: {meta.get('model', 'N/A')} | Tokens: {meta.get('tokens', 0)} | 成本: ${meta.get('cost', 0):.4f}")
        lines.append("")
    
    # 基本信息
    lines.append(f"  📄 变更文件: {len(result.files_changed)} 个")
    for f in result.files_changed[:5]:
        lines.append(f"     - {f}")
    if len(result.files_changed) > 5:
        lines.append(f"     ... 还有 {len(result.files_changed) - 5} 个")
    
    lines.append(f"  📊 代码行: +{result.lines_added} -{result.lines_deleted}")
    if result.commit:
        lines.append(f"  🔗 提交: {result.commit[:12]}")
    
    lines.append("")
    lines.append(f"{Colors.DIM}{'─' * 60}{Colors.RESET}")
    lines.append("")
    
    # 如果有 LLM 结果，显示 LLM 分析
    if result.llm_enabled and result.llm_result.get("summary"):
        lines.append(f"  📝 {Colors.BOLD}LLM 摘要{Colors.RESET}")
        lines.append(f"     {result.llm_result['summary']}")
        lines.append("")
        lines.append(f"{Colors.DIM}{'─' * 60}{Colors.RESET}")
        lines.append("")
    
    # 功能影响
    impact = result.functional_impact
    if result.llm_enabled and result.llm_result.get("functional_impact"):
        impact_level = result.llm_result["functional_impact"].get("level", impact.level)
        impact_desc = result.llm_result["functional_impact"].get("description", impact.description)
    else:
        impact_level = impact.level
        impact_desc = impact.description
    
    icon = LEVEL_ICONS.get(impact_level, "⚪")
    level_color = _level_color(impact_level)
    lines.append(f"  📌 功能影响: {level_color}{icon} {impact_level.upper()}{Colors.RESET}")
    if impact_desc:
        lines.append(f"     {impact_desc}")
    if impact.risk_factors:
        for rf in impact.risk_factors[:3]:
            lines.append(f"     {Colors.YELLOW}⚠️ {rf}{Colors.RESET}")
    
    lines.append("")
    
    # 性能影响
    impact = result.performance_impact
    if result.llm_enabled and result.llm_result.get("performance_impact"):
        impact_level = result.llm_result["performance_impact"].get("level", impact.level)
        impact_desc = result.llm_result["performance_impact"].get("description", impact.description)
    else:
        impact_level = impact.level
        impact_desc = impact.description
    
    icon = LEVEL_ICONS.get(impact_level, "⚪")
    level_color = _level_color(impact_level)
    lines.append(f"  📌 性能影响: {level_color}{icon} {impact_level.upper()}{Colors.RESET}")
    if impact_desc:
        lines.append(f"     {impact_desc}")
    
    lines.append("")
    
    # 安全影响
    impact = result.security_impact
    if result.llm_enabled and result.llm_result.get("security_impact"):
        impact_level = result.llm_result["security_impact"].get("level", impact.level)
        impact_desc = result.llm_result["security_impact"].get("description", impact.description)
    else:
        impact_level = impact.level
        impact_desc = impact.description
    
    icon = LEVEL_ICONS.get(impact_level, "⚪")
    level_color = _level_color(impact_level)
    lines.append(f"  📌 安全影响: {level_color}{icon} {impact_level.upper()}{Colors.RESET}")
    if impact_desc:
        lines.append(f"     {impact_desc}")
    if impact.risk_factors:
        for rf in impact.risk_factors[:3]:
            lines.append(f"     {Colors.RED}🔒 {rf}{Colors.RESET}")
    
    lines.append("")
    
    # 兼容性影响
    impact = result.compatibility_impact
    if result.llm_enabled and result.llm_result.get("compatibility_impact"):
        impact_level = result.llm_result["compatibility_impact"].get("level", impact.level)
        impact_desc = result.llm_result["compatibility_impact"].get("description", impact.description)
    else:
        impact_level = impact.level
        impact_desc = impact.description
    
    icon = LEVEL_ICONS.get(impact_level, "⚪")
    level_color = _level_color(impact_level)
    lines.append(f"  📌 兼容性影响: {level_color}{icon} {impact_level.upper()}{Colors.RESET}")
    if impact_desc:
        lines.append(f"     {impact_desc}")
    if impact.risk_factors:
        for rf in impact.risk_factors[:3]:
            lines.append(f"     {Colors.YELLOW}⚠️ {rf}{Colors.RESET}")
    
    lines.append("")
    lines.append(f"{Colors.DIM}{'─' * 60}{Colors.RESET}")
    lines.append("")
    
    # 知识库匹配
    if result.knowledge_matches:
        lines.append(f"  📚 知识库匹配: {len(result.knowledge_matches)} 条")
        for match in result.knowledge_matches[:3]:
            severity = match.get('severity', 'low')
            severity_color = Colors.RED if severity == 'critical' else Colors.YELLOW
            lines.append(f"     - [{severity_color}{severity.upper()}{Colors.RESET}] {match.get('title', '')}")
        if len(result.knowledge_matches) > 3:
            lines.append(f"     ... 还有 {len(result.knowledge_matches) - 3} 条")
        lines.append("")
    
    # 业务影响 (LLM 特有)
    if result.llm_enabled and result.llm_result.get("business_impact"):
        lines.append(f"  💼 {Colors.BOLD}业务影响{Colors.RESET}")
        lines.append(f"     {result.llm_result['business_impact']}")
        lines.append("")
    
    # 合入建议
    rec = result.recommendation
    action = rec.get('action', 'unknown')
    action_icon = ACTION_ICONS.get(action, "⚪")
    
    if rec.get('source') == 'llm':
        action_color = Colors.CYAN
    else:
        action_color = Colors.GREEN if action == 'merge' else Colors.YELLOW
        if action == 'defer':
            action_color = Colors.RED
    
    lines.append(f"  🎯 合入建议: {action_color}{action_icon} {action.upper()}{Colors.RESET}")
    lines.append(f"     {rec.get('reason', '')}")
    if rec.get('requires_review'):
        lines.append(f"     {Colors.YELLOW}⚠️ 需要进行代码 review{Colors.RESET}")
    
    lines.append("")
    
    return "\n".join(lines)


def format_json(result) -> str:
    """格式化 JSON 输出"""
    data = {
        "metadata": {
            "analyzer": "patch-impact-agent",
            "version": result.analyzer_version,
            "timestamp": result.timestamp,
            "input_type": result.input_type,
            "llm_enabled": result.llm_enabled
        },
        "patch_summary": {
            "files_changed": result.files_changed,
            "lines_added": result.lines_added,
            "lines_deleted": result.lines_deleted,
            "commit": result.commit
        },
        "analysis": {
            "functional_impact": {
                "level": result.functional_impact.level,
                "description": result.functional_impact.description,
                "risk_factors": result.functional_impact.risk_factors
            },
            "performance_impact": {
                "level": result.performance_impact.level,
                "description": result.performance_impact.description,
                "risk_factors": result.performance_impact.risk_factors
            },
            "security_impact": {
                "level": result.security_impact.level,
                "description": result.security_impact.description,
                "risk_factors": result.security_impact.risk_factors,
                "cve_fixes": getattr(result.security_impact, 'cve_fixes', [])
            },
            "compatibility_impact": {
                "level": result.compatibility_impact.level,
                "description": result.compatibility_impact.description,
                "risk_factors": result.compatibility_impact.risk_factors
            }
        },
        "knowledge_matches": result.knowledge_matches,
        "llm_analysis": result.llm_result if result.llm_enabled else None,
        "recommendation": result.recommendation
    }
    
    return json.dumps(data, indent=2, ensure_ascii=False)


def format_markdown(result) -> str:
    """格式化 Markdown 输出"""
    lines = []
    
    # 标题
    lines.append("# Patch 影响分析报告")
    lines.append("")
    lines.append(f"**分析时间**: {result.timestamp}")
    lines.append(f"**分析版本**: {result.analyzer_version}")
    lines.append("")
    
    # 基本信息
    lines.append("## 📊 Patch 摘要")
    lines.append("")
    lines.append(f"- **变更文件**: {len(result.files_changed)} 个")
    lines.append(f"  ```")
    for f in result.files_changed:
        lines.append(f"  - {f}")
    lines.append(f"  ```")
    lines.append(f"- **代码行**: +{result.lines_added} / -{result.lines_deleted}")
    if result.commit:
        lines.append(f"- **提交**: `{result.commit[:12]}`")
    lines.append("")
    
    # 影响评估
    lines.append("## 📈 影响评估")
    lines.append("")
    
    # 功能影响
    level = result.functional_impact.level
    lines.append(f"### 功能影响: {level.upper()}")
    lines.append(result.functional_impact.description)
    if result.functional_impact.risk_factors:
        lines.append("**风险因素**:")
        for rf in result.functional_impact.risk_factors:
            lines.append(f"- {rf}")
    lines.append("")
    
    # 性能影响
    level = result.performance_impact.level
    lines.append(f"### 性能影响: {level.upper()}")
    lines.append(result.performance_impact.description)
    lines.append("")
    
    # 安全影响
    level = result.security_impact.level
    lines.append(f"### 安全影响: {level.upper()}")
    lines.append(result.security_impact.description)
    if result.security_impact.risk_factors:
        lines.append("**风险因素**:")
        for rf in result.security_impact.risk_factors:
            lines.append(f"- {rf}")
    lines.append("")
    
    # 兼容性
    level = result.compatibility_impact.level
    lines.append(f"### 兼容性影响: {level.upper()}")
    lines.append(result.compatibility_impact.description)
    lines.append("")
    
    # 知识库
    if result.knowledge_matches:
        lines.append("## 📚 知识库匹配")
        lines.append("")
        for match in result.knowledge_matches:
            severity = match.get('severity', 'low')
            lines.append(f"- **[{severity.upper()}]** {match.get('title', '')}: {match.get('description', '')[:100]}...")
        lines.append("")
    
    # 建议
    rec = result.recommendation
    action = rec.get('action', 'unknown').upper()
    lines.append("## 🎯 合入建议")
    lines.append("")
    lines.append(f"**建议**: {action}")
    lines.append("")
    lines.append(f"**理由**: {rec.get('reason', '')}")
    if rec.get('requires_review'):
        lines.append("")
        lines.append("> ⚠️ 需要进行代码 review")
    lines.append("")
    
    return "\n".join(lines)


def save_report(result, output_dir: str = "reports", formats: list = None) -> Dict[str, str]:
    """保存报告到文件"""
    import os
    from pathlib import Path
    
    if formats is None:
        formats = ["json"]
    
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # 生成文件名
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    saved = {}
    
    if "json" in formats:
        json_path = output_dir / f"patch-analysis-{timestamp}.json"
        with open(json_path, 'w', encoding='utf-8') as f:
            f.write(format_json(result))
        saved["json"] = str(json_path)
    
    if "markdown" in formats:
        md_path = output_dir / f"patch-analysis-{timestamp}.md"
        with open(md_path, 'w', encoding='utf-8') as f:
            f.write(format_markdown(result))
        saved["markdown"] = str(md_path)
    
    return saved
