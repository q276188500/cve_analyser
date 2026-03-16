"""
Markdown 报告生成器
"""

from typing import Optional
from pathlib import Path

from cve_analyzer.reporter.base import ReportGenerator
from cve_analyzer.reporter.models import CVEReport, SummaryReport


class MarkdownReportGenerator(ReportGenerator):
    """Markdown 格式报告生成器"""
    
    def generate(self, report: CVEReport, filename: Optional[str] = None) -> str:
        """生成 Markdown 报告"""
        if filename is None:
            output_path = self._get_output_path(report.cve_id, "md")
        else:
            output_path = self.output_dir / filename
        
        content = self._render_report(report)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(content)
        
        return str(output_path)
    
    def generate_summary(self, report: SummaryReport, filename: Optional[str] = None) -> str:
        """生成 Markdown 摘要报告"""
        if filename is None:
            filename = "summary_report.md"
        output_path = self.output_dir / filename
        
        content = self._render_summary(report)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(content)
        
        return str(output_path)
    
    def _render_report(self, report: CVEReport) -> str:
        """渲染单个 CVE 报告"""
        lines = []
        
        # 标题
        lines.append(f"# {report.cve_id} 漏洞分析报告")
        lines.append("")
        
        # 基本信息
        lines.append("## 基本信息")
        lines.append("")
        lines.append(f"- **CVE ID**: {report.cve_id}")
        lines.append(f"- **严重程度**: {self._severity_badge(report.severity)}")
        if report.cvss_score:
            lines.append(f"- **CVSS 评分**: {report.cvss_score}")
        lines.append(f"- **发布日期**: {report.published_date or '未知'}")
        lines.append(f"- **最后更新**: {report.last_modified or '未知'}")
        lines.append("")
        
        # 描述
        if report.description:
            lines.append("## 漏洞描述")
            lines.append("")
            lines.append(report.description)
            lines.append("")
        
        # 补丁信息
        if report.patches:
            lines.append("## 补丁信息")
            lines.append("")
            for i, patch in enumerate(report.patches, 1):
                lines.append(f"### 补丁 #{i}")
                lines.append("")
                lines.append(f"- **提交哈希**: `{patch.commit_hash}`")
                if patch.commit_hash_short:
                    lines.append(f"- **短哈希**: `{patch.commit_hash_short}`")
                lines.append(f"- **主题**: {patch.subject}")
                lines.append(f"- **作者**: {patch.author}")
                if patch.author_date:
                    lines.append(f"- **提交日期**: {patch.author_date}")
                lines.append("")
                
                if patch.files_changed:
                    lines.append("**受影响文件**:")
                    for f in patch.files_changed[:10]:  # 最多显示10个
                        lines.append(f"- `{f}`")
                    if len(patch.files_changed) > 10:
                        lines.append(f"- ... 还有 {len(patch.files_changed) - 10} 个文件")
                    lines.append("")
                
                if patch.backported_to:
                    lines.append(f"**已回溯到**: {', '.join(patch.backported_to)}")
                if patch.not_backported_to:
                    lines.append(f"**未回溯到**: {', '.join(patch.not_backported_to)}")
                lines.append("")
        
        # 版本影响
        if report.version_impact:
            lines.append("## 版本影响")
            lines.append("")
            if report.version_impact.mainline_affected:
                lines.append(f"- **主线受影响**: {', '.join(report.version_impact.mainline_affected)}")
            if report.version_impact.stable_affected:
                lines.append(f"- **稳定版受影响**: {', '.join(report.version_impact.stable_affected)}")
            lines.append("")
        
        # Kconfig 分析
        if report.kconfig_analysis:
            lines.append("## Kconfig 配置分析")
            lines.append("")
            lines.append(f"- **风险等级**: {report.kconfig_analysis.risk_level}")
            lines.append(f"- **当前配置易受攻击**: {'是' if report.kconfig_analysis.is_vulnerable else '否'}")
            if report.kconfig_analysis.trigger_configs:
                lines.append("- **触发配置**:")
                for cfg in report.kconfig_analysis.trigger_configs:
                    lines.append(f"  - `{cfg}`")
            lines.append("")
        
        # 补丁历史
        if report.patch_history:
            lines.append("## 补丁历史")
            lines.append("")
            lines.append("| 类型 | 提交 | 作者 | 风险 |")
            lines.append("|------|------|------|------|")
            for h in report.patch_history:
                lines.append(f"| {h.change_type} | `{h.commit_hash[:8]}` | {h.author} | {h.risk_level} |")
            lines.append("")
        
        # 检测状态
        if report.detection_status:
            lines.append("## 检测状态")
            lines.append("")
            lines.append("| 目标版本 | 状态 | 检测方法 | 置信度 |")
            lines.append("|----------|------|----------|--------|")
            for d in report.detection_status:
                confidence = f"{d.confidence * 100:.1f}%" if d.confidence else "N/A"
                lines.append(f"| {d.target_version} | {d.status} | {d.detection_method or 'N/A'} | {confidence} |")
            lines.append("")
        
        # 页脚
        lines.append("---")
        lines.append(f"*报告生成时间: {report.generated_at}*")
        lines.append("")
        
        return "\n".join(lines)
    
    def _render_summary(self, report: SummaryReport) -> str:
        """渲染摘要报告"""
        lines = []
        
        lines.append("# CVE 分析摘要报告")
        lines.append("")
        lines.append(f"**生成时间**: {report.generated_at}")
        lines.append("")
        
        # 统计
        lines.append("## 统计概览")
        lines.append("")
        lines.append(f"- **CVE 总数**: {report.total_cves}")
        lines.append("")
        
        if report.by_severity:
            lines.append("### 按严重程度")
            lines.append("")
            for severity, count in sorted(report.by_severity.items()):
                lines.append(f"- {severity}: {count}")
            lines.append("")
        
        if report.by_status:
            lines.append("### 按状态")
            lines.append("")
            for status, count in sorted(report.by_status.items()):
                lines.append(f"- {status}: {count}")
            lines.append("")
        
        # 高风险 CVE
        if report.high_risk_cves:
            lines.append("## 高风险 CVE")
            lines.append("")
            for cve_id in report.high_risk_cves:
                lines.append(f"- [{cve_id}](./{cve_id.lower().replace('-', '_')}_report.md)")
            lines.append("")
        
        # 详细列表
        if report.cves:
            lines.append("## 详细列表")
            lines.append("")
            for r in report.cves:
                lines.append(f"### {r.cve_id}")
                lines.append("")
                lines.append(f"- 严重程度: {self._severity_badge(r.severity)}")
                if r.cvss_score:
                    lines.append(f"- CVSS: {r.cvss_score}")
                lines.append(f"- 描述: {r.description[:100]}..." if len(r.description) > 100 else f"- 描述: {r.description}")
                lines.append("")
        
        return "\n".join(lines)
    
    def _severity_badge(self, severity: str) -> str:
        """严重程度标签"""
        badges = {
            "critical": "🔴 Critical",
            "high": "🟠 High",
            "medium": "🟡 Medium",
            "low": "🟢 Low",
            "unknown": "⚪ Unknown",
        }
        return badges.get(severity.lower(), severity)
