"""
HTML 报告生成器
"""

from typing import Optional
from pathlib import Path

from cve_analyzer.reporter.base import ReportGenerator
from cve_analyzer.reporter.models import CVEReport, SummaryReport


class HTMLReportGenerator(ReportGenerator):
    """HTML 格式报告生成器"""
    
    # 基础 CSS 样式
    CSS_STYLES = """
    <style>
        * { box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
        }
        .container {
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            padding: 30px;
        }
        h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
        h2 { color: #34495e; margin-top: 30px; border-left: 4px solid #3498db; padding-left: 15px; }
        h3 { color: #555; }
        .badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: bold;
            text-transform: uppercase;
        }
        .badge-critical { background: #e74c3c; color: white; }
        .badge-high { background: #e67e22; color: white; }
        .badge-medium { background: #f39c12; color: white; }
        .badge-low { background: #27ae60; color: white; }
        .badge-unknown { background: #95a5a6; color: white; }
        .info-box {
            background: #ecf0f1;
            padding: 15px;
            border-radius: 6px;
            margin: 15px 0;
        }
        .info-box p { margin: 5px 0; }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background: #34495e;
            color: white;
            font-weight: 600;
        }
        tr:hover { background: #f5f5f5; }
        code {
            background: #f4f4f4;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: "Consolas", "Monaco", monospace;
            font-size: 14px;
        }
        .patch-box {
            border: 1px solid #ddd;
            border-radius: 6px;
            padding: 15px;
            margin: 15px 0;
            background: #fafafa;
        }
        .risk-high { color: #e74c3c; font-weight: bold; }
        .risk-medium { color: #e67e22; }
        .risk-low { color: #27ae60; }
        .footer {
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
            color: #7f8c8d;
            font-size: 12px;
        }
        ul { padding-left: 20px; }
        li { margin: 5px 0; }
    </style>
    """
    
    def generate(self, report: CVEReport, filename: Optional[str] = None) -> str:
        """生成 HTML 报告"""
        if filename is None:
            output_path = self._get_output_path(report.cve_id, "html")
        else:
            output_path = self.output_dir / filename
        
        content = self._render_report(report)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(content)
        
        return str(output_path)
    
    def generate_summary(self, report: SummaryReport, filename: Optional[str] = None) -> str:
        """生成 HTML 摘要报告"""
        if filename is None:
            filename = "summary_report.html"
        output_path = self.output_dir / filename
        
        content = self._render_summary(report)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(content)
        
        return str(output_path)
    
    def _render_report(self, report: CVEReport) -> str:
        """渲染单个 CVE 报告"""
        html_parts = []
        
        html_parts.append("<!DOCTYPE html>")
        html_parts.append('<html lang="zh-CN">')
        html_parts.append("<head>")
        html_parts.append(f'<title>{report.cve_id} 漏洞分析报告</title>')
        html_parts.append('<meta charset="UTF-8">')
        html_parts.append(self.CSS_STYLES)
        html_parts.append("</head>")
        html_parts.append("<body>")
        html_parts.append('<div class="container">')
        
        # 标题
        html_parts.append(f'<h1>{report.cve_id} 漏洞分析报告</h1>')
        
        # 基本信息
        html_parts.append('<h2>基本信息</h2>')
        html_parts.append('<div class="info-box">')
        html_parts.append(f'<p><strong>CVE ID:</strong> {report.cve_id}</p>')
        html_parts.append(f'<p><strong>严重程度:</strong> {self._severity_badge(report.severity)}</p>')
        if report.cvss_score:
            html_parts.append(f'<p><strong>CVSS 评分:</strong> {report.cvss_score}</p>')
        html_parts.append(f'<p><strong>发布日期:</strong> {report.published_date or "未知"}</p>')
        html_parts.append(f'<p><strong>最后更新:</strong> {report.last_modified or "未知"}</p>')
        html_parts.append('</div>')
        
        # 描述
        if report.description:
            html_parts.append('<h2>漏洞描述</h2>')
            html_parts.append(f'<p>{report.description}</p>')
        
        # 补丁信息
        if report.patches:
            html_parts.append('<h2>补丁信息</h2>')
            for i, patch in enumerate(report.patches, 1):
                html_parts.append('<div class="patch-box">')
                html_parts.append(f'<h3>补丁 #{i}</h3>')
                html_parts.append(f'<p><strong>提交哈希:</strong> <code>{patch.commit_hash}</code></p>')
                if patch.commit_hash_short:
                    html_parts.append(f'<p><strong>短哈希:</strong> <code>{patch.commit_hash_short}</code></p>')
                html_parts.append(f'<p><strong>主题:</strong> {patch.subject}</p>')
                html_parts.append(f'<p><strong>作者:</strong> {patch.author}</p>')
                if patch.author_date:
                    html_parts.append(f'<p><strong>提交日期:</strong> {patch.author_date}</p>')
                
                if patch.files_changed:
                    html_parts.append('<p><strong>受影响文件:</strong></p>')
                    html_parts.append('<ul>')
                    for f in patch.files_changed[:10]:
                        html_parts.append(f'<li><code>{f}</code></li>')
                    if len(patch.files_changed) > 10:
                        html_parts.append(f'<li>... 还有 {len(patch.files_changed) - 10} 个文件</li>')
                    html_parts.append('</ul>')
                
                html_parts.append('</div>')
        
        # Kconfig 分析
        if report.kconfig_analysis:
            html_parts.append('<h2>Kconfig 配置分析</h2>')
            html_parts.append('<div class="info-box">')
            risk_class = f"risk-{report.kconfig_analysis.risk_level}"
            html_parts.append(f'<p><strong>风险等级:</strong> <span class="{risk_class}">{report.kconfig_analysis.risk_level}</span></p>')
            html_parts.append(f'<p><strong>当前配置易受攻击:</strong> {"是" if report.kconfig_analysis.is_vulnerable else "否"}</p>')
            if report.kconfig_analysis.trigger_configs:
                html_parts.append('<p><strong>触发配置:</strong></p>')
                html_parts.append('<ul>')
                for cfg in report.kconfig_analysis.trigger_configs:
                    html_parts.append(f'<li><code>{cfg}</code></li>')
                html_parts.append('</ul>')
            html_parts.append('</div>')
        
        # 补丁历史
        if report.patch_history:
            html_parts.append('<h2>补丁历史</h2>')
            html_parts.append('<table>')
            html_parts.append('<tr><th>类型</th><th>提交</th><th>作者</th><th>风险</th></tr>')
            for h in report.patch_history:
                risk_class = f"risk-{h.risk_level}"
                html_parts.append(f'<tr><td>{h.change_type}</td><td><code>{h.commit_hash[:8]}</code></td><td>{h.author}</td><td class="{risk_class}">{h.risk_level}</td></tr>')
            html_parts.append('</table>')
        
        # 检测状态
        if report.detection_status:
            html_parts.append('<h2>检测状态</h2>')
            html_parts.append('<table>')
            html_parts.append('<tr><th>目标版本</th><th>状态</th><th>检测方法</th><th>置信度</th></tr>')
            for d in report.detection_status:
                confidence = f"{d.confidence * 100:.1f}%" if d.confidence else "N/A"
                method = d.detection_method or "N/A"
                html_parts.append(f'<tr><td>{d.target_version}</td><td>{d.status}</td><td>{method}</td><td>{confidence}</td></tr>')
            html_parts.append('</table>')
        
        # 页脚
        html_parts.append('<div class="footer">')
        html_parts.append(f'<p>报告生成时间: {report.generated_at}</p>')
        html_parts.append('</div>')
        
        html_parts.append('</div>')
        html_parts.append('</body>')
        html_parts.append('</html>')
        
        return "\n".join(html_parts)
    
    def _render_summary(self, report: SummaryReport) -> str:
        """渲染摘要报告"""
        html_parts = []
        
        html_parts.append("<!DOCTYPE html>")
        html_parts.append('<html lang="zh-CN">')
        html_parts.append("<head>")
        html_parts.append('<title>CVE 分析摘要报告</title>')
        html_parts.append('<meta charset="UTF-8">')
        html_parts.append(self.CSS_STYLES)
        html_parts.append("</head>")
        html_parts.append("<body>")
        html_parts.append('<div class="container">')
        
        html_parts.append('<h1>CVE 分析摘要报告</h1>')
        html_parts.append(f'<p><strong>生成时间:</strong> {report.generated_at}</p>')
        
        # 统计
        html_parts.append('<h2>统计概览</h2>')
        html_parts.append('<div class="info-box">')
        html_parts.append(f'<p><strong>CVE 总数:</strong> {report.total_cves}</p>')
        html_parts.append('</div>')
        
        if report.by_severity:
            html_parts.append('<h3>按严重程度</h3>')
            html_parts.append('<table>')
            html_parts.append('<tr><th>严重程度</th><th>数量</th></tr>')
            for severity, count in sorted(report.by_severity.items()):
                html_parts.append(f'<tr><td>{self._severity_badge(severity)}</td><td>{count}</td></tr>')
            html_parts.append('</table>')
        
        if report.high_risk_cves:
            html_parts.append('<h2>高风险 CVE</h2>')
            html_parts.append('<ul>')
            for cve_id in report.high_risk_cves:
                html_parts.append(f'<li>{cve_id}</li>')
            html_parts.append('</ul>')
        
        html_parts.append('</div>')
        html_parts.append('</body>')
        html_parts.append('</html>')
        
        return "\n".join(html_parts)
    
    def _severity_badge(self, severity: str) -> str:
        """严重程度徽章"""
        badges = {
            "critical": '<span class="badge badge-critical">Critical</span>',
            "high": '<span class="badge badge-high">High</span>',
            "medium": '<span class="badge badge-medium">Medium</span>',
            "low": '<span class="badge badge-low">Low</span>',
            "unknown": '<span class="badge badge-unknown">Unknown</span>',
        }
        return badges.get(severity.lower(), severity)
