"""
CLI 命令行接口
使用 Click 框架
"""

import asyncio
import os
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from cve_analyzer.core.config import load_settings, get_settings
from cve_analyzer.core.database import Database, get_db
from cve_analyzer.core.config import Settings

console = Console()


# ============================================
# 辅助函数
# ============================================

def print_banner():
    """打印程序横幅"""
    banner = """
    ╔═══════════════════════════════════════════╗
    ║     CVE Analyzer - Linux 内核漏洞分析工具   ║
    ║                                           ║
    ║     自动化采集 · 补丁分析 · 风险评估        ║
    ╚═══════════════════════════════════════════╝
    """
    console.print(Panel(banner, style="cyan"))


def get_db_instance() -> Database:
    """获取数据库实例"""
    return get_db()


# ============================================
# CLI 主入口
# ============================================

@click.group()
@click.option(
    "--config", "-c",
    type=click.Path(exists=True),
    help="配置文件路径"
)
@click.option("--verbose", "-v", is_flag=True, help="详细输出")
@click.pass_context
def cli(ctx: click.Context, config: Optional[str], verbose: bool):
    """
    Linux 内核 CVE 漏洞分析工具
    
    功能：采集 CVE 数据、分析补丁、检测修复状态、评估 Kconfig 风险
    
    示例：
        cve-analyzer init                    # 初始化环境
        cve-analyzer sync --since=2024-01-01 # 同步 CVE 数据
        cve-analyzer analyze CVE-2024-XXXX   # 分析指定 CVE
    """
    # 确保上下文对象存在
    ctx.ensure_object(dict)
    
    # 加载配置
    settings = load_settings(config)
    ctx.obj["settings"] = settings
    ctx.obj["verbose"] = verbose
    
    if verbose:
        console.print(f"[dim]配置加载完成: {settings.data_dir}[/dim]")


# ============================================
# init 命令
# ============================================

@cli.command()
@click.option(
    "--kernel-path",
    type=click.Path(exists=True),
    help="指定内核源码路径"
)
@click.pass_context
def init(ctx: click.Context, kernel_path: Optional[str]):
    """
    初始化工具环境
    
    执行内容：
    1. 创建数据目录结构
    2. 初始化 SQLite 数据库
    3. 配置内核源码路径 (可选)
    """
    print_banner()
    
    settings: Settings = ctx.obj["settings"]
    
    console.print("[bold green]开始初始化...[/bold green]")
    
    # 1. 创建数据目录
    data_dir = Path(settings.data_dir)
    data_dir.mkdir(parents=True, exist_ok=True)
    console.print(f"✓ 数据目录: [cyan]{data_dir}[/cyan]")
    
    # 2. 初始化数据库
    db = Database(settings.database_path)
    db.create_tables()
    console.print(f"✓ 数据库: [cyan]{settings.database_path}[/cyan]")
    
    # 3. 如果指定了内核路径，更新配置
    if kernel_path:
        settings.kernel.path = kernel_path
        settings.kernel.mode = "user_provided"
        console.print(f"✓ 内核路径: [cyan]{kernel_path}[/cyan]")
    
    console.print("\n[bold green]初始化完成![/bold green]")
    console.print("\n下一步建议:")
    console.print("  cve-analyzer sync --since=2024-01-01  # 同步 CVE 数据")


# ============================================
# sync 命令
# ============================================

@cli.command()
@click.option("--since", help="同步起始日期 (YYYY-MM-DD)")
@click.option("--until", help="同步结束日期 (YYYY-MM-DD)，默认今天")
@click.option("--source", help="指定数据源 (nvd/cve-org/all)", default="all")
@click.option("--dry-run", is_flag=True, help="模拟运行，不保存到数据库")
@click.option("--resume", is_flag=True, help="启用断点续传模式")
@click.option("--clear-state", is_flag=True, help="清除断点续传状态")
@click.pass_context
def sync(ctx: click.Context, since: Optional[str], until: Optional[str], source: str, dry_run: bool, resume: bool, clear_state: bool):
    """
    同步 CVE 数据
    
    从 NVD、CVE.org 等数据源同步 CVE 数据到本地数据库
    
    示例：
        cve-analyzer sync                           # 同步最近 30 天
        cve-analyzer sync --since=2024-01-01        # 从指定日期同步
        cve-analyzer sync --since=2026-01-01 --until=2026-03-31  # 指定时间段
        cve-analyzer sync --source=nvd              # 只同步 NVD
        cve-analyzer sync --dry-run                 # 模拟运行
    """
    from datetime import datetime, timedelta
    from cve_analyzer.fetcher.orchestrator import FetchOrchestrator
    from cve_analyzer.core.database import CVERepository, get_db
    from cve_analyzer.core.models import SyncLog
    
    # 确定起始日期
    if not since:
        since_date = (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%d")
    else:
        since_date = since
    
    # 确定结束日期
    if not until:
        until_date = datetime.now().strftime("%Y-%m-%d")
    else:
        until_date = until
    
    console.print(f"[bold green]开始同步 CVE 数据...[/bold green]")
    console.print(f"时间范围: [cyan]{since_date}[/cyan] ~ [cyan]{until_date}[/cyan]")
    console.print(f"数据源: [cyan]{source}[/cyan]")
    if dry_run:
        console.print("[yellow]模拟模式: 数据不会保存到数据库[/yellow]")
    if resume:
        console.print("[blue]断点续传: 启用[/blue]")
    console.print()
    
    # 处理清除状态
    if clear_state:
        from cve_analyzer.fetcher.nvd import NVDFetcher
        fetcher = NVDFetcher()
        fetcher.clear_state()
        console.print("[green]断点续传状态已清除[/green]")
        return
    
    # 创建协调器
    orchestrator = FetchOrchestrator()
    
    # 记录开始时间
    start_time = datetime.utcnow()
    
    try:
        from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(bar_width=40),
            TaskProgressColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("[cyan]正在抓取 CVE 数据...", total=100)
            
            def progress_callback(current, total, message):
                if total > 0:
                    progress.update(task, completed=int(current * 100 / total), description=f"[cyan]{message}")
            
            result = orchestrator.fetch_all(since=since_date, until=until_date, 
                                           progress_callback=progress_callback, resume=resume)
        
        console.print(f"[bold green]✓ 抓取完成![/bold green]")
        console.print()
        
        # 统计信息
        stats_table = Table(title="同步统计")
        stats_table.add_column("指标", style="cyan")
        stats_table.add_column("数值", style="magenta")
        
        stats_table.add_row("总获取", str(result.total))
        stats_table.add_row("新增", str(result.new))
        stats_table.add_row("更新", str(result.updated))
        stats_table.add_row("失败", str(result.failed))
        
        if result.errors:
            stats_table.add_row("错误数", f"[red]{len(result.errors)}[/red]")
        
        console.print(stats_table)
        console.print()
        
        # 严重程度分布
        if result.cves:
            severity_counts = {}
            for cve in result.cves:
                sev = cve.severity or "UNKNOWN"
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
            
            sev_table = Table(title="严重程度分布")
            sev_table.add_column("严重程度", style="cyan")
            sev_table.add_column("数量", style="magenta")
            
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
                if sev in severity_counts:
                    count = severity_counts[sev]
                    color = {
                        "CRITICAL": "red",
                        "HIGH": "orange3",
                        "MEDIUM": "yellow",
                        "LOW": "green",
                        "UNKNOWN": "dim",
                    }.get(sev, "white")
                    sev_table.add_row(f"[{color}]{sev}[/{color}]", str(count))
            
            console.print(sev_table)
            console.print()
        
        # 显示部分 CVE (在保存前提取数据)
        preview_data = []
        for cve in result.cves[:5]:
            preview_data.append({
                'id': cve.id,
                'severity': cve.severity,
                'description': cve.description or "",
            })
        
        # 保存到数据库
        if not dry_run and result.cves:
            with console.status("[bold green]正在保存到数据库..."):
                db = get_db()
                
                with db.session() as session:
                    repo = CVERepository(session)
                    
                    saved_count = 0
                    for cve in result.cves:
                        try:
                            repo.create_or_update(cve)
                            saved_count += 1
                        except Exception as e:
                            console.print(f"[red]保存 {cve.id} 失败: {e}[/red]")
                    
                    # 记录同步日志
                    end_time = datetime.utcnow()
                    sync_log = SyncLog(
                        source=source.upper(),
                        status="SUCCESS" if not result.errors else "PARTIAL",
                        start_time=start_time,
                        end_time=end_time,
                        total_count=result.total,
                        new_count=result.new,
                        update_count=result.updated,
                        error_count=result.failed,
                        errors=[str(e) for e in result.errors] if result.errors else None,
                    )
                    session.add(sync_log)
                
                console.print(f"[green]✓ 已保存 {saved_count} 个 CVE 到数据库[/green]")
        
        # 显示预览
        if preview_data:
            console.print()
            cve_table = Table(title="部分 CVE 预览")
            cve_table.add_column("CVE ID", style="cyan")
            cve_table.add_column("严重程度", style="yellow")
            cve_table.add_column("描述", style="dim", max_width=50)
            
            for item in preview_data:
                desc = item['description'][:47] + "..." if len(item['description']) > 50 else item['description']
                color = {
                    "CRITICAL": "red",
                    "HIGH": "orange3",
                    "MEDIUM": "yellow",
                    "LOW": "green",
                }.get(item['severity'], "white")
                
                cve_table.add_row(
                    item['id'],
                    f"[{color}]{item['severity'] or 'UNKNOWN'}[/{color}]",
                    desc
                )
            
            if len(result.cves) > 5:
                cve_table.add_row("...", "...", f"还有 {len(result.cves) - 5} 个...")
            
            console.print(cve_table)
    
    except Exception as e:
        console.print(f"[red]同步失败: {e}[/red]")
        import traceback
        console.print(traceback.format_exc())


# ============================================
# analyze 命令
# ============================================

@cli.command()
@click.argument("cve-id")
@click.option("--deep", is_flag=True, help="深度分析")
@click.pass_context
def analyze(ctx: click.Context, cve_id: str, deep: bool):
    """
    分析指定 CVE
    
    CVE-ID: CVE 编号，如 CVE-2024-XXXX
    
    分析内容包括：
    - 漏洞基本信息
    - 关联补丁提取
    - 影响版本分析
    - 受影响文件和函数
    """
    from cve_analyzer.core.database import get_db
    from cve_analyzer.core.models import CVE
    
    db = get_db()
    
    with db.session() as session:
        cve = session.query(CVE).filter(CVE.id == cve_id.upper()).first()
        
        if not cve:
            console.print(f"[red]未找到 CVE: {cve_id}[/red]")
            return
        
        # 显示基本信息
        console.print("\n[bold cyan]═══════════════════════════════════════[/bold cyan]")
        console.print(f"[bold]  {cve.id}[/bold]")
        console.print("[bold cyan]═══════════════════════════════════════[/bold cyan]")
        
        # 严重程度和分数
        severity = cve.severity or "UNKNOWN"
        severity_color = {
            "CRITICAL": "red bold",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "green",
        }.get(severity, "white")
        
        cvss = cve.cvss_score
        cvss_str = f" CVSS {cvss}" if cvss else ""
        console.print(f"[{severity_color}]严重程度: {severity}{cvss_str}[/{severity_color}]")
        
        # 日期
        if cve.published_date:
            console.print(f"发布日期: {cve.published_date.strftime('%Y-%m-%d')}")
        if cve.last_modified:
            console.print(f"更新时间: {cve.last_modified.strftime('%Y-%m-%d')}")
        
        # 描述
        console.print("\n[bold]漏洞描述:[/bold]")
        desc = cve.description or "无描述"
        # 限制描述长度
        if len(desc) > 500:
            desc = desc[:500] + "..."
        console.print(f"  {desc}")
        
        # 参考链接
        if cve.references:
            console.print("\n[bold]参考链接:[/bold]")
            for ref in cve.references[:5]:  # 最多显示 5 个
                console.print(f"  - {ref.url}")
        
        console.print()


# ============================================
# patch-status 命令
# ============================================

@cli.command("patch-status")
@click.argument("cve-id")
@click.option("--kernel-path", type=click.Path(exists=True), help="内核源码路径")
@click.option("--version", help="内核版本号")
@click.option("--detection", type=click.Choice(["hash", "content", "both"]), default="both", help="检测策略")
@click.pass_context
def patch_status(
    ctx: click.Context,
    cve_id: str,
    kernel_path: Optional[str],
    version: Optional[str],
    detection: Optional[str],
):
    """
    检测补丁应用状态
    
    检测指定的 CVE 修复补丁是否已应用到目标内核代码中
    
    检测策略：
    - hash: 严格哈希匹配
    - content: 模糊内容匹配
    - both: 两者结合 (默认)
    """
    from cve_analyzer.core.database import get_db
    from cve_analyzer.core.models import CVE, Patch
    
    db = get_db()
    
    with db.session() as session:
        # 获取 CVE 及其补丁信息
        cve = session.query(CVE).filter(CVE.id == cve_id.upper()).first()
        
        if not cve:
            console.print(f"[red]未找到 CVE: {cve_id}[/red]")
            return
        
        console.print("\n[bold cyan]═══════════════════════════════════════[/bold cyan]")
        console.print(f"[bold]  补丁检测: {cve.id}[/bold]")
        console.print("[bold cyan]═══════════════════════════════════════[/bold cyan]")
        
        # 目标版本
        if version:
            console.print(f"目标内核版本: {version}")
        
        # 检测策略
        console.print(f"检测策略: {detection or 'both'}")
        
        # 补丁信息
        patches = session.query(Patch).filter(Patch.cve_id == cve.id).all()
        
        if not patches:
            console.print("\n[yellow]该 CVE 暂无补丁信息[/yellow]")
            console.print("提示: 补丁信息需要在 sync 时从数据源获取")
            return
        
        console.print(f"\n[bold]找到 {len(patches)} 个补丁记录:[/bold]")
        
        for i, patch in enumerate(patches[:5], 1):
            console.print(f"\n  [{i}] {patch.commit_hash[:12]}...")
            if patch.commit_hash_short:
                console.print(f"      短哈希: {patch.commit_hash_short}")
            if patch.description:
                desc = patch.description[:100]
                console.print(f"      描述: {desc}...")
        
        # 检测状态
        console.print("\n[bold]检测结果:[/bold]")
        
        if kernel_path:
            console.print(f"[yellow]⚠ 内核源码检测需要配置内核路径: {kernel_path}[/yellow]")
            console.print("提示: 使用 --kernel-path 指定内核源码进行实际检测")
        else:
            console.print("[dim]未指定内核源码路径，仅显示补丁信息[/dim]")
            console.print("提示: 使用 --kernel-path /path/to/linux 进行实际检测")
        
        console.print()


# ============================================
# kconfig 命令
# ============================================

@cli.command()
@click.argument("cve-id")
@click.option("--kernel-version", help="内核版本号")
@click.option("--config", "config_path", type=click.Path(exists=True), help=".config 文件路径")
@click.option("--audit", is_flag=True, help="审计当前配置")
@click.pass_context
def kconfig(
    ctx: click.Context,
    cve_id: str,
    kernel_version: Optional[str],
    config_path: Optional[str],
    audit: bool,
):
    """
    分析 Kconfig 配置依赖
    
    分析指定 CVE 漏洞触发所需的内核配置项及依赖关系
    
    示例：
        cve-analyzer kconfig CVE-2024-XXXX --config=/path/to/.config
        cve-analyzer kconfig --audit --config=/path/to/.config
    """
    console.print(f"[yellow]分析 Kconfig {cve_id} - 待实现 (Phase 5)[/yellow]")
    if audit:
        console.print("审计模式")
    if config_path:
        console.print(f"配置文件: {config_path}")


# ============================================
# patch-history 命令
# ============================================

@cli.command("patch-history")
@click.argument("cve-id")
@click.option("--kernel-path", type=click.Path(exists=True), help="内核源码路径")
@click.option("--show-all", is_flag=True, help="显示所有变更")
@click.option("--show-fixups", is_flag=True, help="显示 fixup 提交")
@click.option("--show-reverts", is_flag=True, help="显示 revert 提交")
@click.option("--show-conflicts", is_flag=True, help="显示冲突解决")
@click.option("--limit", default=20, help="最大结果数")
@click.pass_context
def patch_history(
    ctx: click.Context,
    cve_id: str,
    kernel_path: Optional[str],
    show_all: bool,
    show_fixups: bool,
    show_reverts: bool,
    show_conflicts: bool,
    limit: int,
):
    """
    追踪补丁修改历史 (Phase 6)
    
    查看补丁的后续修改，包括:
    - fixup: 修复补丁
    - revert: 回退提交
    - refactor: 重构修改
    - conflict: 冲突解决
    
    示例:
        cve-analyzer patch-history CVE-2024-XXXX
        cve-analyzer patch-history CVE-2024-XXXX --kernel-path=/path/to/linux
        cve-analyzer patch-history CVE-2024-XXXX --show-reverts
    """
    from cve_analyzer.history import HistoryAnalyzer, ChangeType
    
    # 获取数据库会话
    db = ctx.ensure_object(dict).get('db')
    
    with console.status("[bold green]正在查询数据库..."):
        from cve_analyzer.core.models import CVE, Patch
        
        cve = db.query(CVE).filter(CVE.cve_id == cve_id).first()
        if not cve:
            console.print(f"[red]错误: 数据库中未找到 {cve_id}[/red]")
            console.print(f"请先运行: cve-analyzer sync --cve={cve_id}")
            return
        
        # 获取补丁信息
        patches = db.query(Patch).filter(Patch.cve_id == cve_id).all()
        if not patches:
            console.print(f"[red]错误: 未找到 {cve_id} 的补丁信息[/red]")
            return
    
    # 使用第一个补丁进行历史追踪
    patch = patches[0]
    patch_commit = patch.commit_hash
    
    if not patch_commit:
        console.print(f"[red]错误: 补丁没有关联的 commit hash[/red]")
        return
    
    # 初始化追踪器
    try:
        tracker_path = kernel_path or ctx.obj.get('kernel_path')
        analyzer = HistoryAnalyzer()
        if tracker_path:
            from cve_analyzer.history import GitHistoryTracker
            analyzer.tracker = GitHistoryTracker(tracker_path)
    except Exception as e:
        console.print(f"[red]初始化失败: {e}[/red]")
        return
    
    # 执行历史追踪
    with console.status(f"[bold green]正在追踪补丁 {patch_commit[:12]} 的历史..."):
        try:
            result = analyzer.analyze(patch_commit, cve_id)
        except Exception as e:
            console.print(f"[red]追踪失败: {e}[/red]")
            return
    
    # 显示结果
    console.print()
    console.print(Panel(
        f"[bold cyan]{cve_id}[/bold cyan]\n"
        f"补丁: [yellow]{patch_commit[:12]}[/yellow] - {result.original_subject[:50]}...",
        title="🔍 补丁历史追踪",
        border_style="green"
    ))
    
    # 显示汇总信息
    if result.summary:
        summary_table = Table(title="📊 变更汇总")
        summary_table.add_column("类型", style="cyan")
        summary_table.add_column("数量", justify="right", style="magenta")
        
        for change_type, count in result.summary.items():
            if change_type != "total" and count > 0:
                emoji = {
                    "fixup": "🔧",
                    "revert": "↩️",
                    "refactor": "♻️",
                    "backport": "📦",
                    "conflict_fix": "⚔️",
                    "follow_up": "📎",
                    "cve_related": "📌",  # ⭐ 新增
                    "unknown": "❓",
                }.get(change_type, "•")
                summary_table.add_row(f"{emoji} {change_type}", str(count))
        
        summary_table.add_row("[bold]总计[/bold]", str(result.summary.get("total", 0)), style="bold")
        console.print(summary_table)
    
    # 显示风险评估
    if result.analysis.get("risk_assessment"):
        risk = result.analysis["risk_assessment"]
        risk_color = {"low": "green", "medium": "yellow", "high": "red"}.get(risk["level"], "white")
        
        console.print()
        console.print(Panel(
            f"[bold {risk_color}]风险等级: {risk['level'].upper()}[/bold {risk_color}]\n"
            f"风险评分: {risk['score']}/100\n"
            + (f"\n[yellow]风险因素:[/yellow]\n" + "\n".join(f"  • {f}" for f in risk["factors"]) if risk["factors"] else "")
            + (f"\n\n[green]缓解措施:[/green]\n" + "\n".join(f"  ✓ {m}" for m in risk["mitigations"]) if risk["mitigations"] else ""),
            title="⚠️ 风险评估",
            border_style=risk_color
        ))
    
    # 显示最新状态
    latest_status = result.get_latest_status()
    status_emoji = {
        "original": "✅",
        "reverted": "❌",
        "fixed": "🔧",
        "refactored": "♻️",
        "modified": "📝",
    }.get(latest_status, "❓")
    
    console.print(f"\n[bold]当前状态:[/bold] {status_emoji} {latest_status}")
    
    # 过滤并显示变更列表
    changes_to_show = result.changes[:limit]
    
    # 应用过滤器
    if not show_all:
        filtered = []
        for change in changes_to_show:
            if show_fixups and change.change_type == ChangeType.FIXUP:
                filtered.append(change)
            elif show_reverts and change.change_type == ChangeType.REVERT:
                filtered.append(change)
            elif show_conflicts and change.change_type == ChangeType.CONFLICT_FIX:
                filtered.append(change)
        
        if show_fixups or show_reverts or show_conflicts:
            changes_to_show = filtered
    
    if changes_to_show:
        console.print()
        changes_table = Table(title=f"📝 相关变更 (显示 {len(changes_to_show)} 个)")
        changes_table.add_column("日期", style="dim", width=12)
        changes_table.add_column("类型", width=12)
        changes_table.add_column("Commit", width=10)
        changes_table.add_column("作者", width=15)
        changes_table.add_column("描述")
        
        type_colors = {
            ChangeType.FIXUP: "yellow",
            ChangeType.REVERT: "red",
            ChangeType.REFACTOR: "blue",
            ChangeType.BACKPORT: "green",
            ChangeType.CONFLICT_FIX: "magenta",
            ChangeType.FOLLOW_UP: "cyan",
            ChangeType.CVE_RELATED: "bright_cyan",  # ⭐ 新增
            ChangeType.UNKNOWN: "dim",
        }
        
        for change in changes_to_show:
            date_str = change.commit_date.strftime("%Y-%m-%d")
            type_str = change.change_type.value
            color = type_colors.get(change.change_type, "white")
            
            changes_table.add_row(
                date_str,
                f"[{color}]{type_str}[/{color}]",
                change.commit_hash[:8],
                change.author[:14],
                change.description[:40] + "..." if len(change.description) > 40 else change.description,
            )
        
        console.print(changes_table)
    else:
        console.print("\n[dim]未找到相关变更[/dim]")
    
    # 显示建议
    if result.analysis.get("recommendations"):
        console.print()
        console.print("[bold cyan]💡 建议:[/bold cyan]")
        for rec in result.analysis["recommendations"]:
            console.print(f"  {rec}")


# ============================================
# report 命令
# ============================================

@cli.command()
@click.option("--format", "fmt", type=click.Choice(["json", "markdown", "html"]), default="json")
@click.option("--output", "-o", help="输出目录")
@click.pass_context
def report(ctx: click.Context, fmt: str, output: Optional[str]):
    """
    生成分析报告
    
    支持格式：JSON / Markdown / HTML
    """
    console.print(f"[yellow]生成报告 - 待实现 (Phase 7)[/yellow]")
    console.print(f"格式: {fmt}")
    if output:
        console.print(f"输出: {output}")


# ============================================
# query 命令
# ============================================

@cli.command()
@click.option("--severity", help="严重程度 (CRITICAL/HIGH/MEDIUM/LOW, 大小写不敏感)")
@click.option("--since", help="起始日期 (YYYY-MM-DD)")
@click.option("--keyword", help="关键词搜索")
@click.option("--limit", default=100, help="返回数量限制")
@click.option("--format", "fmt", default="table", type=click.Choice(["table", "json", "csv"]), help="输出格式")
@click.pass_context
def query(
    ctx: click.Context,
    severity: Optional[str],
    since: Optional[str],
    keyword: Optional[str],
    limit: int,
    fmt: str,
):
    """
    查询漏洞数据库
    
    按条件查询本地 CVE 数据库
    
    示例:
        cve-analyzer query --severity=high --limit=50
        cve-analyzer query --since=2026-01-01 --keyword="use-after-free"
        cve-analyzer query --severity=critical --format=json
    """
    from cve_analyzer.core.database import Database
    from cve_analyzer.core.models import CVE
    from sqlalchemy import or_
    
    db = Database()
    
    with console.status("[bold green]正在查询数据库..."):
        with db.session() as session:
            query = session.query(CVE)
            
            # 应用过滤条件 - 大小写无关
            if severity:
                valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
                severity_upper = severity.upper()
                if severity_upper not in valid_severities:
                    console.print(f"[red]错误: 无效的严重程度 '{severity}', 有效值: CRITICAL, HIGH, MEDIUM, LOW[/red]")
                    return
                query = query.filter(CVE.severity == severity_upper)
            
            if since:
                from datetime import datetime
                try:
                    since_date = datetime.strptime(since, "%Y-%m-%d")
                    query = query.filter(CVE.published_date >= since_date)
                except ValueError:
                    console.print("[red]错误: since 日期格式应为 YYYY-MM-DD[/red]")
                    return
            
            if keyword:
                search = f"%{keyword}%"
                query = query.filter(
                    or_(
                        CVE.id.contains(keyword),
                        CVE.description.contains(keyword)
                    )
                )
            
            # 排序和限制
            query = query.order_by(CVE.published_date.desc()).limit(limit)
            
            # 在会话内提取所有数据
            cves_data = []
            for c in query.all():
                cves_data.append({
                    'id': c.id,
                    'severity': c.severity,
                    'cvss_score': c.cvss_score,
                    'published_date': c.published_date,
                    'description': c.description,
                })
    
    # 输出结果
    if not cves_data:
        console.print("[yellow]未找到匹配的 CVE[/yellow]")
        return
    
    if fmt == "json":
        import json
        data = [{
            "id": c['id'],
            "description": c['description'],
            "severity": c['severity'],
            "cvss_score": c['cvss_score'],
            "published_date": c['published_date'].isoformat() if c['published_date'] else None,
        } for c in cves_data]
        console.print(json.dumps(data, indent=2, ensure_ascii=False))
    
    elif fmt == "csv":
        console.print("CVE_ID,Severity,CVSS,Published_Date,Description")
        for c in cves_data:
            desc = (c['description'] or "").replace(",", ";").replace("\n", " ")[:100]
            pub_date = c['published_date'].strftime("%Y-%m-%d") if c['published_date'] else ""
            console.print(f"{c['id']},{c['severity'] or 'UNKNOWN'},{c['cvss_score'] or ''},{pub_date},{desc}")
    
    else:  # table
        from rich.table import Table
        table = Table(title=f"查询结果 (共 {len(cves_data)} 个)")
        table.add_column("CVE ID", style="cyan", width=18)
        table.add_column("严重程度", width=10)
        table.add_column("CVSS", width=6)
        table.add_column("发布日期", width=12)
        table.add_column("描述")
        
        severity_colors = {
            "CRITICAL": "red",
            "HIGH": "orange3",
            "MEDIUM": "yellow",
            "LOW": "green",
        }
        
        for c in cves_data:
            sev = (c['severity'] or "").upper()
            color = severity_colors.get(sev, "white")
            desc = c['description'][:80] + "..." if c['description'] and len(c['description']) > 80 else (c['description'] or "")
            pub_date = c['published_date'].strftime("%Y-%m-%d") if c['published_date'] else "-"
            
            table.add_row(
                c['id'],
                f"[{color}]{sev or 'UNKNOWN'}[/{color}]",
                str(c['cvss_score']) if c['cvss_score'] else "-",
                pub_date,
                desc
            )
        
        console.print(table)
        console.print(f"\n[dim]提示: 使用 --format=json 或 --format=csv 导出数据[/dim]")


# ============================================
# report 命令
# ============================================

@cli.command()
@click.argument("cve_id", required=False)
@click.option("--format", "fmt", default="markdown", type=click.Choice(["json", "markdown", "html"]), help="报告格式")
@click.option("--output", "-o", default=".", help="输出目录")
@click.option("--cve-list", type=click.Path(exists=True), help="CVE ID 列表文件")
@click.option("--summary", is_flag=True, help="生成摘要报告")
@click.pass_context
def report(
    ctx: click.Context,
    cve_id: Optional[str],
    fmt: str,
    output: str,
    cve_list: Optional[str],
    summary: bool,
):
    """
    生成 CVE 分析报告
    
    支持 JSON/Markdown/HTML 三种格式
    
    示例:
        cve-analyzer report CVE-2024-XXXX --format=html --output=./reports
        cve-analyzer report --summary --format=markdown
        cve-analyzer report --cve-list=cves.txt --format=json
    """
    from cve_analyzer.reporter.service import ReportService
    from cve_analyzer.reporter import JSONReportGenerator, MarkdownReportGenerator, HTMLReportGenerator
    
    # 选择生成器
    generators = {
        "json": JSONReportGenerator,
        "markdown": MarkdownReportGenerator,
        "html": HTMLReportGenerator,
    }
    generator_class = generators[fmt]
    generator = generator_class(output_dir=output)
    
    # 创建报告服务
    service = ReportService()
    
    if summary:
        # 生成摘要报告
        with console.status("[bold green]正在生成摘要报告..."):
            cve_ids = None
            if cve_list:
                with open(cve_list) as f:
                    cve_ids = [line.strip() for line in f if line.strip()]
            
            report_data = service.generate_summary_report(cve_ids)
            output_path = generator.generate_summary(report_data)
        
        console.print(f"[green]✓[/green] 摘要报告已生成: [cyan]{output_path}[/cyan]")
    
    elif cve_id:
        # 生成单个 CVE 报告
        with console.status(f"[bold green]正在生成 {cve_id} 报告..."):
            report_data = service.generate_cve_report(cve_id)
            if not report_data:
                console.print(f"[red]✗[/red] CVE 不存在: {cve_id}")
                return
            
            output_path = generator.generate(report_data)
        
        console.print(f"[green]✓[/green] 报告已生成: [cyan]{output_path}[/cyan]")
    
    elif cve_list:
        # 批量生成报告
        with open(cve_list) as f:
            cve_ids = [line.strip() for line in f if line.strip()]
        
        success_count = 0
        for cid in cve_ids:
            with console.status(f"[bold green]正在生成 {cid} 报告..."):
                report_data = service.generate_cve_report(cid)
                if report_data:
                    generator.generate(report_data)
                    success_count += 1
        
        console.print(f"[green]✓[/green] 成功生成 {success_count}/{len(cve_ids)} 个报告到 [cyan]{output}[/cyan]")
    
    else:
        console.print("[yellow]请指定 CVE ID 或使用 --summary/--cve-list 选项[/yellow]")


# ============================================
# llm-analyze 命令
# ============================================

@cli.command("llm-analyze")
@click.argument("cve_id")
@click.option("--provider", default="openai", type=click.Choice(["openai", "claude"]), help="LLM 提供商")
@click.option("--model", help="模型名称 (如 gpt-4, claude-3-opus)")
@click.option("--output", "-o", type=click.Choice(["json", "markdown"]), default="markdown", help="输出格式")
@click.pass_context
async def llm_analyze(ctx, cve_id: str, provider: str, model: Optional[str], output: str):
    """
    使用大模型分析 CVE
    
    利用 LLM 提供更深入的漏洞分析和修复建议。
    需要设置 API Key 环境变量 (OPENAI_API_KEY 或 ANTHROPIC_API_KEY)。
    
    示例:
        cve-analyzer llm-analyze CVE-2024-1234
        cve-analyzer llm-analyze CVE-2024-1234 --provider=claude --model=claude-3-opus
        cve-analyzer llm-analyze CVE-2024-1234 --output=json
    """
    import asyncio
    
    try:
        from cve_analyzer.llm import LLMFactory, LLMVulnerabilityAnalyzer
    except ImportError as e:
        console.print(f"[red]错误: {e}[/red]")
        console.print("[yellow]请安装依赖: pip install openai anthropic[/yellow]")
        return
    
    # 检查 API Key
    if provider == "openai" and not os.getenv("OPENAI_API_KEY"):
        console.print("[red]错误: 未设置 OPENAI_API_KEY 环境变量[/red]")
        return
    if provider == "claude" and not os.getenv("ANTHROPIC_API_KEY"):
        console.print("[red]错误: 未设置 ANTHROPIC_API_KEY 环境变量[/red]")
        return
    
    # 获取 CVE 数据
    from cve_analyzer.core.database import Database
    from cve_analyzer.core.models import CVE
    
    db = Database()
    with db.session() as session:
        cve = session.query(CVE).filter_by(id=cve_id).first()
        if not cve:
            console.print(f"[red]错误: CVE {cve_id} 不存在[/red]")
            return
    
    # 初始化 LLM
    try:
        llm_provider = LLMFactory.create(provider, model=model)
        analyzer = LLMVulnerabilityAnalyzer(llm_provider)
    except Exception as e:
        console.print(f"[red]LLM 初始化失败: {e}[/red]")
        return
    
    # 执行分析
    with console.status(f"[bold green]正在使用 {provider} 分析 {cve_id}..."):
        try:
            # 使用 asyncio 运行异步函数
            analysis = asyncio.run(analyzer.analyze_cve(cve))
        except Exception as e:
            console.print(f"[red]分析失败: {e}[/red]")
            return
    
    # 显示结果
    console.print()
    console.print(Panel(
        f"[bold cyan]{cve_id}[/bold cyan] 智能分析结果\n"
        f"模型: [dim]{analysis['_metadata']['model']}[/dim] | "
        f"Tokens: [dim]{analysis['_metadata']['tokens_used']}[/dim] | "
        f"成本: [dim]${analysis['_metadata']['cost_usd']:.4f}[/dim]",
        title="🤖 LLM 分析",
        border_style="green"
    ))
    
    if output == "json":
        import json
        console.print(json.dumps(analysis, indent=2, ensure_ascii=False))
    else:
        # Markdown 格式输出
        console.print(f"\n[bold]漏洞摘要[/bold]\n{analysis.get('summary', 'N/A')}\n")
        
        if 'attack_scenario' in analysis:
            console.print(f"[bold]攻击场景[/bold]\n{analysis['attack_scenario']}\n")
        
        if 'affected_components' in analysis:
            console.print("[bold]受影响组件[/bold]")
            for comp in analysis['affected_components']:
                console.print(f"  • {comp}")
            console.print()
        
        if 'exploit_difficulty' in analysis:
            diff = analysis['exploit_difficulty']
            color = {"LOW": "green", "MEDIUM": "yellow", "HIGH": "red"}.get(diff, "white")
            console.print(f"[bold]利用难度:[/bold] [{color}]{diff}[/{color}]\n")
        
        if 'mitigation' in analysis:
            console.print(f"[bold]缓解措施[/bold]\n{analysis['mitigation']}\n")


# ============================================
# llm-batch-analyze 命令
# ============================================

@cli.command("llm-batch-analyze")
@click.option("--cve-list", required=True, type=click.Path(exists=True), help="CVE ID 列表文件")
@click.option("--provider", default="openai", type=click.Choice(["openai", "claude"]), help="LLM 提供商")
@click.option("--model", help="模型名称")
@click.option("--max", default=10, help="最大分析数量 (控制成本)")
@click.pass_context
async def llm_batch_analyze(ctx, cve_list: str, provider: str, model: Optional[str], max: int):
    """
    批量使用大模型分析 CVE
    
    从文件读取 CVE ID 列表，批量进行分析。
    需要设置 API Key 环境变量。
    
    示例:
        cve-analyzer llm-batch-analyze --cve-list=cves.txt
        cve-analyzer llm-batch-analyze --cve-list=cves.txt --max=5 --provider=claude
    """
    import asyncio
    
    try:
        from cve_analyzer.llm import LLMFactory, LLMVulnerabilityAnalyzer
    except ImportError as e:
        console.print(f"[red]错误: {e}[/red]")
        console.print("[yellow]请安装依赖: pip install openai anthropic[/yellow]")
        return
    
    # 检查 API Key
    if provider == "openai" and not os.getenv("OPENAI_API_KEY"):
        console.print("[red]错误: 未设置 OPENAI_API_KEY 环境变量[/red]")
        return
    if provider == "claude" and not os.getenv("ANTHROPIC_API_KEY"):
        console.print("[red]错误: 未设置 ANTHROPIC_API_KEY 环境变量[/red]")
        return
    
    # 读取 CVE 列表
    with open(cve_list) as f:
        cve_ids = [line.strip() for line in f if line.strip()]
    
    if len(cve_ids) > max:
        console.print(f"[yellow]注意: 只分析前 {max} 个 CVE（控制成本）[/yellow]")
        cve_ids = cve_ids[:max]
    
    console.print(f"[cyan]准备分析 {len(cve_ids)} 个 CVE...[/cyan]\n")
    
    # 获取 CVE 数据
    from cve_analyzer.core.database import Database
    from cve_analyzer.core.models import CVE
    
    db = Database()
    cve_data = []
    
    with db.session() as session:
        for cve_id in cve_ids:
            cve = session.query(CVE).filter_by(id=cve_id).first()
            if cve:
                cve_data.append((cve_id, cve))
    
    if not cve_data:
        console.print("[red]错误: 未找到匹配的 CVE[/red]")
        return
    
    # 初始化 LLM
    try:
        llm_provider = LLMFactory.create(provider, model=model)
        analyzer = LLMVulnerabilityAnalyzer(llm_provider)
    except Exception as e:
        console.print(f"[red]LLM 初始化失败: {e}[/red]")
        return
    
    # 批量分析
    results = []
    total_cost = 0.0
    
    for i, (cve_id, cve) in enumerate(cve_data, 1):
        with console.status(f"[bold green][{i}/{len(cve_data)}] 正在分析 {cve_id}..."):
            try:
                analysis = asyncio.run(analyzer.analyze_cve(cve))
                results.append((cve_id, analysis))
                total_cost += analysis['_metadata']['cost_usd']
            except Exception as e:
                console.print(f"[red]分析 {cve_id} 失败: {e}[/red]")
    
    # 显示摘要
    console.print(Panel(
        f"[bold]批量分析完成[/bold]\n"
        f"成功: [green]{len(results)}/{len(cve_data)}[/green]\n"
        f"总成本: [yellow]${total_cost:.4f}[/yellow]",
        title="🤖 批量分析结果",
        border_style="green"
    ))
    
    # 显示简要结果
    table = Table(title="分析结果摘要")
    table.add_column("CVE ID", style="cyan")
    table.add_column("摘要", width=60)
    
    for cve_id, analysis in results:
        summary = analysis.get('summary', 'N/A')
        if len(summary) > 55:
            summary = summary[:55] + '...'
        table.add_row(cve_id, summary)
    
    console.print(table)
    console.print(f"\n[dim]提示: 使用单条分析查看详情: cve-analyzer llm-analyze <CVE-ID>[/dim]")


# ============================================
# version 命令
# ============================================

@cli.command()
def version():
    """显示版本信息"""
    from cve_analyzer import __version__
    console.print(f"CVE Analyzer [bold cyan]{__version__}[/bold cyan]")


# ============================================
# 主入口
# ============================================

def main():
    """CLI 主入口"""
    cli()


if __name__ == "__main__":
    main()
