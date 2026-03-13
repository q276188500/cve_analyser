"""
CLI 命令行接口
使用 Click 框架
"""

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
@click.option("--source", help="指定数据源 (nvd/cve-org/all)", default="all")
@click.option("--dry-run", is_flag=True, help="模拟运行，不保存到数据库")
@click.pass_context
def sync(ctx: click.Context, since: Optional[str], source: str, dry_run: bool):
    """
    同步 CVE 数据
    
    从 NVD、CVE.org 等数据源同步 CVE 数据到本地数据库
    
    示例：
        cve-analyzer sync                           # 同步最近 30 天
        cve-analyzer sync --since=2024-01-01        # 从指定日期同步
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
    
    console.print(f"[bold green]开始同步 CVE 数据...[/bold green]")
    console.print(f"起始日期: [cyan]{since_date}[/cyan]")
    console.print(f"数据源: [cyan]{source}[/cyan]")
    if dry_run:
        console.print("[yellow]模拟模式: 数据不会保存到数据库[/yellow]")
    console.print()
    
    # 创建协调器
    orchestrator = FetchOrchestrator()
    
    # 记录开始时间
    start_time = datetime.utcnow()
    
    try:
        with console.status("[bold green]正在从 NVD 获取数据...") as status:
            result = orchestrator.fetch_all(since=since_date)
        
        # 显示结果
        console.print(f"[bold green]✓ 同步完成![/bold green]")
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
        
        # 保存到数据库
        if not dry_run and result.cves:
            with console.status("[bold green]正在保存到数据库..."):
                db = get_db()
                repo = CVERepository(db.get_session())
                
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
                
                with db.session() as session:
                    session.add(sync_log)
                
                console.print(f"[green]✓ 已保存 {saved_count} 个 CVE 到数据库[/green]")
        
        # 显示部分 CVE
        if result.cves:
            console.print()
            cve_table = Table(title="部分 CVE 预览")
            cve_table.add_column("CVE ID", style="cyan")
            cve_table.add_column("严重程度", style="yellow")
            cve_table.add_column("描述", style="dim", max_width=50)
            
            for cve in result.cves[:5]:
                desc = cve.description[:47] + "..." if cve.description and len(cve.description) > 50 else (cve.description or "")
                color = {
                    "CRITICAL": "red",
                    "HIGH": "orange3",
                    "MEDIUM": "yellow",
                    "LOW": "green",
                }.get(cve.severity, "white")
                
                cve_table.add_row(
                    cve.id,
                    f"[{color}]{cve.severity or 'UNKNOWN'}[/{color}]",
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
    console.print(f"[yellow]分析 CVE {cve_id} - 待实现 (Phase 3)[/yellow]")
    if deep:
        console.print("深度分析模式")


# ============================================
# patch-status 命令
# ============================================

@cli.command("patch-status")
@click.argument("cve-id")
@click.option("--kernel-path", type=click.Path(exists=True), help="内核源码路径")
@click.option("--version", help="内核版本号")
@click.option("--detection", type=click.Choice(["hash", "content", "both"]), help="检测策略")
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
    console.print(f"[yellow]检测补丁状态 {cve_id} - 待实现 (Phase 4)[/yellow]")
    if kernel_path:
        console.print(f"内核路径: {kernel_path}")
    if version:
        console.print(f"目标版本: {version}")
    if detection:
        console.print(f"检测策略: {detection}")


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
@click.option("--show-fixups", is_flag=True, help="显示 fixup 提交")
@click.option("--show-reverts", is_flag=True, help="显示 revert 提交")
@click.option("--show-conflicts", is_flag=True, help="显示冲突解决")
@click.pass_context
def patch_history(
    ctx: click.Context,
    cve_id: str,
    show_fixups: bool,
    show_reverts: bool,
    show_conflicts: bool,
):
    """
    追踪补丁修改历史
    
    查看补丁的后续修改，包括：
    - fixup: 修复补丁
    - revert: 回退提交
    - refactor: 重构修改
    - conflict: 冲突解决
    """
    console.print(f"[yellow]补丁历史 {cve_id} - 待实现 (Phase 6)[/yellow]")


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
@click.option("--severity", type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW"]))
@click.option("--since", help="起始日期 (YYYY-MM-DD)")
@click.option("--keyword", help="关键词搜索")
@click.option("--limit", default=100, help="返回数量限制")
@click.pass_context
def query(
    ctx: click.Context,
    severity: Optional[str],
    since: Optional[str],
    keyword: Optional[str],
    limit: int,
):
    """
    查询漏洞数据库
    
    按条件查询本地 CVE 数据库
    """
    console.print("[yellow]查询漏洞 - 待实现[/yellow]")
    
    table = Table(title="查询参数")
    table.add_column("参数", style="cyan")
    table.add_column("值", style="magenta")
    
    table.add_row("severity", severity or "-")
    table.add_row("since", since or "-")
    table.add_row("keyword", keyword or "-")
    table.add_row("limit", str(limit))
    
    console.print(table)


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
