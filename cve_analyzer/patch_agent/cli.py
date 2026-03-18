#!/usr/bin/env python3
"""
Patch Impact Agent - CLI Entry

Linux 内核补丁影响分析工具

Usage:
    patch-agent analyze -f patch.diff
    patch-agent analyze --patch "diff content..."
    patch-agent knowledge list
    patch-agent --help
"""

import sys
import os
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

import click
import json
from rich.console import Console

cve_analyzer.patch_agent.agent.parser import PatchParser
cve_analyzer.patch_agent.agent.analyzer import ImpactAnalyzer
cve_analyzer.patch_agent.knowledge.base import KnowledgeBase
cve_analyzer.patch_agent.output.formatter import (
    format_terminal, 
    format_json, 
    format_markdown,
    save_report
)


console = Console()


@click.group()
@click.version_option(version="0.1.0")
def cli():
    """Patch Impact Agent - Linux 内核补丁影响分析工具"""
    pass


@cli.command()
@click.option('-f', '--file', 'patch_file', type=click.Path(exists=True), 
              help='Patch 文件路径')
@click.option('-p', '--patch', 'patch_content', type=str,
              help='Patch 内容 (直接输入)')
@click.option('-o', '--output', type=click.Choice(['terminal', 'json', 'markdown', 'all']),
              default='terminal', help='输出格式')
@click.option('--save', 'save_dir', type=click.Path(), 
              help='保存报告的目录')
@click.option('--knowledge-dir', type=click.Path(),
              help='知识库目录 (可选)')
@click.option('--llm', 'use_llm', is_flag=True,
              help='使用 LLM 进行深度分析 (需要 OPENAI_API_KEY 或 ANTHROPIC_API_KEY)')
@click.option('--provider', type=click.Choice(['openai', 'claude', 'ollama']),
              default='openai', help='LLM 提供商')
def analyze(patch_file, patch_content, output, save_dir, knowledge_dir, use_llm, provider):
    """分析 patch 的影响
    
    使用 --llm 启用 LLM 深度分析:
    
        patch-agent analyze -f patch.diff --llm
    """
    
    # 读取 patch 内容
    if patch_file:
        with open(patch_file, 'r') as f:
            patch_data = f.read()
    elif patch_content:
        patch_data = patch_content
    else:
        console.print("[red]错误: 请提供 -f 或 -p 参数[/red]")
        sys.exit(1)
    
    if not patch_data.strip():
        console.print("[red]错误: Patch 内容为空[/red]")
        sys.exit(1)
    
    # 检查 LLM 可用性
    if use_llm:
        try:
            cve_analyzer.patch_agent.llm.provider import LLMFactory
            # 测试 provider
            llm = LLMFactory.create(provider)
            console.print(f"[cyan]🤖 LLM 启用: {provider}[/cyan]")
        except Exception as e:
            console.print(f"[yellow]⚠️ LLM 不可用: {e}[/yellow]")
            console.print("[yellow]将使用规则引擎分析 (无 LLM)[/yellow]")
            use_llm = False
    
    # 初始化知识库
    kb = KnowledgeBase(knowledge_dir) if knowledge_dir else KnowledgeBase()
    
    # 解析并分析
    console.print("[cyan]解析 patch...[/cyan]")
    parser = PatchParser()
    patch_info = parser.parse(patch_data)
    
    console.print(f"[cyan]分析影响... (匹配 {len(kb.rules)} 条规则)[/cyan]")
    analyzer = ImpactAnalyzer(kb)
    result = analyzer.analyze(patch_info, use_llm=use_llm, llm_provider=provider)
    
    # 输出
    if output == 'terminal' or output == 'all':
        print(format_terminal(result))
    
    if output == 'json' or output == 'all':
        if output == 'all':
            console.print("\n[dim]--- JSON 输出 ---[/dim]\n")
        print(format_json(result))
    
    if output == 'markdown':
        print(format_markdown(result))
    
    # 保存报告
    if save_dir:
        saved = save_report(result, save_dir, formats=['json', 'markdown'])
        console.print(f"[green]报告已保存:[/green]")
        for fmt, path in saved.items():
            console.print(f"  - {fmt}: {path}")
    
    # 返回码
    if result.recommendation.get('action') == 'defer':
        sys.exit(1)


@cli.group()
def knowledge():
    """知识库管理"""
    pass


@knowledge.command('list')
@click.option('--domain', type=str, help='按领域过滤')
@click.option('--severity', type=str, help='按严重级别过滤')
@click.option('--knowledge-dir', type=click.Path(),
              help='知识库目录')
def list_rules(domain, severity, knowledge_dir):
    """列出知识库规则"""
    kb = KnowledgeBase(knowledge_dir) if knowledge_dir else KnowledgeBase()
    
    rules = kb.get_all_rules()
    
    # 过滤
    if domain:
        rules = [r for r in rules if r.domain == domain]
    if severity:
        rules = [r for r in rules if r.severity == severity]
    
    console.print(f"\n[bold]知识库规则 ({len(rules)} 条)[/bold]\n")
    
    for r in rules:
        severity_color = {
            'critical': 'red',
            'high': 'yellow', 
            'medium': 'blue',
            'low': 'dim'
        }.get(r.severity, 'white')
        
        console.print(f"[bold]{r.id}[/bold] [{severity_color}]{r.severity.upper()}[/{severity_color}] {r.title}")
        console.print(f"  {r.description[:80]}...")
        console.print(f"  领域: {r.domain}, 标签: {', '.join(r.tags)}")
        console.print("")


@knowledge.command('add')
@click.argument('rule_file', type=click.Path(exists=True))
@click.option('--knowledge-dir', type=click.Path(),
              help='知识库目录')
def add_rule(rule_file, knowledge_dir):
    """添加新规则"""
    import yaml
    import shutil
    
    if knowledge_dir:
        target_dir = Path(knowledge_dir)
    else:
        target_dir = Path(__file__).parent.parent / "knowledge" / "rules"
    
    target_dir.mkdir(parents=True, exist_ok=True)
    
    # 复制文件
    source = Path(rule_file)
    target = target_dir / source.name
    
    if target.exists():
        console.print(f"[red]错误: 规则 {target.name} 已存在[/red]")
        sys.exit(1)
    
    shutil.copy(source, target)
    console.print(f"[green]规则已添加: {target}[/green]")


@cli.command()
@click.argument('patch_file', type=click.Path(exists=True))
def test(patch_file):
    """测试模式: 快速验证 patch"""
    with open(patch_file, 'r') as f:
        patch_data = f.read()
    
    kb = KnowledgeBase()
    parser = PatchParser()
    analyzer = ImpactAnalyzer(kb)
    
    patch_info = parser.parse(patch_data)
    result = analyzer.analyze(patch_info)
    
    # 简单输出
    print(format_terminal(result))


def main():
    cli()


if __name__ == '__main__':
    main()
