#!/usr/bin/env python3
"""
Patch Impact Agent - 部署脚本

支持独立部署和统一部署 (与 cve-analyzer 一起)
"""

import os
import sys
import subprocess
import argparse
from pathlib import Path


def get_project_root():
    return Path(__file__).parent.parent


def create_venv(venv_path=None):
    """创建虚拟环境"""
    if venv_path is None:
        venv_path = get_project_root() / "venv"
    
    if venv_path.exists():
        print(f"虚拟环境已存在: {venv_path}")
        return venv_path
    
    print(f"创建虚拟环境: {venv_path}")
    subprocess.run([sys.executable, "-m", "venv", str(venv_path)], check=True)
    return venv_path


def install_deps(venv_path):
    """安装依赖"""
    print("安装依赖...")
    
    pip = venv_path / "bin" / "pip"
    if sys.platform == "win32":
        pip = venv_path / "Scripts" / "pip"
    
    # 安装项目
    subprocess.run([str(pip), "install", "-e", ".[dev]"], check=True)
    print("✅ 依赖安装完成")


def setup_cve_analyzer_integration(cve_analyzer_path):
    """设置与 cve-analyzer 的集成"""
    print(f"\n配置 cve-analyzer 集成...")
    
    # 创建集成模块链接
    integration_file = Path(cve_analyzer_path) / "cve_analyzer" / "integrations" / "patch_agent.py"
    integration_dir = integration_file.parent
    
    if not integration_dir.exists():
        integration_dir.mkdir(parents=True, exist_ok=True)
    
    # 写入集成代码
    integration_code = '''"""
CVE Analyzer - Patch Impact Agent 集成

用法:
    from cve_analyzer.integrations.patch_agent import analyze_patch
    
    result = analyze_patch(patch_content)
"""

import sys
from pathlib import Path

# 添加 patch-agent 到路径
_agent_path = Path(__file__).parent.parent.parent / "patch-impact-agent"
if _agent_path.exists():
    sys.path.insert(0, str(_agent_path))

from patch_agent.agent.analyzer import analyze_patch as _analyze
from patch_agent.knowledge.base import KnowledgeBase


def analyze_patch(patch_content: str, knowledge_dir: str = None):
    """分析 patch 影响
    
    Args:
        patch_content: patch diff 内容
        knowledge_dir: 知识库目录 (可选)
    
    Returns:
        AnalysisResult: 分析结果
    """
    kb = KnowledgeBase(knowledge_dir) if knowledge_dir else KnowledgeBase()
    return _analyze(patch_content, kb)


__all__ = ['analyze_patch']
'''
    
    with open(integration_file, 'w') as f:
        f.write(integration_code)
    
    print(f"✅ 集成模块已创建: {integration_file}")


def deploy_standalone():
    """独立部署"""
    print("\n" + "=" * 50)
    print("  Patch Impact Agent - 独立部署")
    print("=" * 50 + "\n")
    
    root = get_project_root()
    venv_path = root / "venv"
    
    # 1. 创建虚拟环境
    create_venv(venv_path)
    
    # 2. 安装依赖
    old_cwd = os.getcwd()
    os.chdir(root)
    try:
        install_deps(venv_path)
    finally:
        os.chdir(old_cwd)
    
    print("\n" + "=" * 50)
    print("  ✅ 部署完成!")
    print("=" * 50)
    print("\n用法:")
    print(f"  source {venv_path}/bin/activate")
    print(f"  patch-agent --help")


def deploy_unified(cve_analyzer_path=None):
    """统一部署 (与 cve-analyzer 一起)"""
    print("\n" + "=" * 50)
    print("  Patch Impact Agent - 统一部署")
    print("=" * 50 + "\n")
    
    root = get_project_root()
    venv_path = root / "venv"
    
    # 1. 创建虚拟环境
    create_venv(venv_path)
    
    # 2. 安装依赖
    old_cwd = os.getcwd()
    os.chdir(root)
    try:
        install_deps(venv_path)
    finally:
        os.chdir(old_cwd)
    
    # 3. 查找 cve-analyzer 路径
    if cve_analyzer_path is None:
        cve_analyzer_path = os.environ.get(
            'CVE_ANALYZER_PATH',
            str(Path.home() / "workspace" / "projects" / "cve-analyzer")
        )
    
    if Path(cve_analyzer_path).exists():
        setup_cve_analyzer_integration(cve_analyzer_path)
    else:
        print(f"\n⚠️  cve-analyzer 未找到: {cve_analyzer_path}")
        print("  跳过集成配置")
    
    print("\n" + "=" * 50)
    print("  ✅ 统一部署完成!")
    print("=" * 50)
    print("\n用法:")
    print(f"  source {venv_path}/bin/activate")
    print(f"  patch-agent --help")
    print(f"\ncve-analyzer 集成:")
    print(f"  from cve_analyzer.integrations.patch_agent import analyze_patch")


def main():
    parser = argparse.ArgumentParser(description="Patch Impact Agent 部署")
    parser.add_argument('--standalone', action='store_true',
                        help='独立部署')
    parser.add_argument('--unified', action='store_true',
                        help='统一部署 (与 cve-analyzer)')
    parser.add_argument('--cve-analyzer-path', type=str,
                        help='cve-analyzer 路径')
    
    args = parser.parse_args()
    
    if args.standalone:
        deploy_standalone()
    elif args.unified:
        deploy_unified(args.cve_analyzer_path)
    else:
        # 默认统一部署
        deploy_unified(args.cve_analyzer_path)


if __name__ == '__main__':
    main()
