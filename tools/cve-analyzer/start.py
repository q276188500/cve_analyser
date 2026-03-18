#!/usr/bin/env python3
"""
CVE Analyzer 启动脚本 (跨平台)

自动检测并创建虚拟环境，安装依赖，然后运行程序。

用法:
    python start.py              # 交互式菜单
    python start.py init        # 初始化数据库
    python start.py cve <cve_id> # 分析指定 CVE
    python start.py serve        # 启动 Web 服务
"""

import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path


def get_venv_dir() -> Path:
    """获取虚拟环境目录"""
    if platform.system() == "Windows":
        return Path("venv")
    return Path("venv")


def get_venv_python() -> Path:
    """获取虚拟环境中的 Python"""
    venv_dir = get_venv_dir()
    if platform.system() == "Windows":
        return venv_dir / "Scripts" / "python.exe"
    return venv_dir / "bin" / "python"


def get_venv_pip() -> Path:
    """获取虚拟环境中的 pip"""
    venv_dir = get_venv_dir()
    if platform.system() == "Windows":
        return venv_dir / "Scripts" / "pip.exe"
    return venv_dir / "bin" / "pip"


def check_venv() -> bool:
    """检查虚拟环境是否存在"""
    python_path = get_venv_python()
    if python_path.exists():
        return True
    
    # 检查系统 Python
    if shutil.which("python3") or shutil.which("python"):
        return True
    
    return False


def create_venv() -> None:
    """创建虚拟环境"""
    print("📦 创建虚拟环境...")
    
    venv_dir = get_venv_dir()
    if venv_dir.exists():
        print("  虚拟环境已存在，跳过创建")
        return
    
    try:
        subprocess.run([sys.executable, "-m", "venv", str(venv_dir)], check=True)
        print("  ✅ 虚拟环境创建成功")
    except subprocess.CalledProcessError as e:
        print(f"  ❌ 创建虚拟环境失败: {e}")
        sys.exit(1)


def install_deps() -> None:
    """安装依赖"""
    print("📥 安装依赖...")
    
    pip_path = get_venv_pip()
    
    # 检查是否存在 pyproject.toml
    if not Path("pyproject.toml").exists():
        print("  ❌ 未找到 pyproject.toml")
        sys.exit(1)
    
    try:
        subprocess.run(
            [str(pip_path), "install", "-e", ".[dev]", "-q"],
            check=True,
        )
        print("  ✅ 依赖安装成功")
    except subprocess.CalledProcessError as e:
        print(f"  ❌ 安装依赖失败: {e}")
        sys.exit(1)


def ensure_venv() -> None:
    """确保虚拟环境和依赖可用"""
    if not check_venv():
        create_venv()
    
    if not Path("pyproject.toml").exists():
        print("❌ 未找到 pyproject.toml，请确保在项目根目录运行")
        sys.exit(1)
    
    pip_path = get_venv_pip()
    if not pip_path.exists():
        install_deps()
    else:
        # 检查是否需要重新安装
        try:
            result = subprocess.run(
                [str(pip_path), "show", "cve-analyzer"],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                install_deps()
        except Exception:
            install_deps()


def run_command(args: list) -> None:
    """运行命令"""
    python_path = get_venv_python()
    
    if not python_path.exists():
        print("❌ 虚拟环境未就绪，请先运行 python start.py")
        sys.exit(1)
    
    cmd = [str(python_path), "-m", "cve_analyzer.cli"] + args
    result = subprocess.run(cmd)
    sys.exit(result.returncode)


def cmd_init() -> None:
    """初始化命令"""
    ensure_venv()
    run_command(["init"])


def cmd_serve() -> None:
    """启动 Web 服务"""
    ensure_venv()
    run_command(["serve"])


def cmd_cve(cve_id: str) -> None:
    """分析 CVE"""
    ensure_venv()
    run_command(["analyze", cve_id])


def cmd_shell() -> None:
    """进入 Python Shell"""
    ensure_venv()
    run_command(["shell"])


def main():
    """主入口"""
    if len(sys.argv) > 1:
        cmd = sys.argv[1]
        
        if cmd == "init":
            cmd_init()
        elif cmd == "serve":
            cmd_serve()
        elif cmd == "shell":
            cmd_shell()
        elif cmd == "cve" and len(sys.argv) > 2:
            cmd_cve(sys.argv[2])
        else:
            print(__doc__)
    else:
        # 交互式菜单
        print("\n" + "=" * 50)
        print("  🛡️  CVE Analyzer 启动器")
        print("=" * 50)
        print()
        print("  [1] 初始化数据库")
        print("  [2] 分析 CVE")
        print("  [3] 启动 Web 服务")
        print("  [4] Python Shell")
        print("  [5] 安装/更新依赖")
        print("  [0] 退出")
        print()
        
        choice = input("请选择 [0-5]: ").strip()
        
        if choice == "1":
            cmd_init()
        elif choice == "2":
            cve_id = input("请输入 CVE ID (如 CVE-2024-1234): ").strip()
            if cve_id:
                cmd_cve(cve_id)
            else:
                print("❌ 未输入 CVE ID")
        elif choice == "3":
            cmd_serve()
        elif choice == "4":
            cmd_shell()
        elif choice == "5":
            ensure_venv()
            print("✅ 依赖已安装/更新")
        elif choice == "0":
            print("👋 再见!")
        else:
            print("❌ 无效选择")


if __name__ == "__main__":
    main()
