# 跨平台部署规范

**版本**: 1.0.0  
**创建日期**: 2026-03-17  
**目标**: Linux 与 Windows 双平台部署支持

---

## 1. 当前状态

- ✅ 数据库: SQLite (Python 内置)
- ✅ 路径处理: 使用 `pathlib.Path`
- ✅ 依赖管理: pyproject.toml

## 2. 改进措施

### 2.1 路径兼容性问题

**问题**: 默认使用相对路径 `./data`，在 Windows 上可能有兼容性问题

**解决方案**:
- 使用 `os.path.expanduser("~")` 处理用户目录
- 使用 `platform` 模块检测操作系统
- 默认路径改为用户数据目录:
  - Linux: `~/.local/share/cve-analyzer/`
  - Windows: `%APPDATA%\cve-analyzer\`

### 2.2 数据库路径优化

```python
# 改进前
database_path: str = Field(default="./data/cve-analyzer.db")

# 改进后 - 使用平台适配的默认路径
def get_default_data_dir() -> Path:
    """获取平台默认数据目录"""
    if platform.system() == "Windows":
        return Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming")) / "cve-analyzer"
    elif platform.system() == "Darwin":
        return Path.home() / "Library" / "Application Support" / "cve-analyzer"
    else:  # Linux
        return Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / "cve-analyzer"
```

### 2.3 虚拟环境启动脚本

创建跨平台的启动脚本:

| 脚本 | 用途 |
|------|------|
| `start.sh` | Linux/macOS |
| `start.bat` | Windows |
| `start.py` | 通用 Python 脚本 (推荐) |

### 2.4 数据库文件兼容性

SQLite 数据库文件本身是跨平台的，但需要注意:
- 确保 WAL 模式在所有平台正常工作
- 添加数据库迁移支持 (Alembic)

---

## 3. 实施清单

- [x] 创建本规范
- [ ] 更新 config.py 平台适配逻辑
- [ ] 添加启动脚本
- [ ] 更新 .gitignore 排除数据库文件
- [ ] 测试 Windows 兼容性

---

## 4. 验证方法

```bash
# Linux
python -c "from cve_analyzer.core.config import get_settings; print(get_settings().database_path)"

# Windows (PowerShell)
python -c "from cve_analyzer.core.config import get_settings; print(get_settings().database_path)"
```

预期输出:
- Linux: `/root/.local/share/cve-analyzer/cve-analyzer.db` (或类似)
- Windows: `C:\Users\<user>\AppData\Roaming\cve-analyzer\cve-analyzer.db`
