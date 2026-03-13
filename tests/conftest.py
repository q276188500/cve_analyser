"""
测试配置和 fixtures
"""

import os
import tempfile
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from cve_analyzer.core.config import Settings, reset_settings
from cve_analyzer.core.database import Database, reset_db
from cve_analyzer.core.models import Base


@pytest.fixture
def temp_dir():
    """创建临时目录"""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def test_config(temp_dir):
    """创建测试配置"""
    config = Settings(
        data_dir=str(temp_dir / "data"),
        database_path=str(temp_dir / "data" / "test.db"),
        log_level="DEBUG",
    )
    return config


@pytest.fixture
def test_db(temp_dir):
    """创建测试数据库"""
    db_path = temp_dir / "test.db"
    db = Database(str(db_path))
    db.create_tables()
    yield db
    db.close()
    reset_db()


@pytest.fixture
def db_session(test_db):
    """创建数据库会话"""
    with test_db.session() as session:
        yield session


@pytest.fixture
def mock_kernel_repo(temp_dir):
    """创建模拟的内核 Git 仓库"""
    from git import Repo
    
    repo_path = temp_dir / "mock-linux"
    repo = Repo.init(repo_path)
    
    # 创建初始提交
    with open(repo_path / "README", "w") as f:
        f.write("Mock Linux Kernel\n")
    
    repo.index.add(["README"])
    repo.index.commit("Initial commit")
    
    return str(repo_path)


@pytest.fixture(autouse=True)
def reset_global_state():
    """每个测试后重置全局状态"""
    yield
    reset_settings()
    reset_db()


@pytest.fixture
def sample_cve_data():
    """提供示例 CVE 数据"""
    return {
        "id": "CVE-2024-1234",
        "description": "Test vulnerability in Linux kernel",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "published_date": "2024-01-15T00:00:00",
    }


@pytest.fixture
def sample_patch_data():
    """提供示例补丁数据"""
    return {
        "commit_hash": "abc123def45678901234567890abcdef12345678",
        "commit_hash_short": "abc123def456",
        "subject": "Fix vulnerability CVE-2024-1234",
        "author": "John Doe",
        "author_email": "john@example.com",
    }
