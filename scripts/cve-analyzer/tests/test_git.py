"""
Git 工具测试
"""

import os
from datetime import datetime, timedelta

import pytest
from git import Repo
from git.exc import InvalidGitRepositoryError

from cve_analyzer.utils.git import GitRepository


@pytest.fixture
def empty_repo(temp_dir):
    """创建空 Git 仓库"""
    repo_path = temp_dir / "empty-repo"
    repo = Repo.init(repo_path)
    
    # 创建初始提交
    with open(repo_path / "README", "w") as f:
        f.write("Initial\n")
    repo.index.add(["README"])
    repo.index.commit("Initial commit")
    
    return str(repo_path)


@pytest.fixture
def repo_with_history(temp_dir):
    """创建有历史的 Git 仓库"""
    repo_path = temp_dir / "history-repo"
    repo = Repo.init(repo_path)
    
    # 创建多个提交
    for i in range(5):
        filename = f"file{i}.txt"
        with open(repo_path / filename, "w") as f:
            f.write(f"Content {i}\n")
        repo.index.add([filename])
        repo.index.commit(f"Commit {i}: Add {filename}")
    
    return str(repo_path)


class TestGitRepositoryInit:
    """GitRepository 初始化测试"""
    
    def test_open_existing_repo(self, empty_repo):
        """测试打开现有仓库"""
        git_repo = GitRepository(empty_repo)
        assert git_repo.path == empty_repo
    
    def test_open_nonexistent_path_raises_error(self, temp_dir):
        """测试打开不存在的路径报错"""
        with pytest.raises(InvalidGitRepositoryError):
            GitRepository(str(temp_dir / "nonexistent"))
    
    def test_open_invalid_git_repo_raises_error(self, temp_dir):
        """测试打开无效 Git 仓库报错"""
        invalid_path = temp_dir / "not-a-repo"
        invalid_path.mkdir()
        
        with pytest.raises(InvalidGitRepositoryError):
            GitRepository(str(invalid_path))
    
    def test_clone_remote_repo(self, temp_dir):
        """测试克隆远程仓库 (使用本地仓库模拟)"""
        # 先创建一个源仓库
        source_path = temp_dir / "source-repo"
        source = Repo.init(source_path)
        with open(source_path / "test.txt", "w") as f:
            f.write("test\n")
        source.index.add(["test.txt"])
        source.index.commit("Initial")
        
        # 克隆
        clone_path = temp_dir / "cloned-repo"
        git_repo = GitRepository.clone(str(source_path), str(clone_path))
        
        assert os.path.exists(clone_path / ".git")
        assert git_repo.path == str(clone_path)
    
    def test_init_new_repo(self, temp_dir):
        """测试初始化新仓库"""
        repo_path = temp_dir / "new-repo"
        git_repo = GitRepository.init(str(repo_path))
        
        assert os.path.exists(repo_path / ".git")
        assert git_repo.path == str(repo_path)


class TestGitRepositoryBranchOperations:
    """分支操作测试"""
    
    def test_get_current_branch(self, empty_repo):
        """测试获取当前分支"""
        git_repo = GitRepository(empty_repo)
        branch = git_repo.get_current_branch()
        
        assert branch == "master" or branch == "main"
    
    def test_list_branches(self, repo_with_history):
        """测试列出分支"""
        git_repo = GitRepository(repo_with_history)
        branches = git_repo.list_branches()
        
        assert len(branches) >= 1
        assert "master" in branches or "main" in branches
    
    def test_checkout_commit(self, repo_with_history):
        """测试切换到指定 commit"""
        git_repo = GitRepository(repo_with_history)
        
        # 获取第一个提交
        commits = list(git_repo.repo.iter_commits())
        first_commit = commits[-1].hexsha
        
        # 切换到该提交
        git_repo.checkout_commit(first_commit[:12])
        
        # 验证当前 HEAD
        assert git_repo.repo.head.commit.hexsha.startswith(first_commit[:12])


class TestGitRepositoryCommitOperations:
    """Commit 操作测试"""
    
    def test_get_commit(self, repo_with_history):
        """测试获取 commit 信息"""
        git_repo = GitRepository(repo_with_history)
        
        # 获取最新 commit
        latest = git_repo.get_latest_commit()
        
        assert latest.hash is not None
        assert len(latest.short_hash) == 12
        assert latest.subject is not None
        assert latest.author is not None
    
    def test_get_commit_by_short_hash(self, repo_with_history):
        """测试用短 hash 获取 commit"""
        git_repo = GitRepository(repo_with_history)
        
        # 获取完整 hash，然后用短 hash 查询
        full_hash = git_repo.repo.head.commit.hexsha
        short_hash = full_hash[:12]
        
        commit_info = git_repo.get_commit(short_hash)
        
        assert commit_info.hash == full_hash
    
    def test_find_commits_by_message(self, repo_with_history):
        """测试按 message 搜索 commits"""
        git_repo = GitRepository(repo_with_history)
        
        commits = git_repo.find_commits_by_message("Add file")
        
        assert len(commits) >= 4  # 有 4 个包含 "Add file" 的提交
    
    def test_find_commits_by_file(self, repo_with_history):
        """测试查找修改指定文件的 commits"""
        git_repo = GitRepository(repo_with_history)
        
        commits = git_repo.find_commits_by_file("file0.txt")
        
        assert len(commits) >= 1
        assert "file0.txt" in commits[0].subject
    
    def test_is_commit_exists(self, repo_with_history):
        """测试检查 commit 是否存在"""
        git_repo = GitRepository(repo_with_history)
        
        existing_hash = git_repo.repo.head.commit.hexsha
        nonexistent_hash = "abc123" * 10  # 40 位随机 hash
        
        assert git_repo.is_commit_exists(existing_hash) is True
        assert git_repo.is_commit_exists(nonexistent_hash) is False


class TestGitRepositoryFileOperations:
    """文件操作测试"""
    
    def test_get_file_content_at_commit(self, repo_with_history):
        """测试获取指定 commit 时的文件内容"""
        git_repo = GitRepository(repo_with_history)
        
        # 获取 file0.txt 在第一次提交时的内容
        first_commit = list(git_repo.repo.iter_commits())[-1].hexsha
        content = git_repo.get_file_content_at_commit(first_commit, "file0.txt")
        
        assert content is not None
        assert "Content 0" in content
    
    def test_get_file_content_nonexistent_file(self, repo_with_history):
        """测试获取不存在的文件返回 None"""
        git_repo = GitRepository(repo_with_history)
        
        latest_commit = git_repo.repo.head.commit.hexsha
        content = git_repo.get_file_content_at_commit(latest_commit, "nonexistent.txt")
        
        assert content is None
    
    def test_get_file_history(self, repo_with_history):
        """测试获取文件历史"""
        git_repo = GitRepository(repo_with_history)
        
        history = git_repo.get_file_history("file0.txt")
        
        assert len(history) >= 1
        assert all(isinstance(c.author, str) for c in history)


class TestGitRepositoryTagOperations:
    """Tag 操作测试"""
    
    def test_list_tags(self, empty_repo):
        """测试列出标签"""
        git_repo = GitRepository(empty_repo)
        
        # 创建几个标签
        git_repo.repo.create_tag("v1.0")
        git_repo.repo.create_tag("v1.1")
        
        tags = git_repo.list_tags()
        
        assert "v1.0" in tags
        assert "v1.1" in tags
    
    def test_get_tags_containing_commit(self, repo_with_history):
        """测试获取包含指定 commit 的标签"""
        git_repo = GitRepository(repo_with_history)
        
        # 获取第一个提交
        commits = list(git_repo.repo.iter_commits())
        first_commit = commits[-1]
        
        # 在该提交创建标签
        git_repo.repo.create_tag("v0.1", ref=first_commit)
        
        tags = git_repo.get_tags_containing_commit(first_commit.hexsha)
        
        assert "v0.1" in tags


class TestGitRepositoryRemoteOperations:
    """远程操作测试"""
    
    def test_fetch(self, temp_dir):
        """测试 fetch 操作"""
        # 创建源仓库
        source_path = temp_dir / "source"
        source = Repo.init(source_path, bare=True)
        
        # 创建本地仓库并关联远程
        local_path = temp_dir / "local"
        local = Repo.init(local_path)
        local.create_remote("origin", str(source_path))
        
        # 创建文件并提交
        with open(local_path / "test.txt", "w") as f:
            f.write("test\n")
        local.index.add(["test.txt"])
        local.index.commit("Initial")
        
        # push 到远程
        local.remote("origin").push("master")
        
        # 克隆另一个仓库进行 fetch 测试
        clone_path = temp_dir / "clone"
        cloned = Repo.clone_from(str(source_path), str(clone_path))
        
        git_repo = GitRepository(str(clone_path))
        
        # 在源仓库添加新提交
        with open(local_path / "test2.txt", "w") as f:
            f.write("test2\n")
        local.index.add(["test2.txt"])
        local.index.commit("Second commit")
        local.remote("origin").push("master")
        
        # fetch
        git_repo.fetch()
        
        # 验证获取到了新分支
        assert "origin/master" in git_repo.list_remote_branches()


class TestCommitInfo:
    """CommitInfo 数据类测试"""
    
    def test_commit_info_structure(self, repo_with_history):
        """测试 CommitInfo 结构"""
        git_repo = GitRepository(repo_with_history)
        
        commit_info = git_repo.get_latest_commit()
        
        # 验证所有字段都存在
        assert commit_info.hash is not None
        assert len(commit_info.short_hash) == 12
        assert commit_info.subject is not None
        assert commit_info.author is not None
        assert isinstance(commit_info.author_date, datetime)
        assert isinstance(commit_info.files_changed, list)
        assert isinstance(commit_info.parent_hashes, list)
    
    def test_file_change_structure(self, repo_with_history):
        """测试 FileChange 结构"""
        git_repo = GitRepository(repo_with_history)
        
        commit_info = git_repo.get_latest_commit()
        
        if commit_info.files_changed:
            file_change = commit_info.files_changed[0]
            assert file_change.filename is not None
            assert isinstance(file_change.additions, int)
            assert isinstance(file_change.deletions, int)
            assert file_change.status in ["Added", "Modified", "Deleted", "Renamed"]
