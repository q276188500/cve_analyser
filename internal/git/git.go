// Package git 提供 Git 仓库操作封装
package git

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-git/go-billy/v5/osfs"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
)

// Repository Git 仓库封装
type Repository struct {
	path string
	repo *git.Repository
}

// CommitInfo 提交信息
type CommitInfo struct {
	Hash          string
	ShortHash     string
	Subject       string
	Body          string
	Author        string
	AuthorEmail   string
	AuthorDate    time.Time
	Committer     string
	CommitDate    time.Time
	FilesChanged  []FileChange
	ParentHashes  []string
}

// FileChange 文件变更信息
type FileChange struct {
	Filename  string
	Status    string // Added/Modified/Deleted/Renamed
	Additions int
	Deletions int
}

// CloneOptions 克隆选项
type CloneOptions struct {
	URL           string
	Path          string
	Shallow       bool   // 是否浅克隆
	Depth         int    // 浅克隆深度
	Branch        string // 指定分支
	SingleBranch  bool   // 只克隆单个分支
}

// Clone 克隆远程仓库
func Clone(opts CloneOptions) (*Repository, error) {
	cloneOpts := &git.CloneOptions{
		URL:          opts.URL,
		Progress:     os.Stdout,
		SingleBranch: opts.SingleBranch,
	}

	if opts.Branch != "" {
		cloneOpts.ReferenceName = plumbing.ReferenceName("refs/heads/" + opts.Branch)
	}

	if opts.Shallow {
		cloneOpts.Depth = opts.Depth
	}

	repo, err := git.PlainClone(opts.Path, false, cloneOpts)
	if err != nil {
		return nil, fmt.Errorf("克隆仓库失败: %w", err)
	}

	return &Repository{
		path: opts.Path,
		repo: repo,
	}, nil
}

// Open 打开本地仓库
func Open(path string) (*Repository, error) {
	repo, err := git.PlainOpen(path)
	if err != nil {
		return nil, fmt.Errorf("打开仓库失败: %w", err)
	}

	return &Repository{
		path: path,
		repo: repo,
	}, nil
}

// Init 初始化新仓库
func Init(path string) (*Repository, error) {
	repo, err := git.PlainInit(path, false)
	if err != nil {
		return nil, fmt.Errorf("初始化仓库失败: %w", err)
	}

	return &Repository{
		path: path,
		repo: repo,
	}, nil
}

// Path 返回仓库路径
func (r *Repository) Path() string {
	return r.path
}

// ============================================
// 远程操作
// ============================================

// AddRemote 添加远程仓库
func (r *Repository) AddRemote(name, url string) error {
	_, err := r.repo.CreateRemote(&config.RemoteConfig{
		Name: name,
		URLs: []string{url},
	})
	return err
}

// Fetch 获取远程更新
func (r *Repository) Fetch(remoteName string) error {
	remote, err := r.repo.Remote(remoteName)
	if err != nil {
		return fmt.Errorf("获取远程仓库失败: %w", err)
	}

	opts := &git.FetchOptions{
		RemoteName: remoteName,
		Progress:   os.Stdout,
	}

	return remote.Fetch(opts)
}

// Pull 拉取远程更新
func (r *Repository) Pull() error {
	w, err := r.repo.Worktree()
	if err != nil {
		return err
	}

	return w.Pull(&git.PullOptions{
		RemoteName: "origin",
		Progress:   os.Stdout,
	})
}

// ============================================
// 分支操作
// ============================================

// Checkout 切换到指定分支或 commit
func (r *Repository) Checkout(target string) error {
	w, err := r.repo.Worktree()
	if err != nil {
		return err
	}

	// 尝试作为分支名
	err = w.Checkout(&git.CheckoutOptions{
		Branch: plumbing.ReferenceName("refs/heads/" + target),
	})
	if err == nil {
		return nil
	}

	// 尝试作为远程分支
	err = w.Checkout(&git.CheckoutOptions{
		Branch: plumbing.ReferenceName("refs/remotes/origin/" + target),
	})
	if err == nil {
		return nil
	}

	// 尝试作为 commit hash
	hash := plumbing.NewHash(target)
	err = w.Checkout(&git.CheckoutOptions{
		Hash: hash,
	})
	if err != nil {
		return fmt.Errorf("切换到 %s 失败: %w", target, err)
	}

	return nil
}

// CheckoutCommit 切换到指定 commit (detach HEAD)
func (r *Repository) CheckoutCommit(hash string) error {
	w, err := r.repo.Worktree()
	if err != nil {
		return err
	}

	h := plumbing.NewHash(hash)
	return w.Checkout(&git.CheckoutOptions{
		Hash:  h,
		Force: true,
	})
}

// GetCurrentBranch 获取当前分支名
func (r *Repository) GetCurrentBranch() (string, error) {
	head, err := r.repo.Head()
	if err != nil {
		return "", err
	}

	if head.Name().IsBranch() {
		return head.Name().Short(), nil
	}

	return head.Hash().String()[:12], nil // detached HEAD 返回短 hash
}

// ListBranches 列出所有分支
func (r *Repository) ListBranches() ([]string, error) {
	iter, err := r.repo.Branches()
	if err != nil {
		return nil, err
	}

	var branches []string
	err = iter.ForEach(func(ref *plumbing.Reference) error {
		branches = append(branches, ref.Name().Short())
		return nil
	})

	return branches, err
}

// ListTags 列出所有标签
func (r *Repository) ListTags() ([]string, error) {
	iter, err := r.repo.Tags()
	if err != nil {
		return nil, err
	}

	var tags []string
	err = iter.ForEach(func(ref *plumbing.Reference) error {
		tags = append(tags, ref.Name().Short())
		return nil
	})

	return tags, err
}

// ============================================
// Commit 操作
// ============================================

// GetCommit 获取指定 commit 的信息
func (r *Repository) GetCommit(hash string) (*CommitInfo, error) {
	h := plumbing.NewHash(hash)
	commit, err := r.repo.CommitObject(h)
	if err != nil {
		return nil, fmt.Errorf("获取 commit 失败: %w", err)
	}

	return r.parseCommit(commit)
}

// GetCommitByShortHash 根据短 hash 获取 commit
func (r *Repository) GetCommitByShortHash(shortHash string) (*CommitInfo, error) {
	// 遍历所有 commits 查找匹配短 hash 的
	iter, err := r.repo.Log(&git.LogOptions{
		All: true,
	})
	if err != nil {
		return nil, err
	}

	var found *object.Commit
	err = iter.ForEach(func(c *object.Commit) error {
		if strings.HasPrefix(c.Hash.String(), shortHash) {
			found = c
			return fmt.Errorf("found") // 用错误终止遍历
		}
		return nil
	})

	if found == nil {
		return nil, fmt.Errorf("找不到 commit: %s", shortHash)
	}

	return r.parseCommit(found)
}

// GetLatestCommit 获取最新 commit
func (r *Repository) GetLatestCommit() (*CommitInfo, error) {
	head, err := r.repo.Head()
	if err != nil {
		return nil, err
	}

	return r.GetCommit(head.Hash().String())
}

// GetCommitHistory 获取 commit 历史
func (r *Repository) GetCommitHistory(since, until time.Time) ([]*CommitInfo, error) {
	opts := &git.LogOptions{}
	if !since.IsZero() {
		opts.Since = &since
	}
	if !until.IsZero() {
		opts.Until = &until
	}

	iter, err := r.repo.Log(opts)
	if err != nil {
		return nil, err
	}

	var commits []*CommitInfo
	err = iter.ForEach(func(c *object.Commit) error {
		info, err := r.parseCommit(c)
		if err != nil {
			return err
		}
		commits = append(commits, info)
		return nil
	})

	return commits, err
}

// FindCommitsByMessage 根据 commit message 搜索 commits
func (r *Repository) FindCommitsByMessage(pattern string) ([]*CommitInfo, error) {
	iter, err := r.repo.Log(&git.LogOptions{
		All: true,
	})
	if err != nil {
		return nil, err
	}

	var commits []*CommitInfo
	err = iter.ForEach(func(c *object.Commit) error {
		if strings.Contains(c.Message, pattern) {
			info, err := r.parseCommit(c)
			if err != nil {
				return err
			}
			commits = append(commits, info)
		}
		return nil
	})

	return commits, err
}

// GetCommitsContainingFile 获取包含指定文件变更的所有 commits
func (r *Repository) GetCommitsContainingFile(filename string, sinceHash string) ([]*CommitInfo, error) {
	iter, err := r.repo.Log(&git.LogOptions{
		All: true,
	})
	if err != nil {
		return nil, err
	}

	var commits []*CommitInfo
	err = iter.ForEach(func(c *object.Commit) error {
		// 检查这个 commit 是否修改了指定文件
		stats, err := c.Stats()
		if err != nil {
			return nil // 跳过错误
		}

		for _, stat := range stats {
			if stat.Name == filename {
				info, err := r.parseCommit(c)
				if err != nil {
					return err
				}
				commits = append(commits, info)
				break
			}
		}
		return nil
	})

	return commits, err
}

// ============================================
// 辅助方法
// ============================================

// parseCommit 解析 commit 对象
func (r *Repository) parseCommit(commit *object.Commit) (*CommitInfo, error) {
	// 获取文件变更统计
	stats, err := commit.Stats()
	if err != nil {
		// 某些 commit 可能无法获取 stats，继续处理
		stats = nil
	}

	var files []FileChange
	if stats != nil {
		for _, stat := range stats {
			files = append(files, FileChange{
				Filename:  stat.Name,
				Additions: stat.Addition,
				Deletions: stat.Deletion,
				Status:    "Modified", // go-git stats 不直接提供状态
			})
		}
	}

	// 获取父 commits
	var parents []string
	for _, p := range commit.ParentHashes {
		parents = append(parents, p.String())
	}

	return &CommitInfo{
		Hash:         commit.Hash.String(),
		ShortHash:    commit.Hash.String()[:12],
		Subject:      strings.Split(commit.Message, "\n")[0],
		Body:         commit.Message,
		Author:       commit.Author.Name,
		AuthorEmail:  commit.Author.Email,
		AuthorDate:   commit.Author.When,
		Committer:    commit.Committer.Name,
		CommitDate:   commit.Committer.When,
		FilesChanged: files,
		ParentHashes: parents,
	}, nil
}

// GetFileContentAtCommit 获取指定 commit 时的文件内容
func (r *Repository) GetFileContentAtCommit(commitHash, filePath string) (string, error) {
	h := plumbing.NewHash(commitHash)
	commit, err := r.repo.CommitObject(h)
	if err != nil {
		return "", err
	}

	tree, err := commit.Tree()
	if err != nil {
		return "", err
	}

	file, err := tree.File(filePath)
	if err != nil {
		return "", err
	}

	content, err := file.Contents()
	if err != nil {
		return "", err
	}

	return content, nil
}

// IsCommitExists 检查 commit 是否存在于仓库
func (r *Repository) IsCommitExists(hash string) bool {
	h := plumbing.NewHash(hash)
	_, err := r.repo.CommitObject(h)
	return err == nil
}

// GetTagsContainingCommit 获取包含指定 commit 的所有标签
func (r *Repository) GetTagsContainingCommit(hash string) ([]string, error) {
	// 遍历所有标签，检查是否包含该 commit
	tags, err := r.ListTags()
	if err != nil {
		return nil, err
	}

	var containingTags []string
	for _, tag := range tags {
		// 获取 tag 指向的 commit
		ref, err := r.repo.Tag(tag)
		if err != nil {
			continue
		}

		tagCommit, err := r.repo.CommitObject(ref.Hash())
		if err != nil {
			continue
		}

		// 检查目标 commit 是否是 tag commit 的祖先
		targetHash := plumbing.NewHash(hash)
		isAncestor := r.isAncestorOf(targetHash, tagCommit.Hash)
		if isAncestor {
			containingTags = append(containingTags, tag)
		}
	}

	return containingTags, nil
}

// isAncestorOf 检查 child 是否是 parent 的后代
func (r *Repository) isAncestorOf(child, parent plumbing.Hash) bool {
	// 简化实现：遍历 parent 的历史，看是否包含 child
	iter, err := r.repo.Log(&git.LogOptions{
		From: parent,
	})
	if err != nil {
		return false
	}

	found := false
	iter.ForEach(func(c *object.Commit) error {
		if c.Hash == child {
			found = true
			return fmt.Errorf("found")
		}
		return nil
	})

	return found
}
