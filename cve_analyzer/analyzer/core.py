"""
分析器主实现
"""

from typing import List, Set

from cve_analyzer.analyzer.extractor import PatchExtractor
from cve_analyzer.analyzer.parser import CommitParser
from cve_analyzer.analyzer.version_impact import VersionImpactAnalyzer
from cve_analyzer.core.models import CVE, Patch
from cve_analyzer.utils.git import GitRepository


class AnalysisResult:
    """分析结果"""
    def __init__(self, cve, patches, affected_files, affected_functions, version_impact):
        self.cve = cve
        self.patches = patches
        self.affected_files = affected_files
        self.affected_functions = affected_functions
        self.version_impact = version_impact


class VersionImpact:
    """版本影响分析结果"""
    def __init__(self, mainline_affected=None, stable_affected=None, 
                 longterm_affected=None, backported_to=None, not_backported_to=None):
        self.mainline_affected = mainline_affected or []
        self.stable_affected = stable_affected or []
        self.longterm_affected = longterm_affected or []
        self.backported_to = backported_to or []
        self.not_backported_to = not_backported_to or []


class Analyzer:
    """补丁分析器实现"""
    
    def __init__(self, repo: GitRepository = None):
        """
        初始化分析器
        
        Args:
            repo: Linux 内核 Git 仓库，None 则使用配置
        """
        self.extractor = PatchExtractor()
        self.parser = CommitParser()
        self.repo = repo
        
        if repo is None:
            # 尝试从配置加载
            from cve_analyzer.core.config import get_settings
            settings = get_settings()
            if settings.kernel.path:
                self.repo = GitRepository(settings.kernel.path)
    
    def analyze(self, cve: CVE) -> AnalysisResult:
        """
        分析 CVE
        
        Args:
            cve: CVE 对象
        
        Returns:
            分析结果
        """
        # 提取补丁
        patches = self.extract_patches(cve)
        
        # 收集受影响的文件和函数
        affected_files = []
        affected_functions = []
        
        for patch in patches:
            for fc in patch.files_changed:
                if fc.filename not in affected_files:
                    affected_files.append(fc.filename)
                
                # 如果函数名已解析，添加到列表
                if fc.functions:
                    for func in fc.functions:
                        if func not in affected_functions:
                            affected_functions.append(func)
        
        # 分析版本影响
        version_impact = VersionImpact(
            mainline_affected=[],
            stable_affected=[],
            longterm_affected=[],
            backported_to=[],
            not_backported_to=[],
        )
        
        if self.repo and patches:
            analyzer = VersionImpactAnalyzer(self.repo)
            version_impact = analyzer.analyze(patches[0])
        
        return AnalysisResult(
            cve=cve,
            patches=patches,
            affected_files=affected_files,
            affected_functions=affected_functions,
            version_impact=version_impact,
        )
    
    def extract_patches(self, cve: CVE) -> List[Patch]:
        """
        从 CVE 提取补丁
        
        Args:
            cve: CVE 对象
        
        Returns:
            补丁列表
        """
        patches = []
        
        # 从参考链接中提取 PATCH 类型的链接
        for ref in cve.references:
            if ref.type != "PATCH":
                continue
            
            try:
                if "git.kernel.org" in ref.url or "github.com" in ref.url:
                    patch = self.extractor.extract_from_url(ref.url)
                    if patch:
                        # 关联 CVE ID
                        patch.cve_id = cve.id
                        patches.append(patch)
            except Exception as e:
                print(f"提取补丁失败 {ref.url}: {e}")
                continue
        
        return patches
    
    def analyze_version_impact(self, patch: Patch) -> VersionImpact:
        """
        分析补丁版本影响
        
        Args:
            patch: 补丁对象
        
        Returns:
            版本影响分析结果
        """
        if self.repo is None:
            return VersionImpact(
                mainline_affected=[],
                stable_affected=[],
                longterm_affected=[],
                backported_to=[],
                not_backported_to=[],
            )
        
        analyzer = VersionImpactAnalyzer(self.repo)
        return analyzer.analyze(patch)
    
    def _fetch_patch(self, url: str) -> Patch:
        """内部方法：获取单个补丁"""
        return self.extractor.extract_from_url(url)
