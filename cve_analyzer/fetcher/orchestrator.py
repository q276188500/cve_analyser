"""
采集协调器
整合多个数据源的 CVE 数据
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional

from cve_analyzer.core.config import get_settings
from cve_analyzer.core.models import CVE
from cve_analyzer.fetcher.base import Fetcher, FetchResult, FetcherError


class FetchOrchestrator:
    """CVE 数据采集协调器"""
    
    def __init__(
        self,
        fetchers: Optional[List[Fetcher]] = None,
        max_workers: int = None,
    ):
        """
        初始化协调器
        
        Args:
            fetchers: 获取器列表，None 则自动创建
            max_workers: 最大并发数，None 则使用配置
        """
        settings = get_settings()
        
        if fetchers is None:
            self.fetchers = self._create_default_fetchers()
        else:
            self.fetchers = fetchers
        
        self.max_workers = max_workers or settings.analysis.max_workers
    
    def _create_default_fetchers(self) -> List[Fetcher]:
        """创建默认的获取器列表"""
        fetchers = []
        settings = get_settings()
        
        # NVD
        if settings.data_sources.nvd.enabled:
            from cve_analyzer.fetcher.nvd import NVDFetcher
            fetchers.append(NVDFetcher())
        
        # CVE.org
        if settings.data_sources.cve_org.enabled:
            from cve_analyzer.fetcher.cve_org import CVEOrgFetcher
            fetchers.append(CVEOrgFetcher())
        
        return fetchers
    
    def fetch_all(
        self,
        since: Optional[str] = None,
        until: Optional[str] = None,
        cve_ids: Optional[List[str]] = None,
    ) -> FetchResult:
        """
        从所有数据源获取 CVE 数据
        
        Args:
            since: 起始日期，格式 YYYY-MM-DD
            until: 结束日期，格式 YYYY-MM-DD
            cve_ids: 指定 CVE ID 列表，None 则获取全部
        
        Returns:
            采集结果
        """
        result = FetchResult()
        
        if cve_ids:
            # 获取指定 CVE
            result = self._fetch_specific(cve_ids)
        else:
            # 批量获取
            result = self._fetch_batch(since, until)
        
        # 去重
        result.cves = self._deduplicate(result.cves)
        result.total = len(result.cves)
        
        return result
    
    def _fetch_batch(self, since: Optional[str], until: Optional[str]) -> FetchResult:
        """批量获取 CVE"""
        result = FetchResult()
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # 提交所有任务
            future_to_fetcher = {
                executor.submit(fetcher.fetch, since, until): fetcher
                for fetcher in self.fetchers
            }
            
            # 收集结果
            for future in as_completed(future_to_fetcher):
                fetcher = future_to_fetcher[future]
                try:
                    cves = future.result()
                    result.cves.extend(cves)
                    result.new += len(cves)
                except Exception as e:
                    error_msg = f"{fetcher.name()} fetch failed: {e}"
                    result.errors.append(FetcherError(error_msg))
                    result.failed += 1
        
        return result
    
    def _fetch_specific(self, cve_ids: List[str]) -> FetchResult:
        """获取指定 CVE"""
        result = FetchResult()
        
        # 用于去重的集合
        found_ids = set()
        
        for cve_id in cve_ids:
            cve_found = False
            
            # 按优先级尝试各数据源
            for fetcher in self.fetchers:
                try:
                    cve = fetcher.fetch_one(cve_id)
                    if cve:
                        if cve.id not in found_ids:
                            result.cves.append(cve)
                            found_ids.add(cve.id)
                            result.new += 1
                        cve_found = True
                        break  # 找到就停止
                except Exception as e:
                    error_msg = f"{fetcher.name()} fetch {cve_id} failed: {e}"
                    result.errors.append(FetcherError(error_msg))
            
            if not cve_found:
                result.failed += 1
        
        return result
    
    def _deduplicate(self, cves: List[CVE]) -> List[CVE]:
        """
        去重 CVE 列表
        
        保留信息最完整的版本
        
        Args:
            cves: CVE 列表
        
        Returns:
            去重后的 CVE 列表
        """
        cve_map = {}
        
        for cve in cves:
            if cve.id not in cve_map:
                cve_map[cve.id] = cve
            else:
                # 比较并保留更完整的版本
                existing = cve_map[cve.id]
                if self._is_more_complete(cve, existing):
                    cve_map[cve.id] = cve
        
        return list(cve_map.values())
    
    def _is_more_complete(self, new: CVE, existing: CVE) -> bool:
        """
        判断新的 CVE 是否比现有的更完整
        
        Args:
            new: 新的 CVE
            existing: 现有的 CVE
        
        Returns:
            是否更完整
        """
        # 比较描述长度
        new_desc_len = len(new.description or "")
        existing_desc_len = len(existing.description or "")
        
        # 比较参考链接数量
        new_ref_count = len(new.references)
        existing_ref_count = len(existing.references)
        
        # 比较 CVSS 分数
        new_has_cvss = new.cvss_score is not None
        existing_has_cvss = existing.cvss_score is not None
        
        # 评分：描述长度 + 参考链接数 * 10 + CVSS 存在性 * 20
        new_score = new_desc_len + new_ref_count * 10 + (20 if new_has_cvss else 0)
        existing_score = existing_desc_len + existing_ref_count * 10 + (20 if existing_has_cvss else 0)
        
        return new_score > existing_score
