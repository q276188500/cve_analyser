"""
NVD (National Vulnerability Database) 数据获取器
https://nvd.nist.gov/
"""

import time
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any

import requests
from tenacity import retry, stop_after_attempt, wait_exponential

from cve_analyzer.core.config import get_settings
from cve_analyzer.core.models import CVE, CVEReference, Severity
from cve_analyzer.fetcher.base import Fetcher, APIError, FetcherError
from cve_analyzer.fetcher.normalizer import normalize_nvd_to_cve
from cve_analyzer.fetcher.state import FetchState


class NVDFetcher(Fetcher):
    """NVD 数据获取器"""
    
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    def __init__(self, api_key: Optional[str] = None, rate_limit: int = None, state_file: Optional[str] = None):
        """
        初始化 NVD 获取器
        
        Args:
            api_key: NVD API key，None 则使用配置或环境变量
            rate_limit: 速率限制，None 则自动根据是否有 key 决定
            state_file: 状态文件路径，None 则使用默认
        """
        settings = get_settings()
        
        self.api_key = api_key or settings.data_sources.nvd.api_key
        self.rate_limit = rate_limit or (
            6 if self.api_key else 5  # 有 key 6 req/s，无 key 5 req/s
        )
        self.last_request_time = 0.0
        self.min_interval = 1.0 / self.rate_limit
        
        self.session = requests.Session()
        if self.api_key:
            self.session.headers["apiKey"] = self.api_key
        
        # 断点续传状态
        self.state = FetchState(state_file or ".fetch_state_nvd.json")
    
    def name(self) -> str:
        """返回采集器名称"""
        return "NVD"
    
    def _rate_limit(self):
        """速率限制控制"""
        current_time = time.time()
        elapsed = current_time - self.last_request_time
        
        if elapsed < self.min_interval:
            sleep_time = self.min_interval - elapsed
            time.sleep(sleep_time)
        
        self.last_request_time = time.time()
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=10),
        retry=lambda e: isinstance(e, (requests.exceptions.RequestException, APIError)),
    )
    def _make_request(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """发起 API 请求"""
        self._rate_limit()
        
        response = self.session.get(self.BASE_URL, params=params, timeout=30)
        
        if response.status_code == 403:
            raise APIError(
                "API key invalid or rate limit exceeded",
                status_code=response.status_code,
                response_text=response.text,
            )
        elif response.status_code == 404:
            return {"vulnerabilities": [], "totalResults": 0}
        elif response.status_code >= 500:
            raise APIError(
                f"Server error: {response.status_code}",
                status_code=response.status_code,
                response_text=response.text,
            )
        elif response.status_code != 200:
            raise APIError(
                f"API error: {response.status_code}",
                status_code=response.status_code,
                response_text=response.text,
            )
        
        try:
            return response.json()
        except Exception as e:
            raise FetcherError(f"Failed to parse JSON response: {e}")
    
    def fetch(self, since: Optional[str] = None, until: Optional[str] = None, 
              progress_callback=None, resume: bool = False) -> List[CVE]:
        """
        获取 CVE 数据
        
        Args:
            since: 起始日期，格式 YYYY-MM-DD
            until: 结束日期，格式 YYYY-MM-DD，默认今天
            progress_callback: 进度回调函数
            resume: 是否启用断点续传
        
        Returns:
            CVE 列表
        """
        cves = []
        
        # 确定时间范围
        if since:
            start_date = datetime.strptime(since, "%Y-%m-%d")
        else:
            start_date = datetime.utcnow() - timedelta(days=30)
        
        if until:
            end_date = datetime.strptime(until, "%Y-%m-%d")
        else:
            end_date = datetime.utcnow()
        
        # 断点续传
        fetched_ids = set()
        if resume:
            last_fetch = self.state.get_last_fetch("nvd")
            if last_fetch and last_fetch > start_date:
                print(f"[断点续传] 从上次时间 {last_fetch.strftime('%Y-%m-%d')} 继续")
                start_date = last_fetch
            fetched_ids = self.state.get_fetched_cve_ids()
            print(f"[断点续传] 已抓取 {len(fetched_ids)} 个 CVE，将跳过已存在的")
        
        # 计算总块数
        total_chunks = 0
        tmp_start = start_date
        while tmp_start < end_date:
            total_chunks += 1
            tmp_start += timedelta(days=30)
        
        # 按月份分块抓取
        chunk_start = start_date
        chunk_index = 0
        
        try:
            while chunk_start < end_date:
                chunk_end = min(chunk_start + timedelta(days=30), end_date)
                chunk_key = f"{chunk_start.strftime('%Y%m%d')}_{chunk_end.strftime('%Y%m%d')}"
                
                # 检查是否已抓取
                if resume:
                    chunk_state = self.state.get_chunk_progress(chunk_key)
                    if chunk_state and chunk_state.get("completed"):
                        print(f"[断点续传] 跳过已完成块: {chunk_key}")
                        chunk_start = chunk_end
                        chunk_index += 1
                        continue
                
                if progress_callback:
                    progress_callback(chunk_index, total_chunks, 
                        f"正在抓取 {chunk_start.strftime('%Y-%m-%d')} ~ {chunk_end.strftime('%Y-%m-%d')}")
                
                # 抓取块
                chunk_cves = self._fetch_chunk(
                    chunk_start, chunk_end, progress_callback, 
                    chunk_index, total_chunks
                )
                
                # 去重
                new_cves = [c for c in chunk_cves if c.id not in fetched_ids]
                cves.extend(new_cves)
                
                # 保存状态
                if resume:
                    for cve in new_cves:
                        self.state.add_fetched_cve_id(cve.id)
                        fetched_ids.add(cve.id)
                    self.state.set_chunk_progress(chunk_key, {
                        "completed": True, 
                        "count": len(new_cves),
                        "timestamp": datetime.utcnow().isoformat()
                    })
                
                chunk_start = chunk_end
                chunk_index += 1
                
                if chunk_start < end_date:
                    time.sleep(self.min_interval)
            
            # 保存最终状态
            if resume:
                self.state.set_last_fetch("nvd", datetime.utcnow())
                self.state.save_fetched_cve_ids()
            
            if progress_callback:
                progress_callback(total_chunks, total_chunks, 
                    f"抓取完成，共 {len(cves)} 个新 CVE")
        
        except KeyboardInterrupt:
            print("\n[中断] 保存状态...")
            if resume:
                self.state.set_last_fetch("nvd", datetime.utcnow())
                self.state.save_fetched_cve_ids()
            raise
        
        return cves
    
    def _fetch_chunk(self, start_date: datetime, end_date: datetime, 
                     progress_callback=None, chunk_index=0, total_chunks=1) -> List[CVE]:
        """获取一个时间块的 CVE"""
        cves = []
        start_index = 0
        results_per_page = 100
        total_results = None
        
        while True:
            params = {
                "resultsPerPage": results_per_page,
                "startIndex": start_index,
                "pubStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
                "pubEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
                "keywordSearch": "linux kernel",
            }
            
            try:
                data = self._make_request(params)
            except APIError as e:
                if e.status_code == 404:
                    break
                raise
            
            vulnerabilities = data.get("vulnerabilities", [])
            if total_results is None:
                total_results = data.get("totalResults", 0)
            
            # 更新进度
            if progress_callback and total_results > 0:
                current_count = start_index + len(vulnerabilities)
                message = f"块 {chunk_index + 1}/{total_chunks}: {current_count}/{total_results}"
                progress_callback(chunk_index, total_chunks, message)
            
            for vuln in vulnerabilities:
                try:
                    cve = normalize_nvd_to_cve(vuln)
                    if cve:
                        cves.append(cve)
                except Exception as e:
                    cve_id = vuln.get("cve", {}).get("id", "unknown")
                    print(f"Warning: Failed to normalize {cve_id}: {e}")
            
            if start_index + len(vulnerabilities) >= total_results:
                break
            
            start_index += results_per_page
        
        return cves
    
    def clear_state(self):
        """清除断点续传状态"""
        self.state.clear()
        print("[断点续传] 状态已清除")
    
    def fetch_one(self, cve_id: str) -> Optional[CVE]:
        """获取单个 CVE"""
        params = {"cveId": cve_id}
        
        data = self._make_request(params)
        vulnerabilities = data.get("vulnerabilities", [])
        
        if not vulnerabilities:
            return None
        
        return normalize_nvd_to_cve(vulnerabilities[0])
