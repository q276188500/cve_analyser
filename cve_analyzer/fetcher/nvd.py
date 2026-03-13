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


class NVDFetcher(Fetcher):
    """NVD 数据获取器"""
    
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    def __init__(self, api_key: Optional[str] = None, rate_limit: int = None):
        """
        初始化 NVD 获取器
        
        Args:
            api_key: NVD API key，None 则使用配置或环境变量
            rate_limit: 速率限制，None 则自动根据是否有 key 决定
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
        """
        发起 API 请求
        
        Args:
            params: 请求参数
        
        Returns:
            JSON 响应
        
        Raises:
            APIError: API 调用失败
        """
        self._rate_limit()
        
        response = self.session.get(self.BASE_URL, params=params, timeout=30)
        
        if response.status_code == 403:
            raise APIError(
                "API key invalid or rate limit exceeded",
                status_code=response.status_code,
                response_text=response.text,
            )
        elif response.status_code == 404:
            return {"vulnerabilities": []}
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
    
    def fetch(self, since: Optional[str] = None) -> List[CVE]:
        """
        获取 CVE 数据
        
        Args:
            since: 起始日期，格式 YYYY-MM-DD
        
        Returns:
            CVE 列表
        """
        cves = []
        start_index = 0
        results_per_page = 100  # NVD 最大支持 100
        
        while True:
            params = {
                "resultsPerPage": results_per_page,
                "startIndex": start_index,
            }
            
            # 添加时间范围
            if since:
                pub_start_date = datetime.strptime(since, "%Y-%m-%d")
                params["pubStartDate"] = pub_start_date.strftime("%Y-%m-%dT%H:%M:%S.000")
                params["pubEndDate"] = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000")
            
            # 只获取 Linux 相关的 CVE
            params["keywordSearch"] = "linux kernel"
            
            data = self._make_request(params)
            
            vulnerabilities = data.get("vulnerabilities", [])
            total_results = data.get("totalResults", 0)
            
            for vuln in vulnerabilities:
                try:
                    cve = normalize_nvd_to_cve(vuln)
                    if cve:
                        cves.append(cve)
                except Exception as e:
                    cve_id = vuln.get("cve", {}).get("id", "unknown")
                    print(f"Warning: Failed to normalize {cve_id}: {e}")
                    continue
            
            # 检查是否还有更多数据
            if start_index + len(vulnerabilities) >= total_results:
                break
            
            start_index += results_per_page
        
        return cves
    
    def fetch_one(self, cve_id: str) -> Optional[CVE]:
        """
        获取单个 CVE
        
        Args:
            cve_id: CVE ID，如 CVE-2024-XXXX
        
        Returns:
            CVE 对象或 None
        """
        params = {"cveId": cve_id}
        
        data = self._make_request(params)
        vulnerabilities = data.get("vulnerabilities", [])
        
        if not vulnerabilities:
            return None
        
        return normalize_nvd_to_cve(vulnerabilities[0])
