"""
CVE.org 数据获取器
https://www.cve.org/
"""

from typing import List, Optional, Dict, Any

import requests
from tenacity import retry, stop_after_attempt, wait_exponential

from cve_analyzer.core.config import get_settings
from cve_analyzer.core.models import CVE
from cve_analyzer.fetcher.base import Fetcher, APIError
from cve_analyzer.fetcher.normalizer import normalize_cve_org_to_cve


class CVEOrgFetcher(Fetcher):
    """CVE.org 数据获取器"""
    
    def __init__(self, base_url: Optional[str] = None):
        """
        初始化 CVE.org 获取器
        
        Args:
            base_url: API 基础 URL，None 则使用配置
        """
        settings = get_settings()
        self.base_url = base_url or settings.data_sources.cve_org.base_url
        self.session = requests.Session()
        self.session.headers.update({
            "Accept": "application/json",
            "User-Agent": "CVE-Analyzer/0.1.0",
        })
    
    def name(self) -> str:
        """返回采集器名称"""
        return "CVE.org"
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=lambda e: isinstance(e, (requests.exceptions.RequestException,)),
    )
    def _make_request(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        发起 API 请求
        
        Args:
            cve_id: CVE ID
        
        Returns:
            JSON 响应或 None
        
        Raises:
            APIError: API 调用失败
        """
        url = f"{self.base_url}{cve_id}"
        response = self.session.get(url, timeout=30)
        
        if response.status_code == 404:
            return None
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
            raise APIError(f"Failed to parse JSON: {e}")
    
    def fetch(self, since: Optional[str] = None) -> List[CVE]:
        """
        获取 CVE 数据
        
        注意: CVE.org API 不支持批量获取，此方法返回空列表
        建议使用 fetch_one 获取单个 CVE
        
        Args:
            since: 起始日期，格式 YYYY-MM-DD (暂不支持)
        
        Returns:
            CVE 列表 (空)
        """
        # CVE.org 不提供批量查询接口，需要配合其他数据源使用
        # 或者通过其他方式（如下载完整 CVE 列表）实现
        return []
    
    def fetch_one(self, cve_id: str) -> Optional[CVE]:
        """
        获取单个 CVE
        
        Args:
            cve_id: CVE ID，如 CVE-2024-XXXX
        
        Returns:
            CVE 对象或 None
        """
        data = self._make_request(cve_id)
        
        if data is None:
            return None
        
        try:
            return normalize_cve_org_to_cve(data)
        except Exception as e:
            raise APIError(f"Failed to normalize CVE data: {e}")
