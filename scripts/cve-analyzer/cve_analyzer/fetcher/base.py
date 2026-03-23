"""
CVE 数据采集模块
"""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import List, Optional

from cve_analyzer.core.models import CVE


class Fetcher(ABC):
    """CVE 数据采集器基类"""
    
    @abstractmethod
    def name(self) -> str:
        """返回采集器名称"""
        pass
    
    @abstractmethod
    def fetch(self, since: Optional[str] = None, until: Optional[str] = None) -> List[CVE]:
        """
        获取 CVE 数据
        
        Args:
            since: 起始日期，格式 YYYY-MM-DD
            until: 结束日期，格式 YYYY-MM-DD，默认今天
        
        Returns:
            CVE 列表
        """
        pass
    
    @abstractmethod
    def fetch_one(self, cve_id: str) -> Optional[CVE]:
        """
        获取单个 CVE
        
        Args:
            cve_id: CVE ID，如 CVE-2024-XXXX
        
        Returns:
            CVE 对象或 None
        """
        pass


class FetchResult:
    """采集结果"""
    
    def __init__(self):
        self.cves: List[CVE] = []
        self.total: int = 0
        self.new: int = 0
        self.updated: int = 0
        self.failed: int = 0
        self.errors: List[Exception] = []
    
    def __repr__(self) -> str:
        return (
            f"FetchResult(total={self.total}, new={self.new}, "
            f"updated={self.updated}, failed={self.failed})"
        )


class FetcherError(Exception):
    """采集器错误基类"""
    pass


class APIError(FetcherError):
    """API 调用错误"""
    
    def __init__(self, message: str, status_code: int = None, response_text: str = None):
        super().__init__(message)
        self.status_code = status_code
        self.response_text = response_text


class RateLimitError(FetcherError):
    """速率限制错误"""
    pass


class ParseError(FetcherError):
    """数据解析错误"""
    pass
