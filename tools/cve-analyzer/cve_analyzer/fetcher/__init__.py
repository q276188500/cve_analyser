"""
CVE 数据采集模块
"""

from cve_analyzer.fetcher.base import (
    Fetcher,
    FetchResult,
    FetcherError,
    APIError,
    RateLimitError,
    ParseError,
)
from cve_analyzer.fetcher.nvd import NVDFetcher
from cve_analyzer.fetcher.cve_org import CVEOrgFetcher
from cve_analyzer.fetcher.orchestrator import FetchOrchestrator
from cve_analyzer.fetcher.normalizer import (
    normalize_nvd_to_cve,
    normalize_cve_org_to_cve,
)

__all__ = [
    "Fetcher",
    "FetchResult",
    "FetcherError",
    "APIError",
    "RateLimitError",
    "ParseError",
    "NVDFetcher",
    "CVEOrgFetcher",
    "FetchOrchestrator",
    "normalize_nvd_to_cve",
    "normalize_cve_org_to_cve",
]
