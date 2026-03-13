"""
Phase 2: CVE 数据采集模块测试 (测试驱动需求)

这些测试定义了 Phase 2 的功能需求，待实现后测试应通过
"""

import pytest
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock

from cve_analyzer.fetcher import Fetcher, FetchResult
from cve_analyzer.core.models import CVE


class TestNVDFetcher:
    """NVD 数据获取器测试 - Phase 2 需求"""
    
    @pytest.fixture
    def mock_nvd_response(self):
        """模拟 NVD API 响应"""
        return {
            "resultsPerPage": 2,
            "startIndex": 0,
            "totalResults": 2,
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-1234",
                        "descriptions": [
                            {
                                "lang": "en",
                                "value": "Test vulnerability in Linux kernel netfilter"
                            }
                        ],
                        "published": "2024-01-15T00:00:00.000",
                        "lastModified": "2024-01-20T00:00:00.000",
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "cvssData": {
                                        "baseScore": 7.5,
                                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
                                    },
                                    "baseSeverity": "HIGH"
                                }
                            ]
                        },
                        "references": [
                            {
                                "url": "https://git.kernel.org/.../c/abc123",
                                "source": "Linux",
                                "tags": ["Patch"]
                            }
                        ],
                        "configurations": [
                            {
                                "nodes": [
                                    {
                                        "cpeMatch": [
                                            {
                                                "criteria": "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*",
                                                "versionStartIncluding": "5.10",
                                                "versionEndExcluding": "6.6",
                                                "vulnerable": True
                                            }
                                        ]
                                    }
                                ]
                            }
                        ]
                    }
                }
            ]
        }
    
    def test_nvd_fetcher_name(self):
        """NVD 获取器名称应为 'NVD'"""
        from cve_analyzer.fetcher.nvd import NVDFetcher
        
        fetcher = NVDFetcher(api_key="test-key")
        assert fetcher.name() == "NVD"
    
    def test_nvd_fetch_without_api_key(self):
        """没有 API key 时应该能工作但有限制"""
        from cve_analyzer.fetcher.nvd import NVDFetcher
        
        fetcher = NVDFetcher()
        assert fetcher.api_key is None
        assert fetcher.rate_limit == 5  # 无 key 时限制更严格
    
    @pytest.mark.skip(reason="Phase 2 待实现")
    def test_nvd_fetch_single_page(self, mock_nvd_response):
        """测试获取单页 CVE 数据"""
        from cve_analyzer.fetcher.nvd import NVDFetcher
        
        with patch("requests.get") as mock_get:
            mock_get.return_value.json.return_value = mock_nvd_response
            mock_get.return_value.status_code = 200
            
            fetcher = NVDFetcher(api_key="test-key")
            cves = fetcher.fetch(since="2024-01-01")
            
            assert len(cves) == 1
            assert cves[0].id == "CVE-2024-1234"
            assert cves[0].severity == "HIGH"
    
    @pytest.mark.skip(reason="Phase 2 待实现")
    def test_nvd_fetch_respects_rate_limit(self):
        """测试遵守速率限制"""
        from cve_analyzer.fetcher.nvd import NVDFetcher
        import time
        
        fetcher = NVDFetcher(api_key="test-key", rate_limit=6)
        
        start_time = time.time()
        
        # 模拟多次请求
        with patch("requests.get") as mock_get:
            mock_get.return_value.json.return_value = {"vulnerabilities": []}
            mock_get.return_value.status_code = 200
            
            for _ in range(7):  # 超过每秒限制
                fetcher.fetch(since="2024-01-01")
        
        elapsed = time.time() - start_time
        
        # 7 个请求，限制每秒 6 个，应该至少等待 1 秒
        assert elapsed >= 1.0
    
    @pytest.mark.skip(reason="Phase 2 待实现")
    def test_nvd_fetch_pagination(self):
        """测试分页获取大量数据"""
        from cve_analyzer.fetcher.nvd import NVDFetcher
        
        # 模拟多页响应
        responses = [
            {
                "resultsPerPage": 100,
                "startIndex": 0,
                "totalResults": 250,
                "vulnerabilities": [{"cve": {"id": f"CVE-2024-{i:04d}"}} for i in range(100)]
            },
            {
                "resultsPerPage": 100,
                "startIndex": 100,
                "totalResults": 250,
                "vulnerabilities": [{"cve": {"id": f"CVE-2024-{i:04d}"}} for i in range(100, 200)]
            },
            {
                "resultsPerPage": 50,
                "startIndex": 200,
                "totalResults": 250,
                "vulnerabilities": [{"cve": {"id": f"CVE-2024-{i:04d}"}} for i in range(200, 250)]
            }
        ]
        
        with patch("requests.get") as mock_get:
            mock_get.side_effect = [
                Mock(json=lambda: r, status_code=200) for r in responses
            ]
            
            fetcher = NVDFetcher(api_key="test-key")
            cves = fetcher.fetch(since="2024-01-01")
            
            assert len(cves) == 250
            assert mock_get.call_count == 3
    
    @pytest.mark.skip(reason="Phase 2 待实现")
    def test_nvd_fetch_one_cve(self):
        """测试获取单个 CVE"""
        from cve_analyzer.fetcher.nvd import NVDFetcher
        
        mock_response = {
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2024-1234",
                    "descriptions": [{"lang": "en", "value": "Test"}],
                }
            }]
        }
        
        with patch("requests.get") as mock_get:
            mock_get.return_value.json.return_value = mock_response
            mock_get.return_value.status_code = 200
            
            fetcher = NVDFetcher(api_key="test-key")
            cve = fetcher.fetch_one("CVE-2024-1234")
            
            assert cve is not None
            assert cve.id == "CVE-2024-1234"
    
    @pytest.mark.skip(reason="Phase 2 待实现")
    def test_nvd_fetch_handles_api_error(self):
        """测试处理 API 错误"""
        from cve_analyzer.fetcher.nvd import NVDFetcher, NVDAPIError
        
        with patch("requests.get") as mock_get:
            mock_get.return_value.status_code = 503
            mock_get.return_value.text = "Service Unavailable"
            
            fetcher = NVDFetcher(api_key="test-key")
            
            with pytest.raises(NVDAPIError):
                fetcher.fetch(since="2024-01-01")
    
    @pytest.mark.skip(reason="Phase 2 待实现")
    def test_nvd_fetch_retries_on_failure(self):
        """测试失败时重试"""
        from cve_analyzer.fetcher.nvd import NVDFetcher
        
        with patch("requests.get") as mock_get:
            # 前两次失败，第三次成功
            mock_get.side_effect = [
                Mock(status_code=500, text="Internal Error"),
                Mock(status_code=503, text="Service Unavailable"),
                Mock(
                    status_code=200,
                    json=lambda: {"vulnerabilities": []}
                ),
            ]
            
            fetcher = NVDFetcher(api_key="test-key")
            cves = fetcher.fetch(since="2024-01-01")
            
            assert mock_get.call_count == 3


class TestCVEOrgFetcher:
    """CVE.org 数据获取器测试 - Phase 2 需求"""
    
    @pytest.fixture
    def mock_cve_org_response(self):
        """模拟 CVE.org API 响应"""
        return {
            "cveMetadata": {
                "cveId": "CVE-2024-1234",
                "state": "PUBLISHED",
                "datePublished": "2024-01-15T00:00:00Z",
                "dateUpdated": "2024-01-20T00:00:00Z"
            },
            "containers": {
                "cna": {
                    "descriptions": [
                        {
                            "lang": "en",
                            "value": "Test vulnerability"
                        }
                    ],
                    "affected": [
                        {
                            "vendor": "Linux",
                            "product": "Linux Kernel",
                            "versions": [
                                {
                                    "version": "5.10",
                                    "status": "affected",
                                    "lessThan": "6.6",
                                    "versionType": "semver"
                                }
                            ]
                        }
                    ],
                    "references": [
                        {
                            "url": "https://git.kernel.org/.../c/abc123"
                        }
                    ],
                    "metrics": [
                        {
                            "format": "CVSS",
                            "scenarios": [{"lang": "en", "value": "GENERAL"}],
                            "cvssV3_1": {
                                "version": "3.1",
                                "baseScore": 7.5,
                                "baseSeverity": "HIGH",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
                            }
                        }
                    ]
                }
            }
        }
    
    def test_cve_org_fetcher_name(self):
        """CVE.org 获取器名称应为 'CVE.org'"""
        from cve_analyzer.fetcher.cve_org import CVEOrgFetcher
        
        fetcher = CVEOrgFetcher()
        assert fetcher.name() == "CVE.org"
    
    @pytest.mark.skip(reason="Phase 2 待实现")
    def test_cve_org_fetch_one(self, mock_cve_org_response):
        """测试获取单个 CVE"""
        from cve_analyzer.fetcher.cve_org import CVEOrgFetcher
        
        with patch("requests.get") as mock_get:
            mock_get.return_value.json.return_value = mock_cve_org_response
            mock_get.return_value.status_code = 200
            
            fetcher = CVEOrgFetcher()
            cve = fetcher.fetch_one("CVE-2024-1234")
            
            assert cve is not None
            assert cve.id == "CVE-2024-1234"
            assert cve.severity == "HIGH"
    
    @pytest.mark.skip(reason="Phase 2 待实现")
    def test_cve_org_fetch_not_found(self):
        """测试 CVE 不存在的情况"""
        from cve_analyzer.fetcher.cve_org import CVEOrgFetcher
        
        with patch("requests.get") as mock_get:
            mock_get.return_value.status_code = 404
            
            fetcher = CVEOrgFetcher()
            cve = fetcher.fetch_one("CVE-NOT-EXIST")
            
            assert cve is None


class TestFetchOrchestrator:
    """采集协调器测试 - Phase 2 需求"""
    
    @pytest.mark.skip(reason="Phase 2 待实现")
    def test_orchestrator_uses_all_enabled_fetchers(self):
        """测试协调器使用所有启用的获取器"""
        from cve_analyzer.fetcher.orchestrator import FetchOrchestrator
        
        mock_fetchers = [
            Mock(spec=Fetcher, name="NVD"),
            Mock(spec=Fetcher, name="CVE.org"),
        ]
        
        mock_fetchers[0].fetch.return_value = [
            CVE(id="CVE-2024-0001", description="From NVD")
        ]
        mock_fetchers[1].fetch.return_value = [
            CVE(id="CVE-2024-0002", description="From CVE.org")
        ]
        
        orchestrator = FetchOrchestrator(fetchers=mock_fetchers)
        result = orchestrator.fetch_all(since="2024-01-01")
        
        assert len(result.cves) == 2
        assert mock_fetchers[0].fetch.called
        assert mock_fetchers[1].fetch.called
    
    @pytest.mark.skip(reason="Phase 2 待实现")
    def test_orchestrator_deduplicates_cves(self):
        """测试去重 CVE"""
        from cve_analyzer.fetcher.orchestrator import FetchOrchestrator
        
        mock_fetchers = [
            Mock(spec=Fetcher),
            Mock(spec=Fetcher),
        ]
        
        # 两个获取器返回相同的 CVE
        same_cve = CVE(id="CVE-2024-1234", description="Duplicate")
        mock_fetchers[0].fetch.return_value = [same_cve]
        mock_fetchers[1].fetch.return_value = [same_cve]
        
        orchestrator = FetchOrchestrator(fetchers=mock_fetchers)
        result = orchestrator.fetch_all(since="2024-01-01")
        
        assert len(result.cves) == 1
        assert result.cves[0].id == "CVE-2024-1234"
    
    @pytest.mark.skip(reason="Phase 2 待实现")
    def test_orchestrator_handles_fetcher_failure(self):
        """测试处理获取器失败"""
        from cve_analyzer.fetcher.orchestrator import FetchOrchestrator
        
        mock_fetchers = [
            Mock(spec=Fetcher),
            Mock(spec=Fetcher),
        ]
        
        mock_fetchers[0].fetch.side_effect = Exception("Network error")
        mock_fetchers[1].fetch.return_value = [
            CVE(id="CVE-2024-0002", description="Success")
        ]
        
        orchestrator = FetchOrchestrator(fetchers=mock_fetchers)
        result = orchestrator.fetch_all(since="2024-01-01")
        
        assert len(result.cves) == 1
        assert len(result.errors) == 1
        assert result.failed == 1
    
    @pytest.mark.skip(reason="Phase 2 待实现")
    def test_orchestrator_respects_max_workers(self):
        """测试遵守最大并发数"""
        from cve_analyzer.fetcher.orchestrator import FetchOrchestrator
        from concurrent.futures import ThreadPoolExecutor
        
        mock_fetchers = [Mock(spec=Fetcher) for _ in range(10)]
        
        for f in mock_fetchers:
            f.fetch.return_value = []
        
        orchestrator = FetchOrchestrator(
            fetchers=mock_fetchers,
            max_workers=3
        )
        
        # 验证使用了 ThreadPoolExecutor 且 max_workers=3
        with patch("concurrent.futures.ThreadPoolExecutor") as mock_executor:
            mock_executor_instance = MagicMock()
            mock_executor.return_value = mock_executor_instance
            
            orchestrator.fetch_all(since="2024-01-01")
            
            mock_executor.assert_called_once_with(max_workers=3)


class TestFetchResult:
    """FetchResult 结果类测试"""
    
    def test_fetch_result_initialization(self):
        """测试结果类初始化"""
        result = FetchResult()
        
        assert result.cves == []
        assert result.total == 0
        assert result.new == 0
        assert result.updated == 0
        assert result.failed == 0
        assert result.errors == []
    
    def test_fetch_result_add_cve(self):
        """测试添加 CVE 到结果"""
        result = FetchResult()
        cve = CVE(id="CVE-2024-1234", description="Test")
        
        result.cves.append(cve)
        result.total += 1
        result.new += 1
        
        assert result.total == 1
        assert result.new == 1
        assert len(result.cves) == 1
    
    def test_fetch_result_add_error(self):
        """测试添加错误到结果"""
        result = FetchResult()
        error = Exception("Test error")
        
        result.errors.append(error)
        result.failed += 1
        
        assert result.failed == 1
        assert len(result.errors) == 1


class TestDataNormalization:
    """数据规范化测试 - Phase 2 需求"""
    
    @pytest.mark.skip(reason="Phase 2 待实现")
    def test_normalize_nvd_cve(self):
        """测试规范化 NVD 数据为 CVE 模型"""
        from cve_analyzer.fetcher.normalizer import normalize_nvd_to_cve
        
        nvd_data = {
            "cve": {
                "id": "CVE-2024-1234",
                "descriptions": [{"lang": "en", "value": "Test"}],
                "published": "2024-01-15T00:00:00.000",
                "metrics": {
                    "cvssMetricV31": [{
                        "cvssData": {
                            "baseScore": 7.5,
                            "vectorString": "CVSS:3.1/..."
                        },
                        "baseSeverity": "HIGH"
                    }]
                }
            }
        }
        
        cve = normalize_nvd_to_cve(nvd_data)
        
        assert cve.id == "CVE-2024-1234"
        assert cve.severity == "HIGH"
        assert cve.cvss_score == 7.5
        assert isinstance(cve.published_date, datetime)
    
    @pytest.mark.skip(reason="Phase 2 待实现")
    def test_normalize_cve_org_cve(self):
        """测试规范化 CVE.org 数据为 CVE 模型"""
        from cve_analyzer.fetcher.normalizer import normalize_cve_org_to_cve
        
        cve_org_data = {
            "cveMetadata": {
                "cveId": "CVE-2024-1234",
                "datePublished": "2024-01-15T00:00:00Z"
            },
            "containers": {
                "cna": {
                    "descriptions": [{"lang": "en", "value": "Test"}],
                    "metrics": [{
                        "cvssV3_1": {
                            "baseScore": 7.5,
                            "baseSeverity": "HIGH"
                        }
                    }]
                }
            }
        }
        
        cve = normalize_cve_org_to_cve(cve_org_data)
        
        assert cve.id == "CVE-2024-1234"
        assert cve.severity == "HIGH"
