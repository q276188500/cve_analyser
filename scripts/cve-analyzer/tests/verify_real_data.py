#!/usr/bin/env python3
"""
真实数据验证脚本 - 测试 Phase 2 采集模块

直接调用 NVD 和 CVE.org API，验证数据获取和解析
"""

import json
import sys
from datetime import datetime, timedelta
from pathlib import Path

# 添加项目路径
sys.path.insert(0, str(Path(__file__).parent.parent))

from cve_analyzer.fetcher.nvd import NVDFetcher
from cve_analyzer.fetcher.cve_org import CVEOrgFetcher
from cve_analyzer.fetcher.orchestrator import FetchOrchestrator
from cve_analyzer.core.config import reset_settings, Settings
from cve_analyzer.core.database import Database, reset_db


def test_nvd_fetch_one():
    """测试获取单个真实 CVE"""
    print("=" * 60)
    print("测试 1: NVD 获取单个 CVE")
    print("=" * 60)
    
    fetcher = NVDFetcher()
    
    # 获取一个已知的 Linux 内核 CVE
    test_cves = [
        "CVE-2024-1086",  # 较新的 Linux CVE
        "CVE-2023-38408",  # OpenSSH (作为对比)
    ]
    
    for cve_id in test_cves:
        try:
            print(f"\n获取 {cve_id}...")
            cve = fetcher.fetch_one(cve_id)
            
            if cve:
                print(f"✓ 成功获取")
                print(f"  ID: {cve.id}")
                print(f"  描述: {cve.description[:100]}..." if len(cve.description) > 100 else f"  描述: {cve.description}")
                print(f"  严重程度: {cve.severity}")
                print(f"  CVSS 分数: {cve.cvss_score}")
                print(f"  发布时间: {cve.published_date}")
                print(f"  参考链接数: {len(cve.references)}")
                
                # 查找补丁链接
                patch_refs = [r for r in cve.references if r.type == "PATCH"]
                if patch_refs:
                    print(f"  补丁链接: {patch_refs[0].url[:80]}...")
            else:
                print(f"✗ 未找到 {cve_id}")
                
        except Exception as e:
            print(f"✗ 错误: {e}")


def test_nvd_fetch_batch():
    """测试批量获取 CVE"""
    print("\n" + "=" * 60)
    print("测试 2: NVD 批量获取 (最近 30 天的 Linux CVE)")
    print("=" * 60)
    
    fetcher = NVDFetcher()
    
    # 获取最近 30 天的数据
    since_date = (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%d")
    
    try:
        print(f"\n从 {since_date} 开始获取...")
        print("(NVD 速率限制: 每秒 5-6 次请求，请耐心等待)")
        
        cves = fetcher.fetch(since=since_date)
        
        print(f"\n✓ 获取成功")
        print(f"  共获取 {len(cves)} 个 CVE")
        
        if cves:
            # 统计
            severity_counts = {}
            for cve in cves:
                sev = cve.severity or "UNKNOWN"
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
            
            print(f"\n  严重程度分布:")
            for sev, count in sorted(severity_counts.items()):
                print(f"    {sev}: {count}")
            
            # 显示前 3 个
            print(f"\n  前 3 个 CVE:")
            for cve in cves[:3]:
                print(f"    - {cve.id}: {cve.severity} ({cve.cvss_score})")
                
    except Exception as e:
        print(f"✗ 错误: {e}")
        import traceback
        traceback.print_exc()


def test_cve_org_fetch():
    """测试 CVE.org 获取"""
    print("\n" + "=" * 60)
    print("测试 3: CVE.org 获取单个 CVE")
    print("=" * 60)
    
    fetcher = CVEOrgFetcher()
    
    test_cves = [
        "CVE-2024-1086",
        "CVE-2023-4911",  # glibc
    ]
    
    for cve_id in test_cves:
        try:
            print(f"\n获取 {cve_id}...")
            cve = fetcher.fetch_one(cve_id)
            
            if cve:
                print(f"✓ 成功获取")
                print(f"  ID: {cve.id}")
                print(f"  描述: {cve.description[:100]}..." if cve.description and len(cve.description) > 100 else f"  描述: {cve.description}")
                print(f"  严重程度: {cve.severity}")
                print(f"  受影响配置数: {len(cve.affected_configs)}")
            else:
                print(f"✗ 未找到 {cve_id}")
                
        except Exception as e:
            print(f"✗ 错误: {e}")


def test_orchestrator():
    """测试协调器多源聚合"""
    print("\n" + "=" * 60)
    print("测试 4: 协调器多源聚合")
    print("=" * 60)
    
    orchestrator = FetchOrchestrator()
    
    test_cves = ["CVE-2024-1086", "CVE-2023-4911"]
    
    try:
        print(f"\n获取指定 CVE: {test_cves}")
        result = orchestrator.fetch_all(cve_ids=test_cves)
        
        print(f"\n✓ 获取成功")
        print(f"  总数: {result.total}")
        print(f"  新增: {result.new}")
        print(f"  失败: {result.failed}")
        print(f"  错误数: {len(result.errors)}")
        
        for cve in result.cves:
            print(f"\n  {cve.id}:")
            print(f"    来源: {', '.join(set(r.source for r in cve.references))}")
            print(f"    参考链接: {len(cve.references)} 个")
            
    except Exception as e:
        print(f"✗ 错误: {e}")
        import traceback
        traceback.print_exc()


def save_sample_data():
    """保存样本数据到文件"""
    print("\n" + "=" * 60)
    print("测试 5: 保存样本数据")
    print("=" * 60)
    
    fetcher = NVDFetcher()
    
    try:
        print("\n获取样本 CVE...")
        cve = fetcher.fetch_one("CVE-2024-1086")
        
        if cve:
            # 创建样本目录
            sample_dir = Path(__file__).parent / "sample_data"
            sample_dir.mkdir(exist_ok=True)
            
            # 保存为 JSON
            sample_file = sample_dir / "cve_sample.json"
            
            data = {
                "id": cve.id,
                "description": cve.description,
                "severity": cve.severity,
                "cvss_score": cve.cvss_score,
                "cvss_vector": cve.cvss_vector,
                "published_date": cve.published_date.isoformat() if cve.published_date else None,
                "references": [
                    {
                        "url": r.url,
                        "type": r.type,
                        "source": r.source,
                    }
                    for r in cve.references
                ],
                "affected_configs": [
                    {
                        "vendor": ac.vendor,
                        "product": ac.product,
                        "version_start": ac.version_start,
                        "version_end": ac.version_end,
                    }
                    for ac in cve.affected_configs
                ],
            }
            
            with open(sample_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            
            print(f"✓ 样本数据已保存: {sample_file}")
            
    except Exception as e:
        print(f"✗ 错误: {e}")


def main():
    """主函数"""
    print("\n" + "=" * 60)
    print("CVE Analyzer - Phase 2 真实数据验证")
    print("=" * 60)
    print("\n注意:")
    print("- 本脚本直接调用 NVD 和 CVE.org API")
    print("- 受限于 NVD 速率限制 (5-6 req/s)，批量获取较慢")
    print("- 请确保网络连接正常")
    print()
    
    # 测试 1: NVD 单个获取
    test_nvd_fetch_one()
    
    # 测试 2: NVD 批量获取
    test_nvd_fetch_batch()
    
    # 测试 3: CVE.org 获取
    test_cve_org_fetch()
    
    # 测试 4: 协调器
    test_orchestrator()
    
    # 测试 5: 保存样本
    save_sample_data()
    
    print("\n" + "=" * 60)
    print("验证完成!")
    print("=" * 60)


if __name__ == "__main__":
    main()
