"""
数据规范化模块
将不同数据源的 CVE 数据规范化为统一的 CVE 模型
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from cve_analyzer.core.models import CVE, CVEReference, AffectedConfig, Severity


def parse_datetime(date_str: Optional[str]) -> Optional[datetime]:
    """解析日期字符串为 datetime 对象"""
    if not date_str:
        return None
    
    formats = [
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%d",
    ]
    
    for fmt in formats:
        try:
            return datetime.strptime(date_str.replace("Z", ""), fmt)
        except ValueError:
            continue
    
    return None


def parse_severity(severity_str: Optional[str]) -> str:
    """解析严重程度字符串"""
    if not severity_str:
        return Severity.UNKNOWN.value
    
    severity_upper = severity_str.upper()
    valid_severities = [s.value for s in Severity]
    
    if severity_upper in valid_severities:
        return severity_upper
    
    return Severity.UNKNOWN.value


def normalize_nvd_to_cve(nvd_data: Dict[str, Any]) -> Optional[CVE]:
    """
    将 NVD 数据规范化为 CVE 模型
    
    Args:
        nvd_data: NVD API 返回的 vulnerability 对象
    
    Returns:
        CVE 模型对象
    """
    cve_data = nvd_data.get("cve", {})
    
    cve_id = cve_data.get("id")
    if not cve_id:
        return None
    
    # 描述
    descriptions = cve_data.get("descriptions", [])
    description = ""
    for desc in descriptions:
        if desc.get("lang") == "en":
            description = desc.get("value", "")
            break
    
    # 日期
    published_date = parse_datetime(cve_data.get("published"))
    last_modified = parse_datetime(cve_data.get("lastModified"))
    
    # CVSS 分数和严重程度
    cvss_score = None
    severity = Severity.UNKNOWN.value
    cvss_vector = None
    
    metrics = cve_data.get("metrics", {})
    
    # 优先使用 CVSS 3.1
    cvss_v31 = metrics.get("cvssMetricV31", [])
    if cvss_v31:
        cvss_data = cvss_v31[0].get("cvssData", {})
        cvss_score = cvss_data.get("baseScore")
        severity = parse_severity(cvss_v31[0].get("baseSeverity"))
        cvss_vector = cvss_data.get("vectorString")
    else:
        # 退回到 CVSS 3.0
        cvss_v30 = metrics.get("cvssMetricV30", [])
        if cvss_v30:
            cvss_data = cvss_v30[0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            severity = parse_severity(cvss_v30[0].get("baseSeverity"))
            cvss_vector = cvss_data.get("vectorString")
        else:
            # 退回到 CVSS 2.0
            cvss_v2 = metrics.get("cvssMetricV2", [])
            if cvss_v2:
                cvss_score = cvss_v2[0].get("cvssData", {}).get("baseScore")
                severity = parse_severity(cvss_v2[0].get("baseSeverity"))
                cvss_vector = cvss_v2[0].get("cvssData", {}).get("vectorString")
    
    # 创建 CVE 对象
    cve = CVE(
        id=cve_id,
        description=description,
        published_date=published_date,
        last_modified=last_modified,
        severity=severity,
        cvss_score=cvss_score,
        cvss_vector=cvss_vector,
    )
    
    # 参考链接
    references = cve_data.get("references", [])
    for ref in references:
        ref_url = ref.get("url", "")
        ref_type = None
        
        tags = ref.get("tags", [])
        if "Patch" in tags:
            ref_type = "PATCH"
        elif "Exploit" in tags:
            ref_type = "EXPLOIT"
        elif "Vendor Advisory" in tags:
            ref_type = "ADVISORY"
        
        cve.references.append(CVEReference(
            cve_id=cve_id,
            url=ref_url,
            type=ref_type,
            source="NVD",
        ))
    
    # 受影响配置
    configurations = cve_data.get("configurations", [])
    for config in configurations:
        nodes = config.get("nodes", [])
        for node in nodes:
            cpe_matches = node.get("cpeMatch", [])
            for match in cpe_matches:
                if not match.get("vulnerable", True):
                    continue
                
                criteria = match.get("criteria", "")
                if "linux:linux_kernel" in criteria.lower():
                    affected_config = AffectedConfig(
                        cve_id=cve_id,
                        vendor="Linux",
                        product="Linux Kernel",
                        version_start=match.get("versionStartIncluding") or match.get("versionStartExcluding"),
                        version_end=match.get("versionEndIncluding") or match.get("versionEndExcluding"),
                        version_exact=match.get("versionEndIncluding") if not (match.get("versionStartIncluding") or match.get("versionStartExcluding")) else None,
                        cpe_match=criteria,
                    )
                    cve.affected_configs.append(affected_config)
    
    return cve


def normalize_cve_org_to_cve(cve_org_data: Dict[str, Any]) -> Optional[CVE]:
    """
    将 CVE.org 数据规范化为 CVE 模型
    
    Args:
        cve_org_data: CVE.org API 返回的数据
    
    Returns:
        CVE 模型对象
    """
    metadata = cve_org_data.get("cveMetadata", {})
    cve_id = metadata.get("cveId")
    
    if not cve_id:
        return None
    
    # 日期
    published_date = parse_datetime(metadata.get("datePublished"))
    last_modified = parse_datetime(metadata.get("dateUpdated"))
    
    # CNA 容器数据
    cna = cve_org_data.get("containers", {}).get("cna", {})
    
    # 描述
    descriptions = cna.get("descriptions", [])
    description = ""
    for desc in descriptions:
        if desc.get("lang") == "en":
            description = desc.get("value", "")
            break
    
    # CVSS 分数和严重程度
    cvss_score = None
    severity = Severity.UNKNOWN.value
    cvss_vector = None
    
    metrics = cna.get("metrics", [])
    for metric in metrics:
        if metric.get("format") == "CVSS":
            cvss_v31 = metric.get("cvssV3_1")
            if cvss_v31:
                cvss_score = cvss_v31.get("baseScore")
                severity = parse_severity(cvss_v31.get("baseSeverity"))
                cvss_vector = cvss_v31.get("vectorString")
                break
            
            cvss_v30 = metric.get("cvssV3_0")
            if cvss_v30:
                cvss_score = cvss_v30.get("baseScore")
                severity = parse_severity(cvss_v30.get("baseSeverity"))
                cvss_vector = cvss_v30.get("vectorString")
                break
    
    # 创建 CVE 对象
    cve = CVE(
        id=cve_id,
        description=description,
        published_date=published_date,
        last_modified=last_modified,
        severity=severity,
        cvss_score=cvss_score,
        cvss_vector=cvss_vector,
    )
    
    # 参考链接
    references = cna.get("references", [])
    for ref in references:
        ref_url = ref.get("url", "")
        tags = ref.get("tags", [])
        
        ref_type = None
        if "patch" in [t.lower() for t in tags]:
            ref_type = "PATCH"
        elif "exploit" in [t.lower() for t in tags]:
            ref_type = "EXPLOIT"
        elif "advisory" in [t.lower() for t in tags]:
            ref_type = "ADVISORY"
        
        cve.references.append(CVEReference(
            cve_id=cve_id,
            url=ref_url,
            type=ref_type,
            source="CVE.org",
        ))
    
    # 受影响产品
    affected = cna.get("affected", [])
    for product in affected:
        vendor = product.get("vendor", "")
        product_name = product.get("product", "")
        
        if "linux" in vendor.lower() or "linux" in product_name.lower():
            versions = product.get("versions", [])
            for version_info in versions:
                if version_info.get("status") == "affected":
                    affected_config = AffectedConfig(
                        cve_id=cve_id,
                        vendor=vendor,
                        product=product_name,
                        version_start=version_info.get("version"),
                        version_end=version_info.get("lessThan"),
                    )
                    cve.affected_configs.append(affected_config)
    
    return cve
