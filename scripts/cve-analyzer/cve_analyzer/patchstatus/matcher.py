"""
内容匹配器

基于代码特征的模糊匹配
"""

import re
from typing import Dict, List, Optional

from cve_analyzer.patchstatus.base import PatchStatusEnum


class ContentMatcher:
    """代码内容匹配器"""
    
    def match(self, target_code: str, patch_features: List[str] = None,
              patch_code: str = None, remote_url: str = None) -> Dict:
        """
        匹配目标代码与补丁特征
        
        Args:
            target_code: 目标代码内容
            patch_features: 补丁关键特征列表
            patch_code: 完整补丁代码 (可选)
            remote_url: 远程补丁 URL (可选)
        
        Returns:
            {"matched": bool, "confidence": float, "status": PatchStatusEnum}
        """
        # 如果提供了远程 URL，获取补丁内容
        if remote_url and not patch_features:
            patch_code = self._fetch_remote_patch(remote_url)
            patch_features = self._extract_features(patch_code)
        
        if not patch_features:
            return {
                "matched": False,
                "confidence": 0.0,
                "status": PatchStatusEnum.UNKNOWN
            }
        
        # 计算匹配的特征数
        matched_features = []
        for feature in patch_features:
            if self._check_feature_in_code(target_code, feature):
                matched_features.append(feature)
        
        match_ratio = len(matched_features) / len(patch_features) if patch_features else 0
        
        # 确定状态和置信度
        if match_ratio >= 0.9:
            status = PatchStatusEnum.APPLIED
            confidence = 0.7 + (match_ratio - 0.9) * 3  # 0.7-1.0
        elif match_ratio >= 0.5:
            status = PatchStatusEnum.MODIFIED
            confidence = 0.5 + (match_ratio - 0.5) * 0.5  # 0.5-0.7
        elif match_ratio > 0:
            status = PatchStatusEnum.PENDING
            confidence = 0.3 + match_ratio * 0.4  # 0.3-0.7
        else:
            status = PatchStatusEnum.PENDING
            confidence = 0.5  # 完全无匹配可能是被其他方式修复
        
        return {
            "matched": match_ratio > 0.5,
            "confidence": min(confidence, 1.0),
            "status": status,
            "matched_features": matched_features,
            "total_features": len(patch_features),
            "match_ratio": match_ratio
        }
    
    def _check_feature_in_code(self, code: str, feature: str) -> bool:
        """检查特征是否存在于代码中"""
        # 精确匹配
        if feature in code:
            return True
        
        # 模糊匹配：忽略空白和注释
        normalized_code = self._normalize_code(code)
        normalized_feature = self._normalize_code(feature)
        
        return normalized_feature in normalized_code
    
    def _normalize_code(self, code: str) -> str:
        """规范化代码用于比较"""
        # 移除注释
        code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
        code = re.sub(r'//.*?$', '', code, flags=re.MULTILINE)
        # 移除多余空白
        code = re.sub(r'\s+', ' ', code)
        return code.strip()
    
    def _extract_features(self, patch_code: str) -> List[str]:
        """从补丁代码提取关键特征"""
        features = []
        
        # 提取新增的代码行
        added_lines = re.findall(r'\n\+(.+)', patch_code)
        
        # 提取关键逻辑
        for line in added_lines:
            line = line.strip()
            # 跳过纯格式修改
            if len(line) < 5:
                continue
            # 提取关键代码段
            if any(keyword in line for keyword in ['if', 'return', 'check', 'fix']):
                features.append(line)
        
        return features[:10]  # 限制特征数量
    
    def _fetch_remote_patch(self, url: str) -> Optional[str]:
        """获取远程补丁内容"""
        try:
            import requests
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            return response.text
        except Exception as e:
            print(f"获取远程补丁失败: {e}")
            return None
