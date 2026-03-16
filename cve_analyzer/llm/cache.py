"""
LLM 响应缓存

减少 API 调用成本，加速重复查询
"""

import hashlib
import json
import os
from pathlib import Path
from typing import Optional, Dict, Any
from datetime import datetime, timedelta


class LLMCache:
    """LLM 响应缓存"""
    
    def __init__(self, cache_dir: str = "./data/llm_cache", ttl_hours: int = 168):
        """
        初始化缓存
        
        Args:
            cache_dir: 缓存目录路径
            ttl_hours: 缓存过期时间（小时），默认 7 天
        """
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.ttl = timedelta(hours=ttl_hours)
    
    def _get_cache_key(self, prompt: str, model: str) -> str:
        """生成缓存键"""
        content = f"{model}:{prompt}"
        return hashlib.sha256(content.encode()).hexdigest()
    
    def _get_cache_path(self, key: str) -> Path:
        """获取缓存文件路径"""
        return self.cache_dir / f"{key}.json"
    
    def get(self, prompt: str, model: str) -> Optional[Dict[str, Any]]:
        """
        获取缓存结果
        
        Args:
            prompt: 提示词
            model: 模型名称
        
        Returns:
            缓存结果或 None（如果不存在或已过期）
        """
        key = self._get_cache_key(prompt, model)
        cache_file = self._get_cache_path(key)
        
        if not cache_file.exists():
            return None
        
        try:
            with open(cache_file) as f:
                data = json.load(f)
            
            # 检查是否过期
            cached_at = datetime.fromisoformat(data["cached_at"])
            if datetime.now() - cached_at > self.ttl:
                # 删除过期缓存
                cache_file.unlink()
                return None
            
            return data.get("response")
        except (json.JSONDecodeError, KeyError, ValueError):
            return None
    
    def set(self, prompt: str, model: str, response: Dict[str, Any]):
        """
        缓存响应
        
        Args:
            prompt: 提示词
            model: 模型名称
            response: 响应数据
        """
        key = self._get_cache_key(prompt, model)
        cache_file = self._get_cache_path(key)
        
        data = {
            "model": model,
            "prompt": prompt[:500],  # 只存提示词前500字符作为参考
            "response": response,
            "cached_at": datetime.now().isoformat(),
        }
        
        with open(cache_file, 'w') as f:
            json.dump(data, f, indent=2)
    
    def clear(self, older_than_hours: Optional[int] = None):
        """
        清除缓存
        
        Args:
            older_than_hours: 只清除指定小时数之前的缓存，None 表示全部清除
        """
        if older_than_hours is None:
            # 清除所有
            for cache_file in self.cache_dir.glob("*.json"):
                cache_file.unlink()
        else:
            # 清除指定时间之前的
            cutoff = datetime.now() - timedelta(hours=older_than_hours)
            for cache_file in self.cache_dir.glob("*.json"):
                try:
                    with open(cache_file) as f:
                        data = json.load(f)
                    cached_at = datetime.fromisoformat(data["cached_at"])
                    if cached_at < cutoff:
                        cache_file.unlink()
                except:
                    pass
    
    def get_stats(self) -> Dict[str, Any]:
        """获取缓存统计"""
        cache_files = list(self.cache_dir.glob("*.json"))
        total_size = sum(f.stat().st_size for f in cache_files)
        
        return {
            "cache_count": len(cache_files),
            "total_size_mb": round(total_size / 1024 / 1024, 2),
            "cache_dir": str(self.cache_dir),
        }
