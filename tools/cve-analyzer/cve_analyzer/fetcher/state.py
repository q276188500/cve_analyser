"""
抓取状态管理模块
支持断点续传
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any


class FetchState:
    """抓取状态管理"""
    
    def __init__(self, state_file: str = ".fetch_state.json"):
        self.state_file = Path(state_file)
        self.state = self._load()
    
    def _load(self) -> Dict[str, Any]:
        """加载状态文件"""
        if self.state_file.exists():
            try:
                with open(self.state_file, "r") as f:
                    return json.load(f)
            except Exception:
                pass
        return {}
    
    def save(self):
        """保存状态"""
        with open(self.state_file, "w") as f:
            json.dump(self.state, f, indent=2, default=str)
    
    def get_last_fetch(self, source: str = "nvd") -> Optional[datetime]:
        """获取上次抓取时间"""
        last_fetch = self.state.get("last_fetch", {}).get(source)
        if last_fetch:
            try:
                return datetime.fromisoformat(last_fetch)
            except Exception:
                pass
        return None
    
    def set_last_fetch(self, source: str, fetch_time: datetime):
        """设置上次抓取时间"""
        if "last_fetch" not in self.state:
            self.state["last_fetch"] = {}
        self.state["last_fetch"][source] = fetch_time.isoformat()
        self.save()
    
    def get_fetched_cve_ids(self) -> set:
        """获取已抓取的 CVE ID 集合"""
        return set(self.state.get("fetched_cve_ids", []))
    
    def add_fetched_cve_id(self, cve_id: str):
        """添加已抓取的 CVE ID"""
        if "fetched_cve_ids" not in self.state:
            self.state["fetched_cve_ids"] = []
        if cve_id not in self.state["fetched_cve_ids"]:
            self.state["fetched_cve_ids"].append(cve_id)
    
    def save_fetched_cve_ids(self):
        """保存已抓取列表"""
        self.save()
    
    def get_chunk_progress(self, chunk_key: str) -> Optional[Dict]:
        """获取块进度"""
        return self.state.get("chunks", {}).get(chunk_key)
    
    def set_chunk_progress(self, chunk_key: str, progress: Dict):
        """设置块进度"""
        if "chunks" not in self.state:
            self.state["chunks"] = {}
        self.state["chunks"][chunk_key] = progress
        self.save()
    
    def clear(self):
        """清除状态"""
        self.state = {}
        if self.state_file.exists():
            self.state_file.unlink()
