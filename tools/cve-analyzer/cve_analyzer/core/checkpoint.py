"""
断点续传管理器
用于记录和恢复抓取进度
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional


class CheckpointManager:
    """抓取断点续传管理器"""
    
    def __init__(self, checkpoint_dir: str = "./data/checkpoints"):
        """
        初始化检查点管理器
        
        Args:
            checkpoint_dir: 检查点文件存放目录
        """
        self.checkpoint_dir = Path(checkpoint_dir)
        self.checkpoint_dir.mkdir(parents=True, exist_ok=True)
    
    def _get_checkpoint_file(self, since: str, until: str) -> Path:
        """生成检查点文件路径"""
        # 使用时间段作为文件名
        filename = f"checkpoint_{since}_{until}.json"
        return self.checkpoint_dir / filename
    
    def load_checkpoint(self, since: str, until: str) -> Optional[Dict]:
        """
        加载检查点
        
        Args:
            since: 起始日期
            until: 结束日期
        
        Returns:
            检查点数据或 None
        """
        checkpoint_file = self._get_checkpoint_file(since, until)
        
        if not checkpoint_file.exists():
            return None
        
        try:
            with open(checkpoint_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None
    
    def save_checkpoint(self, since: str, until: str, data: Dict) -> None:
        """
        保存检查点
        
        Args:
            since: 起始日期
            until: 结束日期
            data: 检查点数据
        """
        checkpoint_file = self._get_checkpoint_file(since, until)
        
        # 添加更新时间
        data["updated_at"] = datetime.utcnow().isoformat()
        
        with open(checkpoint_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    
    def mark_chunk_completed(self, since: str, until: str, chunk_start: str, chunk_end: str, count: int) -> None:
        """
        标记一个时间块已完成
        
        Args:
            since: 总起始日期
            until: 总结束日期
            chunk_start: 块起始日期
            chunk_end: 块结束日期
            count: 该块抓取的 CVE 数量
        """
        checkpoint = self.load_checkpoint(since, until) or {
            "since": since,
            "until": until,
            "status": "in_progress",
            "completed_chunks": [],
            "total_cves": 0,
        }
        
        # 检查是否已存在
        chunk_info = {
            "start": chunk_start,
            "end": chunk_end,
            "count": count,
            "completed_at": datetime.utcnow().isoformat(),
        }
        
        # 避免重复添加
        exists = False
        for chunk in checkpoint["completed_chunks"]:
            if chunk["start"] == chunk_start and chunk["end"] == chunk_end:
                exists = True
                break
        
        if not exists:
            checkpoint["completed_chunks"].append(chunk_info)
            checkpoint["total_cves"] += count
        
        self.save_checkpoint(since, until, checkpoint)
    
    def is_chunk_completed(self, since: str, until: str, chunk_start: str, chunk_end: str) -> bool:
        """
        检查一个时间块是否已完成
        
        Args:
            since: 总起始日期
            until: 总结束日期
            chunk_start: 块起始日期
            chunk_end: 块结束日期
        
        Returns:
            是否已完成
        """
        checkpoint = self.load_checkpoint(since, until)
        
        if not checkpoint:
            return False
        
        for chunk in checkpoint.get("completed_chunks", []):
            if chunk["start"] == chunk_start and chunk["end"] == chunk_end:
                return True
        
        return False
    
    def mark_completed(self, since: str, until: str) -> None:
        """标记整个抓取任务完成"""
        checkpoint = self.load_checkpoint(since, until)
        
        if checkpoint:
            checkpoint["status"] = "completed"
            checkpoint["completed_at"] = datetime.utcnow().isoformat()
            self.save_checkpoint(since, until, checkpoint)
    
    def get_progress(self, since: str, until: str) -> Dict:
        """
        获取抓取进度
        
        Returns:
            进度信息字典
        """
        checkpoint = self.load_checkpoint(since, until)
        
        if not checkpoint:
            return {
                "status": "not_started",
                "completed_chunks": 0,
                "total_cves": 0,
            }
        
        return {
            "status": checkpoint.get("status", "in_progress"),
            "completed_chunks": len(checkpoint.get("completed_chunks", [])),
            "total_cves": checkpoint.get("total_cves", 0),
            "updated_at": checkpoint.get("updated_at"),
        }
    
    def clear_checkpoint(self, since: str, until: str) -> None:
        """清除检查点"""
        checkpoint_file = self._get_checkpoint_file(since, until)
        
        if checkpoint_file.exists():
            checkpoint_file.unlink()
    
    def list_checkpoints(self) -> List[Dict]:
        """列出所有检查点"""
        checkpoints = []
        
        for file in self.checkpoint_dir.glob("checkpoint_*.json"):
            try:
                with open(file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    checkpoints.append({
                        "file": file.name,
                        "since": data.get("since"),
                        "until": data.get("until"),
                        "status": data.get("status"),
                        "total_cves": data.get("total_cves", 0),
                        "updated_at": data.get("updated_at"),
                    })
            except Exception:
                continue
        
        return checkpoints
