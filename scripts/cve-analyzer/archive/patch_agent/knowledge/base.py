# Knowledge Base - 知识库检索

import os
import fnmatch
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
import yaml


@dataclass
class KnowledgeRule:
    """知识规则"""
    id: str
    type: str  # constraint, context, reference
    title: str
    description: str
    severity: str  # critical, high, medium, low
    domain: str
    tags: List[str] = field(default_factory=list)
    affected_paths: List[str] = field(default_factory=list)
    requires_approval: bool = False
    approval_role: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)


class KnowledgeBase:
    """知识库"""
    
    def __init__(self, rules_dir: str = None):
        if rules_dir is None:
            # 默认路径
            base_dir = Path(__file__).parent.parent / "knowledge" / "rules"
            rules_dir = str(base_dir)
        
        self.rules_dir = Path(rules_dir)
        self.rules: List[KnowledgeRule] = []
        self._load_rules()
    
    def _load_rules(self):
        """加载所有规则"""
        if not self.rules_dir.exists():
            return
        
        for yaml_file in self.rules_dir.glob("*.yaml"):
            try:
                with open(yaml_file, 'r') as f:
                    data = yaml.safe_load(f)
                    if data:
                        rule = KnowledgeRule(
                            id=data.get('id', yaml_file.stem),
                            type=data.get('type', 'context'),
                            title=data.get('title', ''),
                            description=data.get('description', ''),
                            severity=data.get('severity', 'medium'),
                            domain=data.get('domain', 'general'),
                            tags=data.get('tags', []),
                            affected_paths=data.get('affected_paths', []),
                            requires_approval=data.get('requires_approval', False),
                            approval_role=data.get('approval_role'),
                            extra=data
                        )
                        self.rules.append(rule)
            except Exception as e:
                print(f"Warning: Failed to load {yaml_file}: {e}")
    
    def search_by_path(self, file_path: str) -> List[KnowledgeRule]:
        """根据文件路径搜索相关规则"""
        matches = []
        
        for rule in self.rules:
            for pattern in rule.affected_paths:
                # 支持通配符匹配
                if fnmatch.fnmatch(file_path, pattern):
                    matches.append(rule)
                    break
                # 也支持目录前缀匹配
                if file_path.startswith(pattern.replace('*', '')):
                    matches.append(rule)
                    break
        
        return matches
    
    def search_by_keywords(self, keywords: List[str]) -> List[KnowledgeRule]:
        """根据关键词搜索规则"""
        matches = []
        
        for rule in self.rules:
            # 在标题、描述、标签中搜索
            text = ' '.join([
                rule.title,
                rule.description,
                ' '.join(rule.tags)
            ]).lower()
            
            for kw in keywords:
                if kw.lower() in text:
                    matches.append(rule)
                    break
        
        return matches
    
    def get_critical_rules(self) -> List[KnowledgeRule]:
        """获取所有 critical 级别的规则"""
        return [r for r in self.rules if r.severity == 'critical']
    
    def get_all_rules(self) -> List[KnowledgeRule]:
        """获取所有规则"""
        return self.rules
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典 (用于 JSON 输出)"""
        return {
            "total_rules": len(self.rules),
            "rules": [
                {
                    "id": r.id,
                    "type": r.type,
                    "title": r.title,
                    "severity": r.severity,
                    "domain": r.domain,
                    "tags": r.tags,
                    "affected_paths": r.affected_paths
                }
                for r in self.rules
            ]
        }


# 全局实例
_knowledge_base: Optional[KnowledgeBase] = None


def get_knowledge_base(rules_dir: str = None) -> KnowledgeBase:
    """获取知识库实例"""
    global _knowledge_base
    if _knowledge_base is None:
        _knowledge_base = KnowledgeBase(rules_dir)
    return _knowledge_base
