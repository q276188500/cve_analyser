"""
Kconfig 规则加载器
"""

from typing import Dict, Optional


class RuleLoader:
    """Kconfig 规则加载器"""
    
    def load_rule(self, cve_id: str) -> Optional[Dict]:
        """
        加载 CVE 的 Kconfig 规则
        
        Args:
            cve_id: CVE ID
        
        Returns:
            规则字典或 None
        """
        # 优先从数据库加载
        rule = self._load_from_database(cve_id)
        
        if not rule:
            # 从本地规则文件加载
            rule = self._load_from_file(cve_id)
        
        return rule
    
    def _load_from_database(self, cve_id: str) -> Optional[Dict]:
        """从数据库加载规则"""
        try:
            from cve_analyzer.core.database import get_db
            from cve_analyzer.core.models import KconfigRule
            
            db = get_db()
            with db.session() as session:
                rule = session.query(KconfigRule).filter_by(cve_id=cve_id).first()
                
                if rule:
                    return {
                        "cve_id": rule.cve_id,
                        "required": rule.required.get("configs", []) if rule.required else [],
                        "vulnerable_if": rule.vulnerable_if,
                        "mitigation": rule.mitigation,
                    }
        except Exception as e:
            print(f"从数据库加载规则失败: {e}")
        
        return None
    
    def _load_from_file(self, cve_id: str) -> Optional[Dict]:
        """从本地文件加载规则"""
        import json
        import os
        
        rule_file = f"data/kconfig-rules/{cve_id}.json"
        
        if not os.path.exists(rule_file):
            return None
        
        try:
            with open(rule_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"从文件加载规则失败: {e}")
            return None
    
    def save_rule(self, rule: Dict) -> bool:
        """保存规则"""
        try:
            from cve_analyzer.core.database import get_db
            from cve_analyzer.core.models import KconfigRule
            
            db = get_db()
            with db.session() as session:
                # 检查是否已存在
                existing = session.query(KconfigRule).filter_by(
                    cve_id=rule["cve_id"]
                ).first()
                
                if existing:
                    # 更新
                    existing.required = rule.get("required")
                    existing.vulnerable_if = rule.get("vulnerable_if")
                    existing.mitigation = rule.get("mitigation")
                else:
                    # 创建新规则
                    new_rule = KconfigRule(
                        cve_id=rule["cve_id"],
                        rule_version="1.0",
                        required=rule.get("required"),
                        vulnerable_if=rule.get("vulnerable_if"),
                        mitigation=rule.get("mitigation"),
                        source="manual",
                    )
                    session.add(new_rule)
                
                return True
        except Exception as e:
            print(f"保存规则失败: {e}")
            return False
