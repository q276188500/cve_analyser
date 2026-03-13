"""
Kconfig 解析器

解析 .config 文件和 Kconfig 依赖关系
"""

import re
from typing import Dict, List, Optional


class KconfigParser:
    """Kconfig 解析器"""
    
    def parse_config_file(self, config_path: str) -> Dict[str, str]:
        """
        解析 .config 文件
        
        Args:
            config_path: .config 文件路径
        
        Returns:
            配置字典 {CONFIG_XXX: value}
        """
        config = {}
        
        try:
            with open(config_path, 'r') as f:
                content = f.read()
            return self.parse_config_text(content)
        except Exception as e:
            print(f"解析配置文件失败: {e}")
            return {}
    
    def parse_config_text(self, text: str) -> Dict[str, str]:
        """
        解析配置文本
        
        Args:
            text: 配置文本内容
        
        Returns:
            配置字典
        """
        config = {}
        
        for line in text.split('\n'):
            line = line.strip()
            
            # 跳过空行和注释
            if not line or line.startswith('#') and 'is not set' not in line:
                continue
            
            # 匹配 CONFIG_XXX=y/m/n/value
            match = re.match(r'^(#\s*)?(CONFIG_\w+)\s*=\s*(.+)$', line)
            if match:
                config_name = match.group(2)
                value = match.group(3).strip()
                config[config_name] = value
            
            # 匹配 # CONFIG_XXX is not set
            not_set_match = re.match(r'^#\s*(CONFIG_\w+)\s+is not set$', line)
            if not_set_match:
                config_name = not_set_match.group(1)
                config[config_name] = 'n'
        
        return config
    
    def parse_kconfig_dependencies(self, kconfig_text: str) -> Dict:
        """
        解析 Kconfig 依赖关系
        
        Args:
            kconfig_text: Kconfig 文件内容
        
        Returns:
            依赖信息字典
        """
        result = {
            "config": "",
            "depends_on": [],
            "selects": [],
            "implied_by": [],
            "description": "",
        }
        
        # 提取 config 名称
        config_match = re.search(r'config\s+(\w+)', kconfig_text)
        if config_match:
            result["config"] = config_match.group(1)
        
        # 提取 depends on
        depends_match = re.search(r'depends on\s+(.+)', kconfig_text, re.MULTILINE)
        if depends_match:
            deps = depends_match.group(1)
            # 解析依赖列表
            result["depends_on"] = self._parse_depends(deps)
        
        # 提取 select
        select_matches = re.findall(r'select\s+(\w+)', kconfig_text)
        result["selects"] = select_matches
        
        # 提取 help 描述
        help_match = re.search(r'help\s*\n(.*?)(?=\nconfig|\n[A-Z]|\Z)', 
                               kconfig_text, re.DOTALL)
        if help_match:
            result["description"] = help_match.group(1).strip()
        
        return result
    
    def _parse_depends(self, depends_str: str) -> List[str]:
        """解析依赖字符串"""
        # 简化解析，提取所有 CONFIG_ 或 bare word
        deps = re.findall(r'(CONFIG_\w+|\w+)', depends_str)
        return [d for d in deps if d not in ['&&', '||', '!']]
