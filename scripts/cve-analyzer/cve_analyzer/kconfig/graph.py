"""
Kconfig 依赖图

构建和管理配置依赖关系
"""

from typing import Dict, List, Set


class DependencyGraph:
    """Kconfig 依赖图"""
    
    def __init__(self):
        # 邻接表表示依赖关系
        self.dependencies: Dict[str, List[str]] = {}  # config -> [depends_on]
        self.reverse_deps: Dict[str, List[str]] = {}  # config -> [selected_by]
    
    def add_dependency(self, config: str, depends_on: str):
        """添加依赖关系"""
        if config not in self.dependencies:
            self.dependencies[config] = []
        
        if depends_on not in self.dependencies[config]:
            self.dependencies[config].append(depends_on)
        
        # 反向依赖
        if depends_on not in self.reverse_deps:
            self.reverse_deps[depends_on] = []
        
        if config not in self.reverse_deps[depends_on]:
            self.reverse_deps[depends_on].append(config)
    
    def get_dependencies(self, config: str, transitive: bool = True) -> List[str]:
        """
        获取配置的所有依赖
        
        Args:
            config: 配置名称
            transitive: 是否包含传递依赖
        
        Returns:
            依赖列表
        """
        if not transitive:
            return self.dependencies.get(config, [])
        
        # 广度优先搜索获取传递依赖
        result = []
        visited = set()
        queue = [config]
        
        while queue:
            current = queue.pop(0)
            
            if current in visited:
                continue
            
            visited.add(current)
            
            for dep in self.dependencies.get(current, []):
                if dep not in visited:
                    result.append(dep)
                    queue.append(dep)
        
        return result
    
    def find_path_to(self, from_config: str, to_config: str) -> List[str]:
        """
        查找从 from_config 到 to_config 的路径
        
        Returns:
            路径列表，如果不存在返回空列表
        """
        # 广度优先搜索
        queue = [[to_config]]  # 从目标反向搜索
        visited = {to_config}
        
        while queue:
            path = queue.pop(0)
            current = path[-1]
            
            if current == from_config:
                return path[::-1]  # 反转路径
            
            # 查找依赖于 current 的配置
            for dependent in self.reverse_deps.get(current, []):
                if dependent not in visited:
                    visited.add(dependent)
                    new_path = path + [dependent]
                    queue.append(new_path)
        
        return []
    
    def find_vulnerable_configs(self, enabled_configs: Set[str]) -> List[str]:
        """
        查找可能被启用的漏洞配置
        
        Args:
            enabled_configs: 已启用的配置集合
        
        Returns:
            漏洞配置列表
        """
        vulnerable = []
        
        for config in self.dependencies:
            # 检查 config 的所有依赖是否都已启用
            deps = self.get_dependencies(config)
            
            if all(dep in enabled_configs for dep in deps):
                # 所有依赖都满足，该配置可能被启用
                if config not in enabled_configs:
                    vulnerable.append(config)
        
        return vulnerable
