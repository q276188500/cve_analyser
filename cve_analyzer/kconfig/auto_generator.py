"""
Kconfig 规则自动生成器

严格模式：只推断明确的配置项，不确定的不写

功能：
1. 基于 CVE 描述生成规则
2. 基于补丁 commit 的文件变更推断规则
3. 规则持久化到数据库
"""

import re
import subprocess
from typing import List, Dict, Optional, Tuple


# 明确的 Kconfig 关键词映射
# 只有描述中明确提到这些关键词才推断
EXPLICIT_KCONFIG_MAP = {
    # 文件系统
    "ext4": "CONFIG_EXT4_FS",
    "xfs": "CONFIG_XFS_FS",
    "btrfs": "CONFIG_BTRFS_FS",
    "nfs": "CONFIG_NFS_FS",
    "cifs": "CONFIG_CIFS",
    "smb": "CONFIG_SMB_SERVER",
    "ksmbd": "CONFIG_KSMBD",
    "vfat": "CONFIG_VFAT_FS",
    "ntfs": "CONFIG_NTFS_FS",
    "f2fs": "CONFIG_F2FS_FS",
    
    # 网络
    "tcp": "CONFIG_TCP",
    "udp": "CONFIG_UDP",
    "ipv4": "CONFIG_IP_VS",
    "ipv6": "CONFIG_IPV6",
    "wifi": "CONFIG_WIRELESS",
    "wireless": "CONFIG_WIRELESS",
    "bridge": "CONFIG_BRIDGE",
    "vlan": "CONFIG_VLAN_8021Q",
    "bonding": "CONFIG_BONDING",
    
    # 虚拟化
    "kvm": "CONFIG_KVM",
    "virtio": "CONFIG_VIRTIO",
    "xen": "CONFIG_XEN",
    "docker": "CONFIG_CONTAINERD",
    "container": "CONFIG_CONTAINERS",
    
    # 安全
    "selinux": "CONFIG_SECURITY_SELINUX",
    "apparmor": "CONFIG_SECURITY_APPARMOR",
    "capability": "CONFIG_SECURITY_CAPABILITIES",
    
    # 驱动
    "usb": "CONFIG_USB",
    "pci": "CONFIG_PCI",
    "nvme": "CONFIG_NVME_CORE",
    "gpu": "CONFIG_DRM",
    "amd gpu": "CONFIG_DRM_AMDGPU",
    "nvidia": "CONFIG_DRM_NOUVEAU",
    "intel gpu": "CONFIG_DRM_I915",
    
    # 蓝牙
    "bluetooth": "CONFIG_BT",
    
    # 声音
    "alsa": "CONFIG_SND",
    "sound": "CONFIG_SOUND",
}

# 文件路径到 Kconfig 的映射 (需要从内核源码获取，这里先放常用的)
# 格式: 文件路径前缀 -> 需要开启的配置
FILE_TO_KCONFIG = {
    "fs/ext4": "CONFIG_EXT4_FS",
    "fs/xfs": "CONFIG_XFS_FS", 
    "fs/btrfs": "CONFIG_BTRFS_FS",
    "fs/nfs": "CONFIG_NFS_FS",
    "fs/cifs": "CONFIG_CIFS",
    "fs/smb": "CONFIG_CIFS",
    "net/ipv4": "CONFIG_INET",
    "net/ipv6": "CONFIG_IPV6",
    "net/core": "CONFIG_NET",
    "net/sctp": "CONFIG_SCTP",
    "drivers/virtio": "CONFIG_VIRTIO",
    "drivers/vfio": "CONFIG_VFIO",
    "drivers/xen": "CONFIG_XEN",
    "drivers/usb": "CONFIG_USB",
    "drivers/pci": "CONFIG_PCI",
    "drivers/nvme": "CONFIG_NVME_CORE",
    "drivers/gpu/drm": "CONFIG_DRM",
    "drivers/bluetooth": "CONFIG_BT",
    "sound/core": "CONFIG_SND",
    "security/selinux": "CONFIG_SECURITY_SELINUX",
    "security/apparmor": "CONFIG_SECURITY_APPARMOR",
}


def extract_explicit_configs(description: str) -> List[str]:
    """
    从描述中提取明确提到的配置项
    
    严格模式：只提取明确提到的
    """
    if not description:
        return []
    
    description = description.lower()
    found_configs = set()
    
    # 查找明确的 CONFIG_XXX 格式
    config_pattern = re.compile(r'config_([a-zA-Z0-9_]+)', re.IGNORECASE)
    for match in config_pattern.finditer(description):
        config_name = match.group(0).upper()
        found_configs.add(config_name)
    
    # 查找明确的关键字映射
    for keyword, config in EXPLICIT_KCONFIG_MAP.items():
        if keyword in description:
            # 只有明确提到功能名称时才添加
            # 例如 "ksmbd" 明确提到才添加 CONFIG_KSMBD
            pattern = r'\b' + re.escape(keyword) + r'\b'
            if re.search(pattern, description):
                found_configs.add(config)
    
    return list(found_configs)


def infer_from_patch_files(patch_urls: List[str]) -> List[str]:
    """
    从补丁引用的文件路径推断配置项
    
    需要从 git.kernel.org URL 中提取路径
    """
    inferred = set()
    
    for url in patch_urls:
        # 从 URL 中提取 commit 信息
        # 格式: https://git.kernel.org/stable/c/abc123...
        
        # 简单处理：如果 URL 包含特定路径关键字
        for prefix, config in FILE_TO_KCONFIG.items():
            if prefix in url.lower():
                inferred.add(config)
    
    return list(inferred)


def generate_rule(cve_id: str, description: str, patch_urls: List[str] = None) -> Optional[Dict]:
    """
    生成 Kconfig 规则
    
    严格模式：只有明确信息才生成规则
    """
    patch_urls = patch_urls or []
    
    # 方法1: 从描述中提取
    explicit_configs = extract_explicit_configs(description)
    
    # 方法2: 从补丁 URL 推断
    inferred_configs = infer_from_patch_files(patch_urls)
    
    # 合并结果
    all_configs = set(explicit_configs) | set(inferred_configs)
    
    if not all_configs:
        # 没有明确信息，不生成规则
        return None
    
    # 生成规则
    rule = {
        "cve_id": cve_id,
        "required": {"configs": list(all_configs)},
        "vulnerable_if": f"以下配置开启: {', '.join(all_configs)}",
        "mitigation": f"如不需要，可禁用: {', '.join(all_configs)}",
        "source": "auto",
        "confidence": "high" if explicit_configs else "medium",
    }
    
    return rule


def infer_from_patch_commit(commit_hash: str, kernel_path: str) -> List[str]:
    """
    从补丁 commit 的文件变更推断 Kconfig
    
    从 git show 获取修改的文件，然后推断需要的配置
    """
    configs = set()
    
    try:
        result = subprocess.run(
            ["git", "show", "--stat", "--format=", commit_hash],
            cwd=kernel_path,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode != 0:
            return []
        
        # 解析修改的文件
        files = []
        for line in result.stdout.strip().split('\n'):
            if '/' in line:
                # 获取目录前缀
                path = line.split('/')[0]
                files.append(path)
        
        # 从文件路径推断配置
        for file_path in files:
            if file_path in FILE_TO_KCONFIG:
                configs.add(FILE_TO_KCONFIG[file_path])
    
    except Exception:
        pass
    
    return list(configs)


def generate_rule_from_commit(
    cve_id: str, 
    description: str, 
    patches: List[Dict], 
    kernel_path: str = None
) -> Tuple[Optional[Dict], List[str]]:
    """
    基于补丁 commit 生成 Kconfig 规则
    
    返回: (规则, 日志信息)
    """
    logs = []
    
    # 方法1: 从描述中提取
    explicit_configs = extract_explicit_configs(description)
    if explicit_configs:
        logs.append(f"从描述提取: {explicit_configs}")
    
    # 方法2: 从补丁 commit 文件推断
    commit_configs = []
    if kernel_path:
        for patch in patches[:3]:  # 最多查3个
            commit = patch.get('commit', '')
            if commit:
                configs = infer_from_patch_commit(commit, kernel_path)
                if configs:
                    commit_configs.extend(configs)
                    logs.append(f"从 commit {commit[:12]} 推断: {configs}")
    
    # 合并
    all_configs = set(explicit_configs) | set(commit_configs)
    
    if not all_configs:
        return None, logs
    
    # 生成规则
    rule = {
        "cve_id": cve_id,
        "required": {"configs": list(all_configs)},
        "vulnerable_if": f"以下配置开启: {', '.join(all_configs)}",
        "mitigation": f"如不需要，可禁用: {', '.join(all_configs)}",
        "source": "auto",
        "confidence": "high" if explicit_configs else "medium",
    }
    
    return rule, logs


def save_rule_to_db(rule: Dict) -> bool:
    """保存规则到数据库"""
    try:
        from cve_analyzer.core.database import get_db
        from cve_analyzer.core.models import KconfigRule
        
        db = get_db()
        with db.session() as session:
            # 检查是否已存在
            existing = session.query(KconfigRule).filter_by(cve_id=rule['cve_id']).first()
            
            if existing:
                # 更新
                existing.required = rule.get('required')
                existing.vulnerable_if = rule.get('vulnerable_if')
                existing.mitigation = rule.get('mitigation')
                existing.source = rule.get('source', 'auto')
                logs.append(f"更新已存在的规则")
            else:
                # 创建
                new_rule = KconfigRule(
                    cve_id=rule['cve_id'],
                    rule_version="1.0",
                    required=rule.get('required'),
                    vulnerable_if=rule.get('vulnerable_if'),
                    mitigation=rule.get('mitigation'),
                    source=rule.get('source', 'auto'),
                )
                session.add(new_rule)
                logs.append(f"创建新规则")
        
        return True
    except Exception as e:
        logs.append(f"保存失败: {e}")
        return False


# 测试
if __name__ == "__main__":
    test_desc = """
    In the Linux kernel, the following vulnerability has been resolved:
    ksmbd: fix use-after-free in ksmbd_tree_connect_put under concurrency
    """
    
    result = generate_rule("CVE-2025-68817", test_desc, [])
    print(f"生成的规则: {result}")
