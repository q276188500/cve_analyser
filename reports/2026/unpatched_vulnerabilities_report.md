# 2026年未修补漏洞梳理报告

**生成时间**: 2026-03-16  
**数据范围**: 2026-01-01 ~ 2026-03-31  
**CVE 总数**: 487

---

## 📊 总体概况

| 状态 | 数量 | 占比 |
|------|------|------|
| **有补丁** | 0 | 0.0% |
| **无补丁/待分析** | **487** | **100.0%** |

> ⚠️ **说明**: 当前系统仅完成 CVE 元数据采集，补丁分析功能尚未运行。以下列出的是需要进一步分析的漏洞。

---

## 🔴 高危未修补漏洞 (18个)

| CVE ID | 严重程度 | CVSS | 描述 |
|--------|----------|------|------|
| CVE-2025-68817 | 🟠 High | 7.8 | ksmbd: fix use-after-free in ksmbd_smb2_session_create |
| CVE-2025-71089 | 🟠 High | 7.8 | iommu: disable SVA when CONFIG_AMD_IOMMU is not enabled |
| CVE-2025-71145 | 🟠 High | 7.8 | usb: phy: isp1301: fix non-OF devtree handling |
| CVE-2025-71152 | 🟠 High | 7.8 | net: dsa: properly keep track of port mrouter state |
| CVE-2025-71155 | 🟠 High | 7.8 | KVM: s390: Fix gmap_helper_zap_one() address computation |
| CVE-2025-71156 | 🟠 High | 7.8 | gve: defer interrupt enabling until after napi enable |
| CVE-2025-71157 | 🟠 High | 7.8 | RDMA/core: always drop device refcount on error path |
| CVE-2025-71159 | 🟠 High | 7.8 | btrfs: fix use-after-free warning during reloc stage |
| CVE-2026-22980 | 🟠 High | 7.8 | nfsd: provide locking for v4_enabled operations |
| CVE-2026-22984 | 🟠 High | 7.1 | libceph: prevent potential out-of-bounds access |
| CVE-2026-22995 | 🟠 High | 7.8 | ublk: fix use-after-free in ublk_ch_ev_timer() |
| CVE-2025-71162 | 🟠 High | 7.8 | dmaengine: tegra-adma: Fix use-after-free in tegra_adma_... |
| CVE-2025-33219 | 🟠 High | 7.8 | NVIDIA Display Driver - 本地权限提升 |
| CVE-2026-23068 | 🟠 High | 7.8 | spi: spi-sprd-adi: Fix double free in sprd_adi_remove |
| CVE-2026-23226 | 🟠 High | 7.8 | ksmbd: add chann_lock to protect sess table |
| CVE-2025-1272 | 🟠 High | 7.7 | Fedora Linux kernel lockdown mode - 本地权限提升 |
| CVE-2026-2664 | 🟠 High | 7.8 | Docker Desktop grpcfuse - 本地权限提升 |
| CVE-2026-25702 | 🟠 High | 7.3 | SUSE Linux Enterprise Server - 访问控制绕过 |

---

## 🟡 中危未修补漏洞 (44个)

### 网络相关
- CVE-2025-68823 [5.5] - ublk: fix deadlock when reading config
- CVE-2025-71144 [5.5] - mptcp: ensure context reset on disconnect
- CVE-2026-22976 [5.5] - net/sched: sch_qfq: Fix NULL dereference
- CVE-2026-22977 [5.5] - net: sock: fix hardened usercopy
- CVE-2026-22978 [3.3] - wifi: avoid kernel-infoleak from SIOCGESSID
- CVE-2026-22979 [5.5] - net: fix memory leak in skb_segment
- CVE-2026-22981 [5.5] - idpf: detach and close netdevs properly
- CVE-2026-22982 [5.5] - net: mscc: ocelot: Fix crash when handling...
- CVE-2026-22983 [5.5] - net: do not write to msg_get_inq if non-block
- CVE-2026-22985 [5.5] - idpf: Fix RSS LUT NULL pointer dereference
- CVE-2026-22986 [4.7] - gpiolib: fix race condition for gpio
- CVE-2026-22987 [5.5] - net/sched: act_api: avoid dereferencing...
- CVE-2026-22988 [5.5] - arp: do not assume dev_hard_header length
- CVE-2026-22989 [5.5] - nfsd: check that server is running before...
- CVE-2026-22990 [5.5] - libceph: replace overzealous BUG() with...
- CVE-2026-22991 [5.5] - libceph: make free_choose_arg_mapping...
- CVE-2026-22992 [5.5] - libceph: return the handler error if any
- CVE-2026-22993 [5.5] - idpf: Fix RSS LUT NULL ptr issues
- CVE-2026-22994 [5.5] - bpf: Fix reference count leak in bpf_link_new
- CVE-2026-23060 [5.5] - crypto: authencesn - reject too large...
- CVE-2026-23061 [5.5] - can: kvaser_usb: kvaser_usb_read_bulk
- CVE-2026-23064 [5.5] - net/sched: act_ife: avoid possible null...
- CVE-2026-23066 [5.5] - rxrpc: Fix recvmsg() unconditional...
- CVE-2026-23069 [5.5] - vsock/virtio: fix potential underflow
- CVE-2026-23096 [5.5] - nvme-tcp: fix NULL pointer dereference

### 文件系统相关
- CVE-2025-68753 [5.5] - ALSA: firewire-motu: add bounds check
- CVE-2025-68767 [5.5] - hfsplus: Verify inode mode when reading...
- CVE-2025-68822 [5.5] - Input: alps - fix use-after-free in alps...
- CVE-2025-71065 [5.5] - f2fs: fix to avoid potential deadlock
- CVE-2025-71071 [5.5] - iommu/mediatek: fix use-after-free in...
- CVE-2025-71146 [5.5] - netfilter: nf_conncount: fix leak of...
- CVE-2025-71160 [5.5] - netfilter: nf_tables: avoid chain rule...

### 驱动相关
- CVE-2025-68782 [5.5] - scsi: target: Reset t_task_cdb in...
- CVE-2025-71076 [5.5] - drm/xe/oa: Limit num_syncs to prevent...
- CVE-2025-71094 [5.5] - net: usb: asix: validate PHY address
- CVE-2025-71113 [5.5] - crypto: af_alg - zero initialize key...
- CVE-2025-71137 [5.5] - octeontx2-pf: fix UBSAN: shift exponent...
- CVE-2026-22996 [5.5] - net/mlx5e: Don't store mlx5e_profile pointer
- CVE-2026-22997 [5.5] - net: can: j1939: j1939_xtp_rx_rtr_session
- CVE-2026-22999 [5.5] - net/sched: sch_qfq: do not free internal...
- CVE-2026-23000 [5.5] - net/mlx5e: Fix crash on profile change

### 其他
- CVE-2025-71147 [5.5] - KEYS: trusted: Fix a memory leak in...
- CVE-2025-71148 [3.3] - net/handshake: restore destructor before...
- CVE-2025-71149 [5.5] - io_uring/poll: correctly handle multishot...
- CVE-2025-71150 [5.5] - ksmbd: Fix refcount leak when inode is...
- CVE-2025-71151 [5.5] - cifs: Fix memory and information leak
- CVE-2025-71153 [5.5] - ksmbd: Fix memory leak in get_file_stream_info
- CVE-2025-71154 [5.5] - net: usb: rtl8150: fix memory leak in...
- CVE-2025-71158 [5.5] - gpio: mpsse: ensure worker is trashed before...
- CVE-2026-23062 [5.5] - platform/x86: hp-bioscfg: Fix kernel-infoleak
- CVE-2026-23063 [5.5] - uacce: ensure safe queue release

---

## 🟢 低危未修补漏洞 (2个)

- CVE-2025-71148 [3.3] - net/handshake: restore destructor before release
- CVE-2026-22978 [3.3] - wifi: avoid kernel-infoleak from SIOCGESSID

---

## ⚪ 未分级漏洞 (423个)

大量 Linux kernel 内部修复的通用漏洞，大部分描述为:
> "In the Linux kernel, the following vulnerability has been resolved: ..."

**主要涉及子系统**:
- 网络协议栈 (net/, netfilter/, drivers/net/)
- 文件系统 (fs/, btrfs, f2fs, ext4)
- 设备驱动 (drivers/usb/, drivers/gpu/, drivers/dma/)
- 内存管理 (mm/)
- 虚拟化 (KVM, virtio)
- 安全模块 (crypto/, security/)

---

## 🎯 优先级建议

### 🔴 立即处理 (P0)
1. **NVIDIA 驱动** - CVE-2025-33219 (影响大量用户)
2. **ksmbd 服务器** - CVE-2025-68817, CVE-2026-22995, CVE-2026-23226
3. **KVM 虚拟化** - CVE-2025-71155, CVE-2025-1272

### 🟠 尽快处理 (P1)
1. **网络协议栈** - CVE-2025-71089, CVE-2025-71152
2. **文件系统** - CVE-2025-71159 (btrfs)
3. **RDMA/网络** - CVE-2025-71157

### 🟡 计划处理 (P2)
所有中危漏洞，特别是 netfilter 和驱动相关

---

## 📝 说明

1. **数据来源**: NVD (National Vulnerability Database)
2. **采集时间**: 2026-03-16
3. **补丁状态**: 当前系统尚未运行补丁关联分析，需手动或通过 Phase 3+ 分析器关联 Git commit
4. **下一步**: 运行 `cve-analyzer analyze <CVE-ID>` 进行补丁分析

---

**报告生成**: CVE Analyzer v0.4.0  
**作者**: 小葱明 🌱
