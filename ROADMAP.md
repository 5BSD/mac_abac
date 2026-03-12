# mac_abac Roadmap

## 0. Reduce memory consumption - DONE
Reduced per-label memory from ~9.2KB to ~5.1KB (44% reduction) by:
- Removed redundant `vl_raw` field from `struct abac_label` (saved 4KB per label)
- Removed dead `struct abac_pattern` and related functions
- Labels now reconstruct raw strings on-demand via `abac_label_to_string()`

## 1. UFS Support - DONE
UFS filesystem extended attributes now work for ABAC labeling. Mount with `multilabel` option enabled.

## 2. ZFS Support
ZFS crashes in `vn_extattr_get` during `mac_vnode_associate_singlelabel` because vnodes aren't ready for VOP operations during `zfs_znode_alloc`. Need to investigate:
- Lazy label loading on first access check
- Alternative MAC hooks that fire later in vnode lifecycle
- ZFS-specific workarounds

## 3. Use Standard Labeling Tools (setfmac/getfmac)
Currently using custom syscalls (`ABAC_SYS_SETLABEL`, `ABAC_SYS_REFRESH`). Investigate replacing with standard FreeBSD mechanisms:
- Test if direct `setextattr`/`getextattr` works on UFS (vnode cache behavior)
- Implement `mpo_vnode_externalize_label` / `mpo_vnode_internalize_label` hooks
- Enable standard `setfmac`/`getfmac` tools
- Remove or deprecate custom syscalls if not needed

## 4. Rework MACF Syscalls as ioctl Device
Refactor the current MACF syscall interface to use an ioctl-based character device for improved modularity and cleaner userspace integration.

## 5. Update FreeBSD Documentation
Contribute documentation updates to the FreeBSD project covering mac_abac usage, configuration, and integration.
