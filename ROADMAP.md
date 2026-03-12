# mac_abac Roadmap

## 0. Reduce memory consumption - DONE
Reduced per-label memory from ~9.2KB to ~5.1KB (44% reduction) by:
- Removed redundant `vl_raw` field from `struct abac_label` (saved 4KB per label)
- Removed dead `struct abac_pattern` and related functions
- Labels now reconstruct raw strings on-demand via `abac_label_to_string()`

## 1. UFS Support - DONE
UFS filesystem extended attributes now work for ABAC labeling. Mount with `multilabel` option enabled.

## 2. Rework MACF Syscalls as ioctl Device
Refactor the current MACF syscall interface to use an ioctl-based character device for improved modularity and cleaner userspace integration.

## 3. Update FreeBSD Documentation
Contribute documentation updates to the FreeBSD project covering mac_abac usage, configuration, and integration.
