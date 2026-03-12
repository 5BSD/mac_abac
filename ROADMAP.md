# mac_abac Roadmap

## 0. Reduce memory consumption.
You'll run out of memory on small machines with the standard vnode cache after a day or so. This doesn't appear to be a leak but rather a memory hog.

## 1. UFS Support
Add support for UFS filesystem extended attributes to enable ABAC labeling on UFS volumes.

## 2. Rework MACF Syscalls as ioctl Device
Refactor the current MACF syscall interface to use an ioctl-based character device for improved modularity and cleaner userspace integration.

## 3. Update FreeBSD Documentation
Contribute documentation updates to the FreeBSD project covering mac_abac usage, configuration, and integration.
