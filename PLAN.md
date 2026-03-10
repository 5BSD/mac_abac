# vLabel MACF Hook Implementation Plan

## Object Classification

### Tier 1: Disk-Backed (Can Label via Extattr)

| Object | Filesystem? | Label Source | Priority |
|--------|-------------|--------------|----------|
| **Regular files** | Yes | `system:vlabel` extattr | HIGH |
| **Directories** | Yes | `system:vlabel` extattr | HIGH |
| **UNIX domain sockets** | Yes - socket file | extattr on socket file | HIGH |
| **Named pipes (FIFOs)** | Yes - special file | extattr on FIFO | HIGH |
| **Device nodes** | Yes - `/dev/*` | devfs rules or extattr | MEDIUM |
| **Symlinks** | Yes | extattr (if supported) | LOW |

### Tier 2: Named Kernel Objects (Filesystem-Backed Identity)

| Object | Namespace | Label Source | Priority |
|--------|-----------|--------------|----------|
| **POSIX shm** | `/dev/shm/name` | Inherit from creator, or explicit | HIGH |
| **POSIX semaphores** | Named in kernel | Inherit from creator | MEDIUM |
| **SysV shm** | Key-based IPC | Inherit from creator | LOW |
| **SysV semaphores** | Key-based IPC | Inherit from creator | LOW |
| **SysV message queues** | Key-based IPC | Inherit from creator | LOW |

### Tier 3: Process-Inherited (In-Memory, Inherit Creator Label)

| Object | Created By | Label Source | Priority |
|--------|------------|--------------|----------|
| **Anonymous pipes** | pipe() | Creator process label | MEDIUM |
| **Socket pairs** | socketpair() | Creator process label | MEDIUM |
| **Network sockets** | socket() | Creator process label | MEDIUM |
| **Mbufs (packets)** | Network stack | Socket/interface label | LOW |

### Tier 4: System/Privileged Objects

| Object | What | Label Source | Priority |
|--------|------|--------------|----------|
| **Network interfaces** | ifnet | Static config or inherit | LOW |
| **Mounts** | Filesystem mounts | Mount-time config | LOW |
| **BPF descriptors** | Packet capture | Creator process label | LOW |
| **Kernel modules** | kld | Vnode label of .ko file | MEDIUM |

---

## FreeBSD-Specific Objects

### devfs - Device Filesystem

Devices in `/dev` can be labeled. devfs has its own labeling mechanism:

| Hook | Purpose |
|------|---------|
| `mpo_devfs_create_device` | Label new device node |
| `mpo_devfs_create_directory` | Label devfs directory |
| `mpo_devfs_create_symlink` | Label devfs symlink |
| `mpo_devfs_vnode_associate` | Associate vnode with devfs label |

**Use case:** Label `/dev/mem`, `/dev/kmem` as `type=dangerous` and deny access.

### kld - Kernel Module Loading

| Hook | Purpose |
|------|---------|
| `mpo_kld_check_load` | Check if module can be loaded |
| `mpo_kld_check_stat` | Check if module info visible |

**Use case:** Only load modules labeled `type=trusted,domain=kernel`.

### kenv - Kernel Environment

| Hook | Purpose |
|------|---------|
| `mpo_kenv_check_get` | Read kernel env var |
| `mpo_kenv_check_set` | Write kernel env var |
| `mpo_kenv_check_unset` | Delete kernel env var |
| `mpo_kenv_check_dump` | Dump all kenv |

**Use case:** Protect boot variables from modification.

### System Operations

| Hook | Purpose |
|------|---------|
| `mpo_system_check_reboot` | Control who can reboot |
| `mpo_system_check_swapon` | Control swap file access |
| `mpo_system_check_sysctl` | Control sysctl access |
| `mpo_system_check_acct` | Control process accounting |
| `mpo_system_check_audit*` | Control audit system |

### Privilege Grants

| Hook | Purpose |
|------|---------|
| `mpo_priv_check` | Veto privilege checks |
| `mpo_priv_grant` | Grant additional privileges |

**Use case:** `type=trusted` processes get extra privileges.

### DDB - Kernel Debugger

| Hook | Purpose |
|------|---------|
| `mpo_ddb_command_register` | Register DDB commands |
| `mpo_ddb_command_exec` | Execute DDB commands |
| `mpo_kdb_check_backend` | Check debugger backend |

---

## Implementation Phases

### Phase 1: Core File Operations (HIGH)

Already have: `exec`
Need to implement:

```c
/* Vnode operations */
mpo_vnode_check_read       → VLABEL_OP_READ
mpo_vnode_check_write      → VLABEL_OP_WRITE
mpo_vnode_check_open       → VLABEL_OP_OPEN
mpo_vnode_check_mmap       → VLABEL_OP_MMAP
mpo_vnode_check_mprotect   → VLABEL_OP_MMAP
```

### Phase 2: Protect Labels (HIGH)

Two distinct protections:

**2a. Protect vLabel's Own Labels (`system:vlabel`)**
- Sysctl: `security.mac.vlabel.protect_labels=1`
- When enabled, only authorized processes can modify `system:vlabel` extattr
- Authorization: root OR processes matching a relabel rule

**2b. Protect All Labels (Optional)**
- Sysctl: `security.mac.vlabel.protect_system_extattr=0`
- When enabled, apply vLabel rules to ALL `system:*` extattr modifications
- Allows vLabel to protect other MAC policies' labels too

```c
/* Extattr protection */
mpo_vnode_check_setextattr     → Deny modify system:vlabel unless authorized
                                  Optionally deny modify any system:* extattr
mpo_vnode_check_deleteextattr  → Deny delete system:vlabel
                                  Optionally deny delete any system:* extattr
mpo_vnode_check_getextattr     → VLABEL_OP_GETEXTATTR (optional visibility control)
mpo_vnode_check_listextattr    → VLABEL_OP_GETEXTATTR (optional visibility control)
```

### Phase 3: Directory Operations (MEDIUM)

```c
mpo_vnode_check_lookup     → VLABEL_OP_LOOKUP
mpo_vnode_check_readdir    → VLABEL_OP_READDIR
mpo_vnode_check_create     → VLABEL_OP_CREATE
mpo_vnode_check_unlink     → VLABEL_OP_UNLINK
mpo_vnode_check_link       → VLABEL_OP_LINK
mpo_vnode_check_rename_*   → VLABEL_OP_RENAME
mpo_vnode_check_chdir      → VLABEL_OP_CHDIR
mpo_vnode_check_chroot     → VLABEL_OP_CHDIR
```

### Phase 4: File Metadata (MEDIUM)

```c
mpo_vnode_check_stat       → VLABEL_OP_STAT
mpo_vnode_check_setmode    → VLABEL_OP_SETATTR
mpo_vnode_check_setowner   → VLABEL_OP_SETATTR
mpo_vnode_check_setflags   → VLABEL_OP_SETATTR
mpo_vnode_check_setutimes  → VLABEL_OP_SETATTR
mpo_vnode_check_setacl     → VLABEL_OP_SETATTR
mpo_vnode_check_deleteacl  → VLABEL_OP_SETATTR
mpo_vnode_check_getacl     → VLABEL_OP_STAT
```

### Phase 5: Sockets (HIGH - UNIX domain labelable)

**Two labels for UNIX domain sockets:**
1. **Socket file label** - the vnode at `/var/run/foo.sock` (extattr, on disk)
2. **Socket object label** - `so->so_label` (in memory, inherited from creator)

```c
/* Socket lifecycle */
mpo_socket_init_label
mpo_socket_create          → Inherit creator's process label
mpo_socket_destroy_label
mpo_socket_copy_label
mpo_socket_newconn         → Accepted socket inherits listener's label

/* Socket checks - can deny individual operations! */
mpo_socket_check_create    → VLABEL_OP_CREATE (deny socket() call)
mpo_socket_check_bind      → VLABEL_OP_BIND (UNIX: also check socket file label)
mpo_socket_check_connect   → VLABEL_OP_CONNECT (UNIX: check socket file label!)
mpo_socket_check_listen    → VLABEL_OP_LISTEN
mpo_socket_check_accept    → VLABEL_OP_ACCEPT
mpo_socket_check_send      → VLABEL_OP_WRITE (every send!)
mpo_socket_check_receive   → VLABEL_OP_READ (every recv!)
mpo_socket_check_stat      → VLABEL_OP_STAT
mpo_socket_check_visible   → Hide sockets from wrong labels
mpo_socket_check_deliver   → Control packet delivery
```

**Key insights:**
- `socket_check_send/receive` are called per-operation - can deny individual reads/writes
- For UNIX domain, `connect()` receives `sockaddr_un` with path - can look up vnode label
- Socket labels do NOT change on exec - but new process label is checked on each operation
- Accepted connections inherit listener's socket label via `socket_newconn`

### Phase 6: Pipes (MEDIUM)

```c
/* Pipe lifecycle */
mpo_pipe_init_label
mpo_pipe_create            → Inherit creator's label
mpo_pipe_copy_label
mpo_pipe_destroy_label

/* Pipe checks */
mpo_pipe_check_read        → VLABEL_OP_READ
mpo_pipe_check_write       → VLABEL_OP_WRITE
mpo_pipe_check_stat        → VLABEL_OP_STAT
mpo_pipe_check_ioctl       → VLABEL_OP_IOCTL
mpo_pipe_check_poll        → Allow (no security impact)
```

**Label inheritance:** Both ends of pipe get creator's label. Useful for cross-process pipe access control.

### Phase 7: POSIX Shared Memory (HIGH)

```c
/* Lifecycle */
mpo_posixshm_init_label
mpo_posixshm_create        → Inherit creator's label
mpo_posixshm_destroy_label

/* Checks */
mpo_posixshm_check_create  → VLABEL_OP_CREATE
mpo_posixshm_check_open    → VLABEL_OP_OPEN
mpo_posixshm_check_mmap    → VLABEL_OP_MMAP
mpo_posixshm_check_read    → VLABEL_OP_READ
mpo_posixshm_check_write   → VLABEL_OP_WRITE
mpo_posixshm_check_truncate→ VLABEL_OP_WRITE
mpo_posixshm_check_stat    → VLABEL_OP_STAT
mpo_posixshm_check_unlink  → VLABEL_OP_UNLINK
mpo_posixshm_check_setmode → VLABEL_OP_SETATTR
mpo_posixshm_check_setowner→ VLABEL_OP_SETATTR
```

### Phase 8: POSIX Semaphores (MEDIUM)

```c
/* Lifecycle */
mpo_posixsem_init_label
mpo_posixsem_create        → Inherit creator's label
mpo_posixsem_destroy_label

/* Checks */
mpo_posixsem_check_open    → VLABEL_OP_OPEN
mpo_posixsem_check_post    → VLABEL_OP_WRITE (sem_post)
mpo_posixsem_check_wait    → VLABEL_OP_READ (sem_wait)
mpo_posixsem_check_getvalue→ VLABEL_OP_STAT
mpo_posixsem_check_unlink  → VLABEL_OP_UNLINK
mpo_posixsem_check_setmode → VLABEL_OP_SETATTR
mpo_posixsem_check_setowner→ VLABEL_OP_SETATTR
```

### Phase 9: SysV IPC (LOW)

```c
/* SysV Shared Memory */
mpo_sysvshm_check_shmat    → VLABEL_OP_MMAP
mpo_sysvshm_check_shmdt    → Allow
mpo_sysvshm_check_shmctl   → VLABEL_OP_STAT or VLABEL_OP_SETATTR
mpo_sysvshm_check_shmget   → VLABEL_OP_OPEN or VLABEL_OP_CREATE

/* SysV Semaphores */
mpo_sysvsem_check_semop    → VLABEL_OP_READ/WRITE
mpo_sysvsem_check_semctl   → VLABEL_OP_STAT/SETATTR
mpo_sysvsem_check_semget   → VLABEL_OP_OPEN/CREATE

/* SysV Message Queues */
mpo_sysvmsq_check_msgrcv   → VLABEL_OP_READ
mpo_sysvmsq_check_msqsnd   → VLABEL_OP_WRITE
mpo_sysvmsq_check_msqctl   → VLABEL_OP_STAT/SETATTR
mpo_sysvmsq_check_msqget   → VLABEL_OP_OPEN/CREATE
```

### Phase 10: System Operations (LOW)

```c
/* Kernel modules - label comes from .ko file vnode */
mpo_kld_check_load         → Check vnode label of module file
mpo_kld_check_stat         → VLABEL_OP_STAT

/* System */
mpo_system_check_reboot    → Require type=admin or similar
mpo_system_check_swapon    → Check swap file label
mpo_system_check_swapoff   → Check swap file label
mpo_system_check_sysctl    → Protect sensitive sysctls

/* kenv */
mpo_kenv_check_set         → Protect boot variables
mpo_kenv_check_unset       → Protect boot variables
```

### Phase 11: Device Filesystem (MEDIUM)

```c
/* devfs labeling */
mpo_devfs_create_device    → Label device from rules
mpo_devfs_create_directory → Label devfs directory
mpo_devfs_vnode_associate  → Copy devfs label to vnode

/* Then normal vnode checks apply to /dev/* */
```

**Use case:** Label `/dev/mem` with `type=dangerous`, deny access.

---

## New Operation Constants

```c
/* Add to mac_vlabel.h */

/* Existing (keep) */
#define VLABEL_OP_EXEC          0x0001
#define VLABEL_OP_READ          0x0002
#define VLABEL_OP_WRITE         0x0004
#define VLABEL_OP_MMAP          0x0008
#define VLABEL_OP_LINK          0x0010
#define VLABEL_OP_RENAME        0x0020
#define VLABEL_OP_UNLINK        0x0040
#define VLABEL_OP_CHDIR         0x0080
#define VLABEL_OP_STAT          0x0100
#define VLABEL_OP_READDIR       0x0200
#define VLABEL_OP_CREATE        0x0400
#define VLABEL_OP_SETEXTATTR    0x0800
#define VLABEL_OP_GETEXTATTR    0x1000
#define VLABEL_OP_LOOKUP        0x2000
#define VLABEL_OP_OPEN          0x4000
#define VLABEL_OP_ACCESS        0x8000
#define VLABEL_OP_DEBUG         0x10000
#define VLABEL_OP_SIGNAL        0x20000
#define VLABEL_OP_SCHED         0x40000

/* New operations */
#define VLABEL_OP_SETATTR       0x00080000  /* chmod/chown/chflags/utimes */
#define VLABEL_OP_BIND          0x00100000  /* Socket bind */
#define VLABEL_OP_CONNECT       0x00200000  /* Socket connect */
#define VLABEL_OP_LISTEN        0x00400000  /* Socket listen */
#define VLABEL_OP_ACCEPT        0x00800000  /* Socket accept */
#define VLABEL_OP_IOCTL         0x01000000  /* ioctl operations */
#define VLABEL_OP_KLDLOAD       0x02000000  /* Load kernel module */
#define VLABEL_OP_REBOOT        0x04000000  /* System reboot */
#define VLABEL_OP_SYSCTL        0x08000000  /* Sysctl access */

#define VLABEL_OP_ALL           0x0FFFFFFF
```

---

## New Sysctls

```
security.mac.vlabel.mode                   # 0=disabled, 1=permissive, 2=enforcing
security.mac.vlabel.default_policy         # 0=allow, 1=deny when no rule matches
security.mac.vlabel.protect_labels         # 1=protect system:vlabel from modification
security.mac.vlabel.protect_system_extattr # 0=also protect all system:* extattrs
security.mac.vlabel.socket_inherit         # 1=sockets inherit creator label (default)
security.mac.vlabel.pipe_inherit           # 1=pipes inherit creator label (default)
security.mac.vlabel.ipc_inherit            # 1=POSIX/SysV IPC inherit creator label
```

---

## Implementation Priority Summary

| Phase | Focus | Priority | Est. Hooks |
|-------|-------|----------|------------|
| 1 | Core file ops (read/write/open/mmap) | HIGH | 5 |
| 2 | Protect labels (setextattr) | HIGH | 4 |
| 5 | Sockets (UNIX domain!) | HIGH | 10 |
| 7 | POSIX shm | HIGH | 10 |
| 3 | Directory ops | MEDIUM | 9 |
| 4 | File metadata | MEDIUM | 8 |
| 6 | Pipes | MEDIUM | 6 |
| 8 | POSIX sem | MEDIUM | 7 |
| 11 | devfs | MEDIUM | 4 |
| 9 | SysV IPC | LOW | 12 |
| 10 | System ops | LOW | 8 |

**Total: ~83 hooks** (many are simple, follow same pattern)

---

## Label Inheritance Rules

| Object Type | Label Source |
|-------------|--------------|
| New file | Parent directory label OR creator process label |
| New directory | Parent directory label OR creator process label |
| UNIX socket file | Creator process label (written as extattr) |
| FIFO | Creator process label (written as extattr) |
| Anonymous pipe | Creator process label (in-memory) |
| Socket (network) | Creator process label (in-memory) |
| POSIX shm | Creator process label (in-memory) |
| POSIX sem | Creator process label (in-memory) |
| SysV IPC | Creator process label (in-memory) |
| Accepted socket | Listener socket label |
| Fork'd process | Parent process label |
| Exec'd process | Executable file label OR transition rule |

---

## Limitations (What MACF Cannot Do)

### 1. Relabel Sockets on Exec
No MACF hook iterates open file descriptors on exec. Socket labels stay the same.

**Workaround:** The process label changes via transition rule, then send/recv checks fail because process label doesn't match socket label.

### 2. Atomically Create + Label Files
ZFS doesn't support `vnode_create_extattr`. Files are created without labels.

**Workaround:** Create file, then set label. Brief race window exists.

### 3. Know Remote Peer in Receive Checks
`socket_check_receive` doesn't get the source address.

**Workaround:** Use `socketpeer_set_from_mbuf` for network peer labeling (complex).

### 4. Label Anonymous Memory Mappings
`mmap(MAP_ANON)` creates memory with no file backing - no label source.

**Workaround:** Inherit process label for anonymous mappings.

---

## Testing Strategy

### Per-object-type tests:

```sh
# UNIX domain socket
vlabelctl label set /var/run/test.sock "type=service,domain=web"
# Verify connect() from wrong label is denied

# Named pipe
mkfifo /tmp/test.fifo
vlabelctl label set /tmp/test.fifo "type=ipc,domain=app"
# Verify read/write from wrong label denied

# POSIX shm
# Create shm, check label inheritance
# Verify cross-domain access denied
```
