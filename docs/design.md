# vLabel Design Document

## Answers to Key Questions

### Can MACF deny individual socket reads/writes?

**Yes.** The hooks exist and work:

```c
mac_socket_check_send(cred, so)    // Called on every send()
mac_socket_check_receive(cred, so) // Called on every recv()
```

The policy receives:
- `cred` - the process credential (has our process label)
- `so` - the socket (has `so->so_label` - our socket label)

So we can enforce: "process with label X cannot send on socket with label Y"

### Can MACF change socket labels on exec?

**No direct hook.** But here's what happens:

1. `execve_transition()` changes the **credential label** (process label)
2. Existing sockets keep their **socket labels** unchanged
3. Post-exec, the new process label is checked against socket labels on each operation

So effectively: after exec with a transition rule, the process has a new label, and if that new label doesn't match the socket's label, send/recv will be denied.

**There is no hook to iterate and relabel all open sockets on exec.**

If you need that, you'd have to:
1. Track sockets per-process (not provided by MACF)
2. Relabel them in `execve_transition` (would need custom code)

The simpler approach: rely on the send/recv checks to deny access post-transition.

---

## Label Protection Design

### Two Types of Label Protection

#### 1. Protect vLabel's Own Labels (system:vlabel extattr)

**Goal:** Prevent unauthorized modification of `system:vlabel` extended attributes.

**Implementation:**
```c
int vlabel_vnode_check_setextattr(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, int attrnamespace, const char *name)
{
    /* Always protect our own attribute */
    if (attrnamespace == EXTATTR_NAMESPACE_SYSTEM &&
        strcmp(name, "vlabel") == 0) {
        /* Only allow if process has relabel privilege */
        if (!vlabel_can_relabel(cred, vplabel))
            return (EPERM);
    }
    return (0);
}
```

**Policy options:**
- `security.mac.vlabel.protect_labels` sysctl (1 = on, 0 = off)
- When on, only root OR processes with `type=labeler` can modify `system:vlabel`
- Or: integrate with rules - `allow setextattr type=admin -> *`

#### 2. Protect Other MAC Policy Labels

**Goal:** Optionally protect other policies' labels (e.g., `system:biba`, `system:mls`).

**Implementation:**
```c
int vlabel_vnode_check_setextattr(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, int attrnamespace, const char *name)
{
    /* Protect our labels */
    if (attrnamespace == EXTATTR_NAMESPACE_SYSTEM &&
        strcmp(name, "vlabel") == 0) {
        return vlabel_check_relabel_allowed(cred, vplabel);
    }

    /* Optionally protect ALL system namespace extattrs */
    if (vlabel_protect_system_extattr &&
        attrnamespace == EXTATTR_NAMESPACE_SYSTEM) {
        /* Use standard vnode check */
        return vlabel_rules_check(cred, subj, obj, VLABEL_OP_SETEXTATTR, NULL);
    }

    return (0);
}
```

**Sysctl options:**
```
security.mac.vlabel.protect_own_label=1     # Protect system:vlabel
security.mac.vlabel.protect_system_extattr=0 # Protect all system:* extattrs
```

---

## Object Label Inheritance

### File-Backed Objects (Persistent Labels)

| Object | Label Source | Storage |
|--------|--------------|---------|
| Regular file | `system:vlabel` extattr | Disk |
| Directory | `system:vlabel` extattr | Disk |
| UNIX socket file | `system:vlabel` extattr | Disk |
| FIFO (named pipe) | `system:vlabel` extattr | Disk |
| Device node | devfs labeling OR extattr | Varies |
| Symlink | `system:vlabel` extattr | Disk |

### In-Memory Objects (Inherited Labels)

| Object | Label Source | Lifecycle |
|--------|--------------|-----------|
| Process | Exec'd file label OR transition rule | Until exit |
| Anonymous pipe | Creator process label | Until close |
| Socket (any type) | Creator process label | Until close |
| POSIX shm | Creator process label | Until unlink |
| POSIX sem | Creator process label | Until unlink |
| SysV IPC | Creator process label | Until removal |
| Accepted socket | Listener socket label | Until close |

### Label Inheritance on Creation

```c
void mpo_socket_create(struct ucred *cred, struct socket *so,
    struct label *solabel)
{
    /* Copy creator's credential label to socket label */
    struct vlabel_label *proc_label = SLOT(cred->cr_label);
    struct vlabel_label *sock_label = SLOT(solabel);

    if (proc_label != NULL && sock_label != NULL)
        vlabel_label_copy(proc_label, sock_label);
}
```

### Accepted Connection Labeling

```c
void mpo_socket_newconn(struct socket *oldso, struct label *oldsolabel,
    struct socket *newso, struct label *newsolabel)
{
    /* New connection inherits listener's label */
    struct vlabel_label *listener = SLOT(oldsolabel);
    struct vlabel_label *accepted = SLOT(newsolabel);

    if (listener != NULL && accepted != NULL)
        vlabel_label_copy(listener, accepted);
}
```

---

## Socket Operations Deep Dive

### What MACF Provides

| Hook | When Called | Can Deny? |
|------|-------------|-----------|
| `socket_check_create` | `socket()` | Yes |
| `socket_check_bind` | `bind()` | Yes |
| `socket_check_connect` | `connect()` | Yes |
| `socket_check_listen` | `listen()` | Yes |
| `socket_check_accept` | `accept()` | Yes |
| `socket_check_send` | `send/write` | Yes |
| `socket_check_receive` | `recv/read` | Yes |
| `socket_check_stat` | `fstat()` | Yes |
| `socket_check_visible` | Socket enumeration | Yes |
| `socket_check_deliver` | Packet delivery | Yes |
| `socket_create` | After socket() | No (labeling) |
| `socket_newconn` | After accept() | No (labeling) |
| `socket_relabel` | Label change | No (labeling) |

### UNIX Domain Sockets - Two Labels!

For UNIX domain sockets, we have:

1. **Socket file label** (on disk) - the vnode at `/var/run/foo.sock`
2. **Socket object label** (in memory) - the `so->so_label`

**On connect():**
```c
int mpo_socket_check_connect(struct ucred *cred, struct socket *so,
    struct label *solabel, struct sockaddr *sa)
{
    /* sa contains the path for AF_UNIX */
    /* We could look up the vnode and check its label! */

    if (so->so_type == SOCK_STREAM && sa->sa_family == AF_UNIX) {
        /* Look up the socket file vnode */
        struct sockaddr_un *sun = (struct sockaddr_un *)sa;
        /* Could do namei() to get vnode, check its label */
    }

    return (0);
}
```

**Design choice:** For UNIX domain sockets:
- Label the socket FILE (vnode) via extattr
- Check vnode label on bind/connect
- Socket object inherits creator's process label

---

## What Cannot Be Done

### 1. Relabel All Sockets on Exec

No MACF hook iterates a process's open file descriptors on exec. The credential label changes, but socket labels don't.

**Workaround:** Deny send/recv if process label doesn't match socket label.

### 2. Label Network Connections by Remote Peer

MACF doesn't provide the remote address to most checks. `socket_check_connect` gets `sockaddr` but receive checks don't get source info.

**Workaround:** Use `socketpeer_set_from_mbuf` to extract remote label from packets (requires labeling mbufs).

### 3. Atomically Create and Label Files

`vnode_create_extattr` is for UFS multilabel, not ZFS. Can't atomically create a file with a label.

**Workaround:** Create file, then label via `vlabelctl`. Race window exists.

---

## Implementation Phases (Revised)

### Phase 1: Core File Operations
- `vnode_check_read/write/open/mmap/mprotect`
- Follow existing `check_exec` pattern

### Phase 2: Label Protection
- `vnode_check_setextattr` - protect `system:vlabel`
- `vnode_check_deleteextattr` - protect `system:vlabel`
- Add sysctl: `security.mac.vlabel.protect_labels`

### Phase 3: Socket Lifecycle
- `socket_init_label/destroy_label`
- `socket_create` - inherit creator label
- `socket_newconn` - inherit listener label
- `socket_copy_label`

### Phase 4: Socket Checks
- `socket_check_send/receive` - per-operation control
- `socket_check_bind/connect/listen/accept`
- `socket_check_visible` - hide sockets from wrong labels

### Phase 5: Pipe Lifecycle & Checks
- `pipe_init_label/create/destroy_label`
- `pipe_check_read/write/stat/ioctl`

### Phase 6: POSIX IPC
- `posixshm_*` - all lifecycle and checks
- `posixsem_*` - all lifecycle and checks

### Phase 7: Directory & Metadata
- `vnode_check_lookup/readdir/create/unlink/link/rename`
- `vnode_check_stat/setmode/setowner/setflags`

### Phase 8: System Operations
- `kld_check_load` - check .ko file label
- `system_check_reboot/sysctl` - privilege based on label

### Phase 9: SysV IPC (if needed)
- `sysvshm/sysvsem/sysvmsq` checks

---

## New Sysctls

```
security.mac.vlabel.mode                 # 0=disabled, 1=permissive, 2=enforcing
security.mac.vlabel.default_policy       # 0=allow, 1=deny
security.mac.vlabel.protect_labels       # 1=protect system:vlabel from modification
security.mac.vlabel.socket_inherit       # 1=sockets inherit creator label (default)
security.mac.vlabel.pipe_inherit         # 1=pipes inherit creator label (default)
security.mac.vlabel.ipc_inherit          # 1=POSIX/SysV IPC inherit creator label
```

---

## Summary: Can We Do X?

| Question | Answer |
|----------|--------|
| Deny socket send/recv per-operation? | **Yes** |
| Change socket labels on exec? | **No** - but new process label checked on each op |
| Label UNIX domain socket files? | **Yes** - via extattr |
| Check socket file label on connect? | **Yes** - can look up vnode in connect hook |
| Protect our own labels? | **Yes** - via setextattr hook |
| Protect other policies' labels? | **Yes** - same hook, configurable |
| Label new files atomically? | **No** - ZFS limitation |
| Label accepted connections? | **Yes** - from listener label |
| Deny socket creation by label? | **Yes** - `socket_check_create` |
| Control who can listen on ports? | **Yes** - `socket_check_listen` |
