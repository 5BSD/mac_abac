# vLabel MACF Module Requirements Specification

## 1. Overview

**Project**: vLabel - A label-based Mandatory Access Control Framework module for FreeBSD

**Purpose**: Provide fine-grained access control for filesystem operations using persistent labels stored in extended attributes, with a flexible policy engine supporting context-aware rules.

---

## 2. Architecture

### 2.1 Components

| Component | Location | Description |
|-----------|----------|-------------|
| `mac_vlabel.ko` | Kernel | MACF policy module implementing access control hooks |
| `/dev/vlabel` | Kernel (devfs) | Character device for userland communication |
| `vlabeld` | Userland | Daemon managing policy rules and audit logging |
| `vlabelctl` | Userland | CLI tool for policy and label management |

### 2.2 Component Interactions

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  vlabelctl CLI  │────▶│    vlabeld       │────▶│  Policy Store   │
└─────────────────┘     │  (userland)      │     │  (config files) │
                        └────────┬─────────┘     └─────────────────┘
                                 │ ioctl
                        ┌────────▼─────────┐
                        │  /dev/vlabel     │
                        └────────┬─────────┘
                                 │
                        ┌────────▼─────────┐     ┌─────────────────┐
                        │  mac_vlabel.ko   │────▶│  Audit Subsystem│
                        │  (MACF module)   │     │  (kernel/user)  │
                        └────────┬─────────┘     └─────────────────┘
                                 │
                        ┌────────▼─────────┐
                        │  Extended Attrs  │
                        │  system:vlabel   │
                        └─────────────────┘
```

---

## 3. Label System

### 3.1 Label Storage

- **Namespace**: `system` (requires root privileges to modify)
- **Attribute name**: `vlabel`
- **Full extattr path**: `system:vlabel`

### 3.2 Label Format

Labels use a key-value pair format:

```
key1=value1,key2=value2,...
```

**Reserved keys**:
| Key | Description | Example Values |
|-----|-------------|----------------|
| `type` | Object/subject classification | `system`, `app`, `user`, `untrusted` |
| `domain` | Functional domain | `network`, `storage`, `gui`, `daemon` |
| `level` | Sensitivity/trust level | `high`, `medium`, `low` |
| `name` | Specific identifier | `httpd`, `sshd`, `firefox` |

**Example labels**:
- `type=system,domain=daemon,name=sshd,level=high`
- `type=app,domain=network,name=firefox,level=low`
- `type=user,level=medium`

### 3.3 Subject Labels

Subject (process) labels are determined by:

1. **Inheritance**: New processes inherit parent's label by default
2. **Transitions**: Executing a labeled binary can trigger a label transition based on transition rules
3. **Kernel tracking**: Module maintains label state in process credentials

### 3.4 Default Labels

- **Unlabeled objects**: Assigned a configurable default label (e.g., `type=unlabeled,level=low`)
- **Unlabeled subjects**: Assigned a configurable default subject label
- **Default labels configurable** via policy

---

## 4. Policy Engine

### 4.1 Rule Structure

```
<action> <operation> subject:<subject-match> object:<object-match> [context:<context-match>]
```

**Components**:
| Field | Values | Description |
|-------|--------|-------------|
| `action` | `allow`, `deny` | Grant or refuse access |
| `operation` | `exec`, `read`, `write`, `mmap`, `link`, `rename`, `unlink`, `chdir`, `stat`, `*` | Filesystem operation |
| `subject-match` | Key-value pattern | Match against subject label |
| `object-match` | Key-value pattern | Match against object label |
| `context-match` | Context assertions | Match against process context |

### 4.2 Pattern Matching

Label patterns support:
- **Exact match**: `type=system`
- **Wildcard**: `type=*` or `domain=*`
- **Multiple values**: `type=system|app`
- **Negation**: `type!=untrusted`
- **Conjunction**: `type=system,domain=daemon` (AND)

### 4.3 Context Assertions

Rules can include context conditions:

| Assertion | Description | Example |
|-----------|-------------|---------|
| `cap_sandboxed` | Process is in capability mode | `cap_sandboxed=true` |
| `jail` | Jail ID check | `jail=0` (host), `jail!=0` (any jail) |
| `uid` | Effective UID | `uid=0`, `uid!=0` |
| `gid` | Effective GID | `gid=0`, `gid=wheel` (resolved) |
| `euid` | Effective UID | Same as uid |
| `ruid` | Real UID | `ruid=1000` |
| `sid` | Session ID | `sid=current` (same session) |
| `has_tty` | Has controlling terminal | `has_tty=true` |
| `parent_label` | Parent process label | `parent_label:type=system` |

### 4.4 Rule Evaluation

1. **Order**: Rules evaluated in definition order (first match wins)
2. **Default**: No matching rule = **deny** (implicit deny / whitelist model)
3. **Explicit deny**: Deny rules can be placed early to block specific combinations

### 4.5 Label Transition Rules

Special rules for subject label changes on exec:

```
transition exec subject:<current-label> object:<binary-label> -> <new-label>
```

**Example**:
```
transition exec subject:type=user object:type=system,name=su -> type=system,domain=auth,name=su
```

---

## 5. Controlled Operations

### 5.1 MACF Hooks Required

| Operation | MACF Hook(s) | Description |
|-----------|--------------|-------------|
| `exec` | `mpo_vnode_check_exec` | Execute file |
| `read` | `mpo_vnode_check_read` | Read file contents |
| `write` | `mpo_vnode_check_write` | Write file contents |
| `mmap` | `mpo_vnode_check_mmap` | Memory-map file |
| `link` | `mpo_vnode_check_link` | Create hard link |
| `rename` | `mpo_vnode_check_rename_from`, `mpo_vnode_check_rename_to` | Rename/move file |
| `unlink` | `mpo_vnode_check_unlink` | Delete file |
| `chdir` | `mpo_vnode_check_chdir` | Change directory |
| `stat` | `mpo_vnode_check_stat` | Stat file |
| `readdir` | `mpo_vnode_check_readdir` | Read directory contents |
| `create` | `mpo_vnode_check_create` | Create new file |
| `mkdir` | `mpo_vnode_check_mkdir` | Create directory |
| `setextattr` | `mpo_vnode_check_setextattr` | Modify extended attributes |
| `getextattr` | `mpo_vnode_check_getextattr` | Read extended attributes |

### 5.2 Label Lifecycle Hooks

| Hook | Purpose |
|------|---------|
| `mpo_vnode_init_label` | Initialize vnode label slot |
| `mpo_vnode_destroy_label` | Clean up vnode label |
| `mpo_vnode_associate_extattr` | Load label from extattr on vnode activation |
| `mpo_vnode_create_extattr` | Set default label on new file creation |
| `mpo_cred_init_label` | Initialize credential (subject) label |
| `mpo_cred_destroy_label` | Clean up credential label |
| `mpo_cred_copy_label` | Copy label on fork |
| `mpo_cred_execve_transition` | Handle label transition on exec |

---

## 6. Enforcement Modes

### 6.1 Global Modes

| Mode | Behavior |
|------|----------|
| `enforcing` | Policy decisions are enforced; violations denied |
| `permissive` | Policy evaluated but not enforced; violations logged only |
| `disabled` | Module loaded but not active; all operations allowed |

### 6.2 Mode Control

- Mode set via `/dev/vlabel` ioctl or `vlabelctl mode <mode>`
- Mode change requires appropriate privilege
- Default mode on load: configurable (recommend `permissive` for initial deployment)

---

## 7. Audit System

### 7.1 Audit Events

| Event Type | Description |
|------------|-------------|
| `ACCESS_ALLOWED` | Policy allowed an operation |
| `ACCESS_DENIED` | Policy denied an operation |
| `LABEL_TRANSITION` | Subject label changed |
| `POLICY_LOAD` | Policy rules loaded/updated |
| `MODE_CHANGE` | Enforcement mode changed |
| `LABEL_CHANGE` | Object label modified |

### 7.2 Audit Record Fields

Each audit record includes:
- Timestamp
- Event type
- Subject label
- Subject context (pid, uid, gid, jail, cap_sandboxed, etc.)
- Object path and label
- Operation attempted
- Rule matched (if any)
- Decision (allow/deny)
- Enforcement mode at time of decision

### 7.3 Audit Delivery

- Kernel queues audit events
- `vlabeld` reads events via `/dev/vlabel`
- `vlabeld` can: log to file, syslog, forward to remote, etc.
- Configurable verbosity levels:
  - `none`: No auditing
  - `denials`: Only denied operations
  - `decisions`: All policy decisions
  - `verbose`: All decisions plus label lookups

---

## 8. devfs Interface (`/dev/vlabel`)

### 8.1 Operations

| Operation | Description |
|-----------|-------------|
| `open()` | Connect to control interface |
| `read()` | Read audit events (blocking or non-blocking) |
| `write()` | Submit policy rules |
| `ioctl()` | Control commands (mode, query, etc.) |
| `poll()`/`select()` | Wait for audit events |

### 8.2 ioctl Commands

| Command | Description |
|---------|-------------|
| `VLABEL_GET_MODE` | Query current enforcement mode |
| `VLABEL_SET_MODE` | Set enforcement mode |
| `VLABEL_LOAD_POLICY` | Atomically load policy ruleset |
| `VLABEL_GET_POLICY` | Retrieve current policy |
| `VLABEL_GET_STATS` | Get statistics (decisions, cache hits, etc.) |
| `VLABEL_SET_AUDIT_LEVEL` | Configure audit verbosity |
| `VLABEL_QUERY_LABEL` | Query label for a path (debugging) |

---

## 9. Userland Tools

### 9.1 vlabeld (Daemon)

**Responsibilities**:
- Load policy from configuration files on startup
- Push policy to kernel via `/dev/vlabel`
- Receive and process audit events
- Provide IPC for `vlabelctl`
- Handle SIGHUP for policy reload

**Configuration**: `/usr/local/etc/vlabel/vlabeld.conf`

### 9.2 vlabelctl (CLI)

**Commands**:

```
vlabelctl mode [enforcing|permissive|disabled]  # Get/set mode
vlabelctl policy load <file>                     # Load policy file
vlabelctl policy show                            # Display current policy
vlabelctl policy test <subject> <object> <op>    # Test rule evaluation
vlabelctl label get <path>                       # Show label for path
vlabelctl label set <path> <label>               # Set label (via setextattr)
vlabelctl label clear <path>                     # Remove label
vlabelctl stats                                  # Show statistics
vlabelctl audit [tail|export]                    # View/export audit log
```

---

## 10. Policy File Format

### 10.1 Syntax

```
# Comments start with #

# Default labels
default object_label type=unlabeled,level=default
default subject_label type=user,level=default

# Audit configuration
audit level decisions

# Rules (evaluated in order, first match wins)
allow exec subject:type=system object:type=system
allow exec subject:type=system object:type=app
deny  exec subject:type=untrusted object:type=system
allow exec subject:type=user object:type=app context:jail=0
allow read subject:type=* object:type=user context:uid=owner  # owner can read own files

# Transitions
transition exec subject:type=user object:type=system,name=sudo -> type=system,domain=auth

# Catch-all (optional, implicit deny if omitted)
# deny * subject:* object:*
```

### 10.2 File Locations

- `/usr/local/etc/vlabel/policy.conf` - Main policy
- `/usr/local/etc/vlabel/policy.d/*.conf` - Additional policy fragments (loaded in order)

---

## 11. Security Considerations

### 11.1 Privilege Requirements

| Action | Required Privilege |
|--------|-------------------|
| Modify `system:vlabel` extattr | Root (uid 0) |
| Change enforcement mode | Root or `vlabel` capability |
| Load policy | Root or `vlabel` capability |
| Read audit log | Root or audit group |

### 11.2 Self-Protection

- Module must protect `/dev/vlabel` access
- Module must protect its own policy and audit mechanisms
- Policy should restrict modification of labels on critical binaries
- Consider: bootstrap/chicken-egg - initial labeling before policy active

### 11.3 Bypass Considerations

- Raw disk access can bypass extattr storage
- Kernel modules can bypass MACF
- Document limitations clearly

---

## 12. Performance Considerations

### 12.1 Caching

- Cache resolved labels for vnodes (already in vnode label slot)
- Cache compiled rule patterns
- Consider negative cache for unlabeled objects

### 12.2 Lock Contention

- Policy rule set: read-mostly, RCU-style or rwlock
- Audit queue: lockless ring buffer or per-CPU queues
- Label cache: per-vnode, follows vnode lifecycle

---

## 13. Future Considerations (Out of Scope for MVP)

- Network socket labeling
- IPC (pipe, socket, SysV IPC) labeling
- Label integrity verification (signed labels)
- Remote policy management
- Integration with FreeBSD audit(4)
- GUI policy editor

---

## 14. Success Criteria

### 14.1 Functional Requirements

- [ ] Module loads and registers with MACF
- [ ] Labels read from `system:vlabel` extattr
- [ ] Subject labels track process lifecycle (fork, exec)
- [ ] Label transitions work on exec
- [ ] All specified operations checked against policy
- [ ] Context assertions evaluated correctly
- [ ] First-match rule evaluation works
- [ ] Explicit allow/deny rules work
- [ ] Default labels applied to unlabeled objects/subjects
- [ ] Enforcement mode toggles correctly
- [ ] Permissive mode logs but allows
- [ ] Audit events generated and readable
- [ ] devfs interface functional
- [ ] vlabeld loads policy and receives audit
- [ ] vlabelctl can manage labels and policy

### 14.2 Non-Functional Requirements

- [ ] Overhead < 5% on typical workloads (to be benchmarked)
- [ ] No kernel panics under stress
- [ ] Graceful handling of corrupted/missing labels
- [ ] Policy load atomic (all or nothing)

---

## Appendix A: Example Policy

```
# /usr/local/etc/vlabel/policy.conf
# Example: Restrict untrusted applications

# Defaults
default object_label type=unlabeled,level=default
default subject_label type=user,level=default

# System processes can do anything to system files
allow * subject:type=system object:type=system

# System can execute and read app binaries
allow exec subject:type=system object:type=app
allow read subject:type=system object:type=app

# Users can run and access user files
allow * subject:type=user object:type=user

# Users can execute (but not write) app binaries
allow exec subject:type=user object:type=app
allow read subject:type=user object:type=app
allow mmap subject:type=user object:type=app

# Untrusted can only access untrusted files
allow * subject:type=untrusted object:type=untrusted

# Untrusted can read (not write) user data
allow read subject:type=untrusted object:type=user

# Untrusted CANNOT execute system or app binaries
deny exec subject:type=untrusted object:type=system
deny exec subject:type=untrusted object:type=app

# Sandboxed apps (capability mode) get minimal access
deny * subject:* object:* context:cap_sandboxed=true
allow read subject:* object:type=app,name=sandbox-whitelist context:cap_sandboxed=true

# Transition: when user runs su, transition to system/auth
transition exec subject:type=user object:type=system,name=su -> type=system,domain=auth,name=su
transition exec subject:type=user object:type=system,name=sudo -> type=system,domain=auth,name=sudo
```

---

## Appendix B: Glossary

| Term | Definition |
|------|------------|
| **MACF** | Mandatory Access Control Framework - FreeBSD's pluggable MAC system |
| **Subject** | The active entity (process) attempting an operation |
| **Object** | The passive entity (file, directory) being acted upon |
| **Label** | Security metadata attached to subjects and objects |
| **Extattr** | Extended attribute - arbitrary metadata stored with filesystem objects |
| **Policy** | Set of rules determining access decisions |
| **Transition** | Change in subject label, typically triggered by exec |

---

*Document Version: 1.0*
*Last Updated: 2026-03-05*
