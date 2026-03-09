# vLabelMACF Project Plan

## Project Status: ~85% Complete

The core kernel module is functional with exec enforcement, label transitions,
DTrace instrumentation, and ZFS support working. Tests pass (12/12 when
pre-labeled binaries are set up).

---

## Critical Priority (Before 1.0 Release)

### 1. Vnode Operation Enforcement
**Status:** Only `check_exec` fully implemented
**Location:** `kernel/vlabel_vnode.c`

Other file operations are stubs returning 0 (allow):
- `check_read`, `check_write`, `check_open`, `check_mmap`
- `check_stat`, `check_link`, `check_rename`, `check_unlink`
- `check_create`, `check_lookup`, `check_readdir`, `check_chdir`
- Extended attribute operations

Rules can specify these operations but enforcement doesn't happen.
Pattern from `check_exec` can be replicated.

### 2. Label Externalization/Internalization
**Status:** Stubs that do nothing
**Location:** `kernel/vlabel_vnode.c` lines 249-264

- `vlabel_vnode_externalize_label()` - stub
- `vlabel_vnode_internalize_label()` - stub

Standard FreeBSD tools (`mac_get_file`/`mac_set_file`) won't work.
Currently recommends `vlabelctl`/`setextattr` instead.

### 3. Test Coverage for Non-Exec Operations
**Status:** Tests only cover exec/transitions
**Location:** `tests/`

Need integration tests for each operation type once #1 is implemented.

---

## Important Priority (Beta Release)

### 4. Credential Check Hooks
**Status:** Stubs returning 0
**Location:** `kernel/vlabel_cred.c` lines 123-150

- `cred_check_relabel()` - stub
- `cred_check_setuid()` - stub
- `cred_check_setgid()` - stub

### 5. DTrace Probe Testing
**Status:** 13 probes defined but undertested
**Location:** `kernel/mac_vlabel.c`, `tests/11_dtrace.sh`

Test output shows "Probe count: 0" - need to verify probes fire.
DTrace scripts exist in `/scripts/dtrace/` but not integrated into test suite.

### 6. Process Enforcement Testing
**Status:** Implemented but limited test coverage
**Location:** `kernel/vlabel_proc.c`, `tests/12_process_enforcement.sh`

- `proc_check_debug` - controls ptrace/procfs
- `proc_check_signal` - controls signal delivery
- `proc_check_sched` - controls scheduler operations

### 7. Limits Verification
**Status:** Limits defined but may not match post-refactoring behavior
**Location:** `kernel/vlabel_rules.c`, `tests/10_limits.sh`

Documented limits:
- 4KB labels, 64-byte keys, 256-byte values
- 16 key-value pairs per label
- 1024 rules maximum

Verify consistently enforced across kernel/userland.

### 8. Audit/Logging Infrastructure
**Status:** Partial (sysctl stats + DTrace probes)

No standard FreeBSD audit subsystem integration documented.
Consider auditd integration for production deployments.

---

## Nice-to-Have (Polish & Optimization)

### 9. Module Unloading Support
**Status:** Disabled by design (no MPC_LOADTIME_FLAG_UNLOADOK)

High complexity - requires redesign of label attachment lifecycle.
Known FreeBSD MAC framework limitation, not unique to vLabel.

### 10. Performance Optimization
**Status:** Basic implementation

- Rule evaluation is linear search O(n)
- No rule indexing by operation type
- Consider hash table for 1000+ rule deployments

### 11. Documentation
**Status:** 85% complete

Missing:
- Getting started tutorial
- Deployment guide (production best practices)
- Real-world policy examples (web server stack, etc.)

### 12. FreeBSD Port/Package
**Status:** Manual build only

Need:
- FreeBSD port structure
- Install script
- RC script for vlabeld

### 13. Rule Management Enhancements

Ideas:
- Rule groups/profiles for easier policy switching
- Incremental rule updates without full clear
- Rule validation/dry-run before loading

### 14. vlabelctl Enhancements

Ideas:
- Interactive rule editor
- Policy simulation/testing mode
- Batch label operations
- Import/export capabilities

### 15. Context Constraints Testing
**Status:** Framework exists, limited test coverage

5 constraint types exist:
- Jail ID constraints
- Capsicum sandboxing detection
- UID/GID matching
- Has TTY detection

---

## Known Limitations (By Design)

1. **No Module Unloading** - Following FreeBSD MAC framework patterns
2. **Vnode Label Caching** - Labels cached until vnode reclaim; binaries must
   be labeled before module load OR use deploy-test.sh workflow
3. **Default Policy** - Default is allow (not deny)
4. **Linear Rule Evaluation** - First match wins, O(n) lookup

---

## What Works Today (Production-Ready)

- Kernel module loading/enforcement (3 modes: disabled/permissive/enforcing)
- Exec denial based on labels (UFS and ZFS)
- Label transitions on exec
- DTrace instrumentation (13 probes)
- Policy language parsing (vlabeld with UCL)
- CLI management (vlabelctl)
- 48 MACF hooks registered
- Extended attribute label storage

---

## Original Questions (Archived)

> Am I handling the rule ID field correctly?

Rule IDs are assigned sequentially. First-match-wins evaluation.
IDs are useful for `rule remove <id>` but not for priority.
Consider rule groups for related rules.

> We have add. What about subtract?

`rule remove <id>` removes by ID. `rule clear` removes all.
No subtract/diff operation exists.

> What about limits - do they make sense now that we're not using ioctl?

Limits moved to mac_syscall interface. Should verify they're
consistently enforced across kernel/userland boundaries.

> FreeBSDKit: Label tool doesn't support context.

Context constraints are kernel-side only. Userland tools
(`vlabelctl label`) set key=value pairs; context is evaluated
at enforcement time by the kernel.
