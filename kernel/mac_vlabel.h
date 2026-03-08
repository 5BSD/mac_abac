/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 vLabel Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _SECURITY_MAC_VLABEL_H_
#define _SECURITY_MAC_VLABEL_H_

/*
 * vLabel MAC Policy Module
 *
 * A label-based Mandatory Access Control policy for FreeBSD that stores
 * security labels in extended attributes and enforces access control
 * based on configurable rules.
 */

/*
 * Extended attribute configuration
 */
#define VLABEL_EXTATTR_NAMESPACE	EXTATTR_NAMESPACE_SYSTEM
#define VLABEL_EXTATTR_NAME		"vlabel"

/*
 * Label constraints (per-label limits)
 *
 * Labels are stored as newline-separated key=value pairs in extended attributes:
 *   "key1=val1\nkey2=val2\n"
 *
 * Patterns (in rules) use comma-separated format for command-line convenience:
 *   "key1=val1,key2=val2"
 *
 * Both kernel and userland must agree on the maximum sizes.
 *
 * VLABEL_MAX_LABEL_LEN: Maximum total length of a label string (per label).
 *   - Stored in extended attributes on files
 *   - Used in ioctl structures for rule patterns
 *   - Limited by FreeBSD ioctl max size (8KB for entire structure)
 *   - struct vlabel_rule_io uses ~3x this value, so max is ~2.5KB
 *   - Set to 1KB (struct becomes ~3KB, well under 8KB limit)
 *
 * VLABEL_MAX_KEY_LEN: Maximum length of a single key name (per key).
 *   - 32 bytes total (31 usable + null terminator)
 *   - Typical keys: type, domain, level, tenant, env
 *
 * VLABEL_MAX_VALUE_LEN: Maximum length of a single value (per value).
 *   - 96 bytes total (95 usable + null terminator)
 *   - Typical values: untrusted, web, production
 *
 * VLABEL_MAX_PAIRS: Maximum number of key=value pairs per label.
 *   - Applies to both file labels and rule patterns
 *   - This is a kernel parsing limit, independent of ioctl size
 */
#define VLABEL_MAX_LABEL_LEN		1024	/* Max label string length (1KB) */
#define VLABEL_MAX_KEY_LEN		32	/* Max key length (32 bytes including null) */
#define VLABEL_MAX_VALUE_LEN		96	/* Max value length (96 bytes including null) */
#define VLABEL_MAX_PAIRS		8	/* Max key=value pairs per label */

/*
 * Rule constraints (system-wide limits)
 *
 * VLABEL_MAX_RULES: Maximum number of rules loaded in the kernel.
 *   - This is the total rule capacity system-wide
 *   - Rules are evaluated in order (first match wins)
 *   - Each rule has subject and object patterns (each up to 32 pairs)
 */
#define VLABEL_MAX_RULES		1024	/* Max rules in kernel */

/*
 * Operations bitmask for rule matching
 */
#define VLABEL_OP_EXEC			0x00000001
#define VLABEL_OP_READ			0x00000002
#define VLABEL_OP_WRITE			0x00000004
#define VLABEL_OP_MMAP			0x00000008
#define VLABEL_OP_LINK			0x00000010
#define VLABEL_OP_RENAME		0x00000020
#define VLABEL_OP_UNLINK		0x00000040
#define VLABEL_OP_CHDIR			0x00000080
#define VLABEL_OP_STAT			0x00000100
#define VLABEL_OP_READDIR		0x00000200
#define VLABEL_OP_CREATE		0x00000400
#define VLABEL_OP_SETEXTATTR		0x00000800
#define VLABEL_OP_GETEXTATTR		0x00001000
#define VLABEL_OP_LOOKUP		0x00002000
#define VLABEL_OP_OPEN			0x00004000
#define VLABEL_OP_ACCESS		0x00008000
#define VLABEL_OP_DEBUG			0x00010000	/* ptrace/procfs debug */
#define VLABEL_OP_SIGNAL		0x00020000	/* kill/signal */
#define VLABEL_OP_SCHED			0x00040000	/* scheduler operations */
#define VLABEL_OP_ALL			0x0007FFFF

/*
 * Rule actions
 */
#define VLABEL_ACTION_ALLOW		0
#define VLABEL_ACTION_DENY		1
#define VLABEL_ACTION_TRANSITION	2	/* Allow and transition to new label */

/*
 * Enforcement modes
 */
#define VLABEL_MODE_DISABLED		0
#define VLABEL_MODE_PERMISSIVE		1	/* Log but don't enforce */
#define VLABEL_MODE_ENFORCING		2

/*
 * Audit levels
 */
#define VLABEL_AUDIT_NONE		0
#define VLABEL_AUDIT_DENIALS		1	/* Log denials only */
#define VLABEL_AUDIT_DECISIONS		2	/* Log all decisions */
#define VLABEL_AUDIT_VERBOSE		3	/* Log everything */

/*
 * Context assertion flags
 */
#define VLABEL_CTX_CAP_SANDBOXED	0x00000001
#define VLABEL_CTX_JAIL			0x00000002
#define VLABEL_CTX_UID			0x00000004
#define VLABEL_CTX_GID			0x00000008
#define VLABEL_CTX_EUID			0x00000010
#define VLABEL_CTX_RUID			0x00000020
#define VLABEL_CTX_SID			0x00000040
#define VLABEL_CTX_HAS_TTY		0x00000080
#define VLABEL_CTX_PARENT_LABEL		0x00000100

/*
 * Pattern match flags
 *
 * Patterns now match against arbitrary key=value pairs in the label string.
 * The old hardcoded type/domain/name/level fields are removed.
 */
#define VLABEL_MATCH_NEGATE		0x80000000	/* Invert match result */

/*
 * Statistics structure (shared with userland)
 */
struct vlabel_stats {
	uint64_t	vs_checks;		/* Total access checks */
	uint64_t	vs_allowed;		/* Allowed accesses */
	uint64_t	vs_denied;		/* Denied accesses */
	uint64_t	vs_labels_read;		/* Labels read from extattr */
	uint64_t	vs_labels_default;	/* Default labels assigned */
	uint32_t	vs_rule_count;		/* Current rule count */
};

/*
 * Audit event structure (shared with userland)
 *
 * This is returned via read() on /dev/vlabel.
 * Each read returns one or more complete entries.
 */
#define VLABEL_AUDIT_LABEL_LEN	64
#define VLABEL_AUDIT_PATH_LEN	256

struct vlabel_audit_entry {
	uint64_t	vae_timestamp;		/* Unix timestamp */
	uint32_t	vae_type;		/* Event type */
	uint32_t	vae_operation;		/* Operation bitmask */
	int32_t		vae_result;		/* 0=allowed, errno=denied */
	int32_t		vae_pid;		/* Process ID */
	uint32_t	vae_uid;		/* User ID */
	int32_t		vae_jailid;		/* Jail ID (0 = host) */
	char		vae_subject_label[VLABEL_AUDIT_LABEL_LEN];
	char		vae_object_label[VLABEL_AUDIT_LABEL_LEN];
	char		vae_path[VLABEL_AUDIT_PATH_LEN];
};

/*
 * Pattern I/O structure for ioctl (userland-kernel interface)
 *
 * Patterns are now simple strings that match against label strings.
 * Pattern format: "key1=value1,key2=value2,..."
 *
 * Matching rules:
 *   - "*" matches any label (wildcard)
 *   - "key=value" requires label to have that exact key=value
 *   - "key=*" requires key to exist with any value
 *   - Multiple pairs: ALL must match (AND logic)
 *   - Prefix "!" negates the entire pattern
 *
 * Examples:
 *   "*"                          - matches anything
 *   "type=app"                   - label must have type=app
 *   "type=app,domain=web"        - must have both
 *   "sensitivity=*"              - must have sensitivity key (any value)
 *   "!type=untrusted"            - must NOT have type=untrusted
 */
struct vlabel_pattern_io {
	uint32_t	vp_flags;			/* VLABEL_MATCH_NEGATE, etc */
	char		vp_pattern[VLABEL_MAX_LABEL_LEN]; /* Pattern string */
};

/*
 * Context I/O structure for userland-kernel interface
 */
struct vlabel_context_io {
	uint32_t	vc_flags;		/* Which checks are enabled */
	uint8_t		vc_cap_sandboxed;	/* true=must be sandboxed */
	uint8_t		vc_has_tty;		/* true=must have tty */
	uint8_t		vc_padding[2];
	int32_t		vc_jail_check;		/* 0=host, >0=jail id, -1=any jail */
	uint32_t	vc_uid;			/* Required UID */
	uint32_t	vc_gid;			/* Required GID */
};

struct vlabel_rule_io {
	uint32_t		vr_id;
	uint8_t			vr_action;
	uint8_t			vr_padding[3];
	uint32_t		vr_operations;
	struct vlabel_pattern_io vr_subject;
	struct vlabel_pattern_io vr_object;
	struct vlabel_context_io vr_context;	/* Context constraints */
	char			vr_newlabel[VLABEL_MAX_LABEL_LEN];  /* For TRANSITION */
};

/*
 * ioctl commands for /dev/vlabel (shared with userland)
 */
#define VLABEL_IOC_GETMODE	_IOR('V', 1, int)
#define VLABEL_IOC_SETMODE	_IOW('V', 2, int)
#define VLABEL_IOC_GETSTATS	_IOR('V', 5, struct vlabel_stats)
#define VLABEL_IOC_SETAUDIT	_IOW('V', 6, int)

/* Rule management */
#define VLABEL_IOC_RULE_ADD	_IOW('V', 10, struct vlabel_rule_io)
#define VLABEL_IOC_RULE_REMOVE	_IOW('V', 11, uint32_t)
#define VLABEL_IOC_RULES_CLEAR	_IO('V', 12)
#define VLABEL_IOC_RULE_LIST	_IOWR('V', 13, struct vlabel_rule_list_io)
#define VLABEL_IOC_GETAUDIT	_IOR('V', 14, int)
#define VLABEL_IOC_TEST_ACCESS	_IOWR('V', 15, struct vlabel_test_io)
#define VLABEL_IOC_GETDEFPOL	_IOR('V', 16, int)
#define VLABEL_IOC_SETDEFPOL	_IOW('V', 17, int)

/*
 * Rule list I/O structure - for listing all rules
 *
 * Usage:
 *   1. Allocate buffer for vrl_count rules
 *   2. Set vrl_rules to point to buffer
 *   3. Set vrl_count to buffer capacity
 *   4. Set vrl_offset for pagination (usually 0)
 *   5. Call ioctl - kernel copies rules via copyout()
 *   6. vrl_count updated to actual rules copied
 *   7. vrl_total contains total rules in kernel
 */
struct vlabel_rule_list_io {
	uint32_t		vrl_count;	/* In: max rules, Out: actual count */
	uint32_t		vrl_total;	/* Out: total rules in kernel */
	uint32_t		vrl_offset;	/* In: starting offset for pagination */
	uint32_t		vrl_reserved;
	struct vlabel_rule_io	*vrl_rules;	/* In: userland buffer for rules */
};

/*
 * Test access I/O structure - for testing policy without enforcement
 */
struct vlabel_test_io {
	char		vt_subject_label[VLABEL_MAX_LABEL_LEN];	/* Subject label */
	char		vt_object_label[VLABEL_MAX_LABEL_LEN];	/* Object label */
	uint32_t	vt_operation;				/* Operation to test */
	uint32_t	vt_result;				/* Out: 0=allow, EACCES=deny */
	uint32_t	vt_rule_id;				/* Out: matching rule ID (0=default) */
	uint32_t	vt_reserved;
};

#ifdef _KERNEL

#include <sys/types.h>

/*
 * Key-value pair for parsed labels
 */
struct vlabel_pair {
	char		vp_key[VLABEL_MAX_KEY_LEN];
	char		vp_value[VLABEL_MAX_VALUE_LEN];
};

/*
 * Label structure - stored in MAC label slot
 *
 * Labels are stored as raw strings and parsed into key-value pairs.
 * The raw string is authoritative; pairs are for fast matching.
 *
 * Example: "type=app,domain=web,sensitivity=secret"
 * Parses to: pairs[0]={type,app}, pairs[1]={domain,web}, pairs[2]={sensitivity,secret}
 */
struct vlabel_label {
	char			vl_raw[VLABEL_MAX_LABEL_LEN];	/* Original string */
	uint32_t		vl_hash;			/* Quick compare hash */
	uint32_t		vl_npairs;			/* Number of valid pairs */
	struct vlabel_pair	vl_pairs[VLABEL_MAX_PAIRS];	/* Parsed key=value pairs */
};

/*
 * Pattern for matching labels in rules
 *
 * Patterns are also stored as key=value pairs. A label matches a pattern
 * if ALL pairs in the pattern exist in the label with matching values.
 * Value "*" is a wildcard that matches any value for that key.
 *
 * Examples:
 *   Pattern "type=app,domain=web" matches label "type=app,domain=web,level=high"
 *   Pattern "type=*" matches any label that has a "type" key
 *   Pattern "" (empty) matches any label (wildcard)
 */
struct vlabel_pattern {
	uint32_t		vp_flags;			/* VLABEL_MATCH_NEGATE, etc */
	uint32_t		vp_npairs;			/* Number of pairs to match */
	struct vlabel_pair	vp_pairs[VLABEL_MAX_PAIRS];	/* Pairs to match */
};

/*
 * Context constraints for rules
 *
 * vc_jail_check interpretation:
 *   0  = must be on host (not in a jail)
 *   >0 = must be in specific jail with this ID
 *   -1 = must be in any jail (not host)
 *   -2 = don't check jail (wildcard) - only valid if VLABEL_CTX_JAIL not set
 */
struct vlabel_context {
	uint32_t	vc_flags;		/* Which checks are enabled */
	bool		vc_cap_sandboxed;	/* true=must be sandboxed, false=must not */
	bool		vc_has_tty;		/* true=must have tty, false=must not */
	int		vc_jail_check;		/* See above */
	uid_t		vc_uid;			/* Required UID (for UID/RUID checks) */
	gid_t		vc_gid;			/* Required GID */
};

/*
 * Access control rule
 */
struct vlabel_rule {
	uint32_t		vr_id;		/* Rule identifier */
	uint8_t			vr_action;	/* ALLOW, DENY, or TRANSITION */
	uint32_t		vr_operations;	/* Bitmask of operations */
	struct vlabel_pattern	vr_subject;	/* Subject (process) pattern */
	struct vlabel_pattern	vr_object;	/* Object (file) pattern */
	struct vlabel_context	vr_context;	/* Optional context constraints */
	struct vlabel_label	vr_newlabel;	/* New label for TRANSITION rules */
};

/*
 * Slot accessor macro - retrieves our label from a MAC label structure
 *
 * IMPORTANT: Always NULL-check the result before use!
 */
extern int vlabel_slot;

#define SLOT(l)		((struct vlabel_label *)mac_label_get((l), vlabel_slot))
#define SLOT_SET(l, v)	mac_label_set((l), vlabel_slot, (intptr_t)(v))

/*
 * Default labels for unlabeled objects/subjects
 */
extern struct vlabel_label vlabel_default_object;
extern struct vlabel_label vlabel_default_subject;

/*
 * Global configuration (exposed via sysctl)
 *
 * Note: sysctl provides synchronization. For check paths,
 * stale reads are acceptable as mode changes propagate quickly.
 */
extern int vlabel_enabled;
extern int vlabel_mode;
extern int vlabel_audit_level;
extern int vlabel_initialized;
extern int vlabel_default_policy;	/* 0=allow, 1=deny when no rule matches */

/*
 * Debug output macro
 */
#ifdef VLABEL_DEBUG
#define VLABEL_DPRINTF(fmt, ...)					\
	printf("vlabel: " fmt "\n", ##__VA_ARGS__)
#else
#define VLABEL_DPRINTF(fmt, ...)	do { } while (0)
#endif

/*
 * Common check macro - early exit if disabled or not initialized
 */
#define VLABEL_CHECK_ENABLED()	do {					\
	if (!vlabel_initialized ||					\
	    vlabel_enabled == 0 || vlabel_mode == VLABEL_MODE_DISABLED)	\
		return (0);						\
} while (0)

/*
 * Function prototypes - vlabel_label.c
 */
void vlabel_label_init(void);
void vlabel_label_destroy(void);
struct vlabel_label *vlabel_label_alloc(int flags);
void vlabel_label_free(struct vlabel_label *vl);
int vlabel_label_parse(const char *str, size_t len, struct vlabel_label *out);
void vlabel_label_copy(const struct vlabel_label *src, struct vlabel_label *dst);
void vlabel_label_set_default(struct vlabel_label *vl, bool is_subject);
const char *vlabel_label_get_value(const struct vlabel_label *vl, const char *key);
bool vlabel_label_match(const struct vlabel_label *label,
    const struct vlabel_pattern *pattern);
uint32_t vlabel_label_hash(const char *str, size_t len);
int vlabel_label_to_string(const struct vlabel_label *vl, char *buf, size_t buflen);
int vlabel_pattern_parse(const char *str, size_t len, struct vlabel_pattern *pattern);

/*
 * Function prototypes - vlabel_rules.c
 */
void vlabel_rules_init(void);
void vlabel_rules_destroy(void);
int vlabel_rules_check(struct ucred *cred, struct vlabel_label *subj,
    struct vlabel_label *obj, uint32_t op);
bool vlabel_rules_will_transition(struct ucred *cred, struct vlabel_label *subj,
    struct vlabel_label *obj);
int vlabel_rules_get_transition(struct ucred *cred, struct vlabel_label *subj,
    struct vlabel_label *obj, struct vlabel_label *newlabel);
int vlabel_rule_add(struct vlabel_rule *rule);
int vlabel_rule_remove(uint32_t id);
void vlabel_rules_clear(void);
void vlabel_rules_get_stats(struct vlabel_stats *stats);
int vlabel_rules_list(struct vlabel_rule_list_io *list_io,
    struct vlabel_rule_io *rules_out, uint32_t max_rules);
int vlabel_rules_test_access(struct vlabel_test_io *test_io);

/*
 * Function prototypes - vlabel_dev.c
 */
void vlabel_dev_init(void);
void vlabel_dev_destroy(void);
bool vlabel_dev_in_use(void);

/*
 * Function prototypes - vlabel_cred.c
 */
void vlabel_cred_init_label(struct label *label);
void vlabel_cred_destroy_label(struct label *label);
void vlabel_cred_copy_label(struct label *src, struct label *dest);
void vlabel_cred_relabel(struct ucred *cred, struct label *newlabel);
int vlabel_cred_externalize_label(struct label *label, char *element_name,
    struct sbuf *sb, int *claimed);
int vlabel_cred_internalize_label(struct label *label, char *element_name,
    char *element_data, int *claimed);
int vlabel_cred_check_relabel(struct ucred *cred, struct label *newlabel);
int vlabel_cred_check_setuid(struct ucred *cred, uid_t uid);
int vlabel_cred_check_setgid(struct ucred *cred, gid_t gid);
int vlabel_cred_check_setgroups(struct ucred *cred, int ngroups, gid_t *gidset);
void vlabel_execve_transition(struct ucred *old, struct ucred *new,
    struct vnode *vp, struct label *vplabel, struct label *interpvplabel,
    struct image_params *imgp, struct label *execlabel);
int vlabel_execve_will_transition(struct ucred *old, struct vnode *vp,
    struct label *vplabel, struct label *interpvplabel,
    struct image_params *imgp, struct label *execlabel);

/*
 * Function prototypes - vlabel_vnode.c
 */
void vlabel_vnode_init_label(struct label *label);
void vlabel_vnode_destroy_label(struct label *label);
void vlabel_vnode_copy_label(struct label *src, struct label *dest);
int vlabel_vnode_associate_extattr(struct mount *mp, struct label *mplabel,
    struct vnode *vp, struct label *vplabel);
int vlabel_vnode_create_extattr(struct ucred *cred, struct mount *mp,
    struct label *mplabel, struct vnode *dvp, struct label *dvplabel,
    struct vnode *vp, struct label *vplabel, struct componentname *cnp);
int vlabel_vnode_setlabel_extattr(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, struct label *intlabel);
void vlabel_vnode_relabel(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, struct label *newlabel);
int vlabel_vnode_externalize_label(struct label *label, char *element_name,
    struct sbuf *sb, int *claimed);
int vlabel_vnode_internalize_label(struct label *label, char *element_name,
    char *element_data, int *claimed);
int vlabel_vnode_check_access(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, accmode_t accmode);
int vlabel_vnode_check_chdir(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel);
int vlabel_vnode_check_chroot(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel);
int vlabel_vnode_check_create(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct componentname *cnp, struct vattr *vap);
int vlabel_vnode_check_deleteacl(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, acl_type_t type);
int vlabel_vnode_check_deleteextattr(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, int attrnamespace, const char *name);
int vlabel_vnode_check_exec(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, struct image_params *imgp, struct label *execlabel);
int vlabel_vnode_check_getacl(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, acl_type_t type);
int vlabel_vnode_check_getextattr(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, int attrnamespace, const char *name);
int vlabel_vnode_check_link(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct vnode *vp, struct label *vplabel,
    struct componentname *cnp);
int vlabel_vnode_check_listextattr(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, int attrnamespace);
int vlabel_vnode_check_lookup(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct componentname *cnp);
int vlabel_vnode_check_mmap(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, int prot, int flags);
int vlabel_vnode_check_open(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, accmode_t accmode);
int vlabel_vnode_check_poll(struct ucred *active_cred, struct ucred *file_cred,
    struct vnode *vp, struct label *vplabel);
int vlabel_vnode_check_read(struct ucred *active_cred, struct ucred *file_cred,
    struct vnode *vp, struct label *vplabel);
int vlabel_vnode_check_readdir(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel);
int vlabel_vnode_check_readlink(struct ucred *cred, struct vnode *vp,
    struct label *vplabel);
int vlabel_vnode_check_relabel(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, struct label *newlabel);
int vlabel_vnode_check_rename_from(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct vnode *vp, struct label *vplabel,
    struct componentname *cnp);
int vlabel_vnode_check_rename_to(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct vnode *vp, struct label *vplabel,
    int samedir, struct componentname *cnp);
int vlabel_vnode_check_revoke(struct ucred *cred, struct vnode *vp,
    struct label *vplabel);
int vlabel_vnode_check_setacl(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, acl_type_t type, struct acl *acl);
int vlabel_vnode_check_setextattr(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, int attrnamespace, const char *name);
int vlabel_vnode_check_setflags(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, u_long flags);
int vlabel_vnode_check_setmode(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, mode_t mode);
int vlabel_vnode_check_setowner(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, uid_t uid, gid_t gid);
int vlabel_vnode_check_setutimes(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, struct timespec atime, struct timespec mtime);
int vlabel_vnode_check_stat(struct ucred *active_cred, struct ucred *file_cred,
    struct vnode *vp, struct label *vplabel);
int vlabel_vnode_check_unlink(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct vnode *vp, struct label *vplabel,
    struct componentname *cnp);
int vlabel_vnode_check_write(struct ucred *active_cred, struct ucred *file_cred,
    struct vnode *vp, struct label *vplabel);
void vlabel_mount_init_label(struct label *label);
void vlabel_mount_destroy_label(struct label *label);

/*
 * Function prototypes - vlabel_proc.c
 */
int vlabel_proc_check_debug(struct ucred *cred, struct proc *p);
int vlabel_proc_check_sched(struct ucred *cred, struct proc *p);
int vlabel_proc_check_signal(struct ucred *cred, struct proc *p, int signum);
int vlabel_priv_grant(struct ucred *cred, int priv);

/*
 * Function prototypes - vlabel_audit.c
 */
void vlabel_audit_init(void);
void vlabel_audit_destroy(void);
void vlabel_audit_log(uint32_t event_type, struct ucred *cred,
    struct vnode *vp, uint32_t operation, int result);
int vlabel_audit_read(struct uio *uio, int ioflag);
int vlabel_audit_poll(int events, struct thread *td);
u_int vlabel_audit_count(void);

#endif /* _KERNEL */

#endif /* !_SECURITY_MAC_VLABEL_H_ */
