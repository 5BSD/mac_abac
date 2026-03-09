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
 * Label constraints
 *
 * Labels are stored as newline-separated key=value pairs in extended attributes:
 *   "key1=val1\nkey2=val2\n"
 *
 * Patterns (in rules) use comma-separated format for command-line convenience:
 *   "key1=val1,key2=val2"
 *
 * VLABEL_MAX_LABEL_LEN: Soft limit for labels stored in extattrs.
 *   - Extended attributes have filesystem-specific limits
 *   - UFS/ZFS typically support 64KB+ but we use a reasonable default
 *   - This is NOT a hard limit for syscall structures (those use variable length)
 *
 * VLABEL_MAX_PAIRS: Maximum number of key=value pairs per label.
 *   - Kernel parsing limit for in-memory label structures
 *   - Keep reasonable to avoid excessive memory per label
 */
#define VLABEL_MAX_LABEL_LEN		4096	/* Soft limit for extattr labels */
#define VLABEL_MAX_KEY_LEN		64	/* Max key length */
#define VLABEL_MAX_VALUE_LEN		256	/* Max value length */
#define VLABEL_MAX_PAIRS		16	/* Max key=value pairs per label */

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
 * Legacy structures for daemon rule parser
 *
 * These structures use fixed-size arrays for compatibility with the
 * existing parser code. The syscall API uses variable-length data,
 * so vlabelctl converts between formats.
 */
#define VLABEL_PATTERN_MAX_LEN	256	/* Max pattern string for parsing */

struct vlabel_pattern_io {
	uint32_t	vp_flags;
	char		vp_pattern[VLABEL_PATTERN_MAX_LEN];
};

struct vlabel_context_io {
	uint32_t	vc_flags;
	uint8_t		vc_cap_sandboxed;
	uint8_t		vc_has_tty;
	uint8_t		vc_padding[2];
	int32_t		vc_jail_check;
	uint32_t	vc_uid;
	uint32_t	vc_gid;
};

struct vlabel_rule_io {
	uint32_t		vr_id;
	uint8_t			vr_action;
	uint8_t			vr_padding[3];
	uint32_t		vr_operations;
	struct vlabel_pattern_io vr_subject;
	struct vlabel_pattern_io vr_object;
	struct vlabel_context_io vr_context;
	char			vr_newlabel[VLABEL_PATTERN_MAX_LEN];
};

/*
 * mac_syscall() command numbers
 *
 * Usage: mac_syscall("vlabel", VLABEL_SYS_*, arg)
 *
 * All commands require root (uid 0).
 */
#define VLABEL_SYS_GETMODE	1	/* arg: int* (out) */
#define VLABEL_SYS_SETMODE	2	/* arg: int* (in) */
#define VLABEL_SYS_GETSTATS	5	/* arg: struct vlabel_stats* (out) */
#define VLABEL_SYS_GETDEFPOL	6	/* arg: int* (out) */
#define VLABEL_SYS_SETDEFPOL	7	/* arg: int* (in) */

#define VLABEL_SYS_RULE_ADD	10	/* arg: struct vlabel_rule_arg* (in) */
#define VLABEL_SYS_RULE_REMOVE	11	/* arg: uint32_t* (in: rule_id) */
#define VLABEL_SYS_RULE_CLEAR	12	/* arg: NULL */
#define VLABEL_SYS_RULE_LIST	13	/* arg: struct vlabel_rule_list_arg* (in/out) */

#define VLABEL_SYS_TEST		20	/* arg: struct vlabel_test_arg* (in/out) */

/*
 * Context constraints for rules (shared between kernel and userland)
 */
struct vlabel_context_arg {
	uint32_t	vc_flags;		/* Which checks are enabled */
	uint8_t		vc_cap_sandboxed;	/* true=must be sandboxed */
	uint8_t		vc_has_tty;		/* true=must have tty */
	uint8_t		vc_padding[2];
	int32_t		vc_jail_check;		/* 0=host, >0=jail id, -1=any jail */
	uint32_t	vc_uid;			/* Required UID */
	uint32_t	vc_gid;			/* Required GID */
};

/*
 * Rule add argument - variable length strings
 *
 * Pattern format: "key1=value1,key2=value2,..."
 *   "*"           - matches anything
 *   "type=app"    - must have type=app
 *   "!type=bad"   - must NOT have type=bad
 *
 * Layout in memory:
 *   struct vlabel_rule_arg header
 *   char subject[vr_subject_len]   (null-terminated)
 *   char object[vr_object_len]     (null-terminated)
 *   char newlabel[vr_newlabel_len] (null-terminated, only for TRANSITION)
 */
struct vlabel_rule_arg {
	uint8_t			vr_action;	/* ALLOW/DENY/TRANSITION */
	uint8_t			vr_reserved[3];
	uint32_t		vr_operations;	/* Operation bitmask */
	uint32_t		vr_subject_flags; /* VLABEL_MATCH_NEGATE, etc */
	uint32_t		vr_object_flags;
	struct vlabel_context_arg vr_context;
	uint16_t		vr_subject_len;	/* Length including null */
	uint16_t		vr_object_len;
	uint16_t		vr_newlabel_len; /* 0 if not transition */
	uint16_t		vr_reserved2;
	/* Variable data follows: subject, object, newlabel */
};

/*
 * Rule output for listing - also variable length
 *
 * Same layout as vlabel_rule_arg but with rule ID
 */
struct vlabel_rule_out {
	uint32_t		vr_id;		/* Rule ID */
	uint8_t			vr_action;
	uint8_t			vr_reserved[3];
	uint32_t		vr_operations;
	uint32_t		vr_subject_flags;
	uint32_t		vr_object_flags;
	struct vlabel_context_arg vr_context;
	uint16_t		vr_subject_len;
	uint16_t		vr_object_len;
	uint16_t		vr_newlabel_len;
	uint16_t		vr_reserved2;
	/* Variable data follows */
};

/*
 * Rule list argument
 *
 * To list rules:
 *   1. Call with vrl_buf=NULL, vrl_buflen=0 to get vrl_total
 *   2. Allocate buffer of appropriate size
 *   3. Call again with buffer to get rules
 *
 * Rules are packed as vlabel_rule_out structures with variable data.
 */
struct vlabel_rule_list_arg {
	uint32_t	vrl_total;	/* Out: total rules in kernel */
	uint32_t	vrl_count;	/* Out: rules copied to buffer */
	uint32_t	vrl_offset;	/* In: starting offset */
	uint32_t	vrl_buflen;	/* In: buffer size */
	void		*vrl_buf;	/* In: buffer for rules (userland pointer) */
};

/*
 * Test access argument - variable length strings
 *
 * Layout:
 *   struct vlabel_test_arg header
 *   char subject[vt_subject_len]
 *   char object[vt_object_len]
 */
struct vlabel_test_arg {
	uint32_t	vt_operation;		/* Operation to test */
	uint32_t	vt_result;		/* Out: 0=allow, EACCES=deny */
	uint32_t	vt_rule_id;		/* Out: matching rule ID (0=default) */
	uint16_t	vt_subject_len;		/* Length including null */
	uint16_t	vt_object_len;
	/* Variable data follows: subject, object */
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
int vlabel_rule_add_from_arg(struct vlabel_rule_arg *arg, const char *data);
int vlabel_rule_remove(uint32_t id);
void vlabel_rules_clear(void);
void vlabel_rules_get_stats(struct vlabel_stats *stats);
int vlabel_rules_list(struct vlabel_rule_list_arg *list_arg);
int vlabel_rules_test_access(const char *subject, size_t subject_len,
    const char *object, size_t object_len, uint32_t operation,
    uint32_t *result, uint32_t *rule_id);

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

#endif /* _KERNEL */

#endif /* !_SECURITY_MAC_VLABEL_H_ */
