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
 */
#define VLABEL_MAX_LABEL_LEN		256	/* Maximum label string length */
#define VLABEL_MAX_KEY_LEN		32	/* Maximum key length */
#define VLABEL_MAX_VALUE_LEN		64	/* Maximum value length */
#define VLABEL_MAX_PAIRS		16	/* Maximum key=value pairs */

/*
 * Rule constraints
 */
#define VLABEL_MAX_RULES		1024	/* Maximum number of rules */

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
#define VLABEL_OP_ALL			0x0000FFFF

/*
 * Rule actions
 */
#define VLABEL_ACTION_ALLOW		0
#define VLABEL_ACTION_DENY		1

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
 */
#define VLABEL_MATCH_TYPE		0x00000001
#define VLABEL_MATCH_DOMAIN		0x00000002
#define VLABEL_MATCH_NAME		0x00000004
#define VLABEL_MATCH_LEVEL		0x00000008
#define VLABEL_MATCH_NEGATE		0x80000000	/* Invert match result */

#ifdef _KERNEL

#include <sys/types.h>

/*
 * Label structure - stored in MAC label slot
 *
 * This structure represents a parsed vLabel. The raw string is kept
 * for externalization, while parsed fields enable fast matching.
 */
struct vlabel_label {
	char		vl_raw[VLABEL_MAX_LABEL_LEN];	/* Original string */
	uint32_t	vl_hash;			/* Quick compare hash */
	char		vl_type[VLABEL_MAX_VALUE_LEN];	/* type= value */
	char		vl_domain[VLABEL_MAX_VALUE_LEN]; /* domain= value */
	char		vl_name[VLABEL_MAX_VALUE_LEN];	/* name= value */
	char		vl_level[VLABEL_MAX_VALUE_LEN];	/* level= value */
	uint32_t	vl_flags;			/* Which fields are set */
};

/*
 * Pattern for matching labels in rules
 */
struct vlabel_pattern {
	uint32_t	vp_flags;			/* Which fields to match */
	char		vp_type[VLABEL_MAX_VALUE_LEN];	/* NULL string = wildcard */
	char		vp_domain[VLABEL_MAX_VALUE_LEN];
	char		vp_name[VLABEL_MAX_VALUE_LEN];
	char		vp_level[VLABEL_MAX_VALUE_LEN];
};

/*
 * Context constraints for rules
 */
struct vlabel_context {
	uint32_t	vc_flags;		/* Which checks are enabled */
	bool		vc_cap_sandboxed;	/* Must/must not be sandboxed */
	int		vc_jail_check;		/* 0=host, >0=specific jail, -1=any jail */
	uid_t		vc_uid;			/* Required UID */
	gid_t		vc_gid;			/* Required GID */
};

/*
 * Access control rule
 */
struct vlabel_rule {
	uint32_t		vr_id;		/* Rule identifier */
	uint8_t			vr_action;	/* ALLOW or DENY */
	uint32_t		vr_operations;	/* Bitmask of operations */
	struct vlabel_pattern	vr_subject;	/* Subject (process) pattern */
	struct vlabel_pattern	vr_object;	/* Object (file) pattern */
	struct vlabel_context	vr_context;	/* Optional context constraints */
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
 */
extern int vlabel_enabled;
extern int vlabel_mode;
extern int vlabel_audit_level;

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
 * Common check macro - early exit if disabled
 */
#define VLABEL_CHECK_ENABLED()	do {					\
	if (vlabel_enabled == 0 || vlabel_mode == VLABEL_MODE_DISABLED)	\
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
bool vlabel_label_match(const struct vlabel_label *label,
    const struct vlabel_pattern *pattern);
uint32_t vlabel_label_hash(const char *str, size_t len);
int vlabel_label_to_string(const struct vlabel_label *vl, char *buf, size_t buflen);

/*
 * Function prototypes - vlabel_rules.c
 */
void vlabel_rules_init(void);
void vlabel_rules_destroy(void);
int vlabel_rules_check(struct ucred *cred, struct vlabel_label *subj,
    struct vlabel_label *obj, uint32_t op);
int vlabel_rule_add(struct vlabel_rule *rule);
int vlabel_rule_remove(uint32_t id);
void vlabel_rules_clear(void);

/*
 * Function prototypes - vlabel_dev.c
 */
void vlabel_dev_init(void);
void vlabel_dev_destroy(void);

/*
 * Function prototypes - vlabel_audit.c
 */
void vlabel_audit_init(void);
void vlabel_audit_destroy(void);
void vlabel_audit_log(uint32_t event_type, struct ucred *cred,
    struct vnode *vp, uint32_t operation, int result);

#endif /* _KERNEL */

/*
 * ioctl commands for /dev/vlabel (shared with userland)
 */
#define VLABEL_IOC_GETMODE	_IOR('V', 1, int)
#define VLABEL_IOC_SETMODE	_IOW('V', 2, int)
#define VLABEL_IOC_GETSTATS	_IOR('V', 5, struct vlabel_stats)
#define VLABEL_IOC_SETAUDIT	_IOW('V', 6, int)

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

#endif /* !_SECURITY_MAC_VLABEL_H_ */
