/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 vLabel Project
 * All rights reserved.
 *
 * vLabel userland definitions
 *
 * This header provides the interface between userland and the
 * vLabel MACF kernel module via /dev/vlabel.
 */

#ifndef _CVLABEL_H_
#define _CVLABEL_H_

#include <sys/types.h>
#include <sys/ioccom.h>

/*
 * Label constraints (must match kernel mac_vlabel.h)
 */
#define VLABEL_MAX_LABEL_LEN        256
#define VLABEL_MAX_VALUE_LEN        64
#define VLABEL_MAX_RULES            1024

/*
 * Operations bitmask for rule matching
 */
#define VLABEL_OP_EXEC              0x00000001
#define VLABEL_OP_READ              0x00000002
#define VLABEL_OP_WRITE             0x00000004
#define VLABEL_OP_MMAP              0x00000008
#define VLABEL_OP_LINK              0x00000010
#define VLABEL_OP_RENAME            0x00000020
#define VLABEL_OP_UNLINK            0x00000040
#define VLABEL_OP_CHDIR             0x00000080
#define VLABEL_OP_STAT              0x00000100
#define VLABEL_OP_READDIR           0x00000200
#define VLABEL_OP_CREATE            0x00000400
#define VLABEL_OP_SETEXTATTR        0x00000800
#define VLABEL_OP_GETEXTATTR        0x00001000
#define VLABEL_OP_LOOKUP            0x00002000
#define VLABEL_OP_OPEN              0x00004000
#define VLABEL_OP_ACCESS            0x00008000
#define VLABEL_OP_ALL               0x0000FFFF

/*
 * Rule actions
 */
#define VLABEL_ACTION_ALLOW         0
#define VLABEL_ACTION_DENY          1

/*
 * Enforcement modes
 */
#define VLABEL_MODE_DISABLED        0
#define VLABEL_MODE_PERMISSIVE      1
#define VLABEL_MODE_ENFORCING       2

/*
 * Audit levels
 */
#define VLABEL_AUDIT_NONE           0
#define VLABEL_AUDIT_DENIALS        1
#define VLABEL_AUDIT_DECISIONS      2
#define VLABEL_AUDIT_VERBOSE        3

/*
 * Pattern match flags
 */
#define VLABEL_MATCH_TYPE           0x00000001
#define VLABEL_MATCH_DOMAIN         0x00000002
#define VLABEL_MATCH_NAME           0x00000004
#define VLABEL_MATCH_LEVEL          0x00000008
#define VLABEL_MATCH_NEGATE         0x80000000

/*
 * Statistics structure
 */
struct vlabel_stats {
    uint64_t    vs_checks;
    uint64_t    vs_allowed;
    uint64_t    vs_denied;
    uint64_t    vs_labels_read;
    uint64_t    vs_labels_default;
    uint32_t    vs_rule_count;
};

/*
 * Pattern I/O structure for ioctl (matches kernel vlabel_pattern_io)
 */
struct vlabel_pattern_io {
    uint32_t    vp_flags;
    char        vp_type[VLABEL_MAX_VALUE_LEN];
    char        vp_domain[VLABEL_MAX_VALUE_LEN];
    char        vp_name[VLABEL_MAX_VALUE_LEN];
    char        vp_level[VLABEL_MAX_VALUE_LEN];
};

/*
 * Rule I/O structure for ioctl (matches kernel vlabel_rule_io)
 */
struct vlabel_rule_io {
    uint32_t                    vr_id;
    uint8_t                     vr_action;
    uint8_t                     vr_padding[3];
    uint32_t                    vr_operations;
    struct vlabel_pattern_io    vr_subject;
    struct vlabel_pattern_io    vr_object;
};

/*
 * ioctl commands for /dev/vlabel
 *
 * Swift can't import _IOR/_IOW macros, so we provide constants.
 * These must match the kernel's mac_vlabel.h definitions.
 */

/* _IOR('V', 1, int) = 0x40045601 */
static const unsigned long VLABEL_IOC_GETMODE = 0x40045601;

/* _IOW('V', 2, int) = 0x80045602 */
static const unsigned long VLABEL_IOC_SETMODE = 0x80045602;

/* _IOR('V', 5, struct vlabel_stats) = 0x40305605 (sizeof vlabel_stats = 48) */
static const unsigned long VLABEL_IOC_GETSTATS = 0x40305605;

/* _IOW('V', 6, int) = 0x80045606 */
static const unsigned long VLABEL_IOC_SETAUDIT = 0x80045606;

/*
 * Rule management ioctls
 * vlabel_rule_io size = 4 + 1 + 3 + 4 + (4 + 64*4)*2 = 532 bytes
 * _IOW('V', 10, struct vlabel_rule_io) = 0x80000000 | (532 << 16) | ('V' << 8) | 10
 */
static const unsigned long VLABEL_IOC_RULE_ADD = 0x8214560a;

/* _IOW('V', 11, uint32_t) = 0x8004560b */
static const unsigned long VLABEL_IOC_RULE_REMOVE = 0x8004560b;

/* _IO('V', 12) = 0x2000560c */
static const unsigned long VLABEL_IOC_RULES_CLEAR = 0x2000560c;

/*
 * Helper functions for ioctl (Swift can't call variadic C functions)
 */
static inline int
vlabel_ioctl_int(int fd, unsigned long request, int *value)
{
    return ioctl(fd, request, value);
}

static inline int
vlabel_ioctl_stats(int fd, unsigned long request, struct vlabel_stats *stats)
{
    return ioctl(fd, request, stats);
}

static inline int
vlabel_ioctl_rule(int fd, unsigned long request, struct vlabel_rule_io *rule)
{
    return ioctl(fd, request, rule);
}

static inline int
vlabel_ioctl_uint32(int fd, unsigned long request, uint32_t *value)
{
    return ioctl(fd, request, value);
}

static inline int
vlabel_ioctl_void(int fd, unsigned long request)
{
    return ioctl(fd, request);
}

#endif /* !_CVLABEL_H_ */
