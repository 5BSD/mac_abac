/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 vLabel Project
 *
 * Simple C test program for vLabel ioctls
 * Compile on VM: cc -o test_ioctl test_ioctl.c
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

/* Must match kernel mac_vlabel.h */
#define VLABEL_MAX_VALUE_LEN    64

#define VLABEL_OP_EXEC          0x00000001
#define VLABEL_OP_READ          0x00000002
#define VLABEL_OP_WRITE         0x00000004

#define VLABEL_ACTION_ALLOW     0
#define VLABEL_ACTION_DENY      1
#define VLABEL_ACTION_TRANSITION 2

#define VLABEL_MAX_LABEL_LEN    256

#define VLABEL_MATCH_TYPE       0x00000001

struct vlabel_stats {
    uint64_t    vs_checks;
    uint64_t    vs_allowed;
    uint64_t    vs_denied;
    uint64_t    vs_labels_read;
    uint64_t    vs_labels_default;
    uint32_t    vs_rule_count;
};

struct vlabel_pattern_io {
    uint32_t    vp_flags;
    char        vp_type[VLABEL_MAX_VALUE_LEN];
    char        vp_domain[VLABEL_MAX_VALUE_LEN];
    char        vp_name[VLABEL_MAX_VALUE_LEN];
    char        vp_level[VLABEL_MAX_VALUE_LEN];
};

struct vlabel_rule_io {
    uint32_t                    vr_id;
    uint8_t                     vr_action;
    uint8_t                     vr_padding[3];
    uint32_t                    vr_operations;
    struct vlabel_pattern_io    vr_subject;
    struct vlabel_pattern_io    vr_object;
    char                        vr_newlabel[VLABEL_MAX_LABEL_LEN];  /* For TRANSITION */
};

/* ioctl commands - must match kernel */
#define VLABEL_IOC_GETMODE      _IOR('V', 1, int)
#define VLABEL_IOC_SETMODE      _IOW('V', 2, int)
#define VLABEL_IOC_GETSTATS     _IOR('V', 5, struct vlabel_stats)
#define VLABEL_IOC_SETAUDIT     _IOW('V', 6, int)
#define VLABEL_IOC_RULE_ADD     _IOW('V', 10, struct vlabel_rule_io)
#define VLABEL_IOC_RULE_REMOVE  _IOW('V', 11, uint32_t)
#define VLABEL_IOC_RULES_CLEAR  _IO('V', 12)

void print_stats(struct vlabel_stats *stats)
{
    printf("Stats:\n");
    printf("  checks:     %lu\n", (unsigned long)stats->vs_checks);
    printf("  allowed:    %lu\n", (unsigned long)stats->vs_allowed);
    printf("  denied:     %lu\n", (unsigned long)stats->vs_denied);
    printf("  labels_read: %lu\n", (unsigned long)stats->vs_labels_read);
    printf("  rule_count: %u\n", stats->vs_rule_count);
}

int main(int argc, char *argv[])
{
    int fd, mode, ret;
    struct vlabel_stats stats;
    struct vlabel_rule_io rule;
    uint32_t rule_id;

    fd = open("/dev/vlabel", O_RDWR);
    if (fd < 0) {
        perror("open /dev/vlabel");
        return 1;
    }

    printf("=== vLabel ioctl test ===\n\n");

    /* Test GETMODE */
    printf("1. Testing GETMODE...\n");
    if (ioctl(fd, VLABEL_IOC_GETMODE, &mode) < 0) {
        perror("   GETMODE failed");
    } else {
        printf("   Current mode: %d\n", mode);
    }

    /* Test GETSTATS */
    printf("\n2. Testing GETSTATS...\n");
    memset(&stats, 0, sizeof(stats));
    if (ioctl(fd, VLABEL_IOC_GETSTATS, &stats) < 0) {
        perror("   GETSTATS failed");
    } else {
        print_stats(&stats);
    }

    /* Test RULE_ADD */
    printf("\n3. Testing RULE_ADD (id=100, allow read type=trusted)...\n");
    memset(&rule, 0, sizeof(rule));
    rule.vr_id = 100;
    rule.vr_action = VLABEL_ACTION_ALLOW;
    rule.vr_operations = VLABEL_OP_READ;
    /* Subject: wildcard (flags=0) */
    rule.vr_subject.vp_flags = 0;
    /* Object: match type=trusted */
    rule.vr_object.vp_flags = VLABEL_MATCH_TYPE;
    strlcpy(rule.vr_object.vp_type, "trusted", sizeof(rule.vr_object.vp_type));

    if (ioctl(fd, VLABEL_IOC_RULE_ADD, &rule) < 0) {
        perror("   RULE_ADD failed");
    } else {
        printf("   Rule 100 added successfully\n");
    }

    /* Test GETSTATS again to see rule count */
    printf("\n4. Testing GETSTATS after rule add...\n");
    memset(&stats, 0, sizeof(stats));
    if (ioctl(fd, VLABEL_IOC_GETSTATS, &stats) < 0) {
        perror("   GETSTATS failed");
    } else {
        print_stats(&stats);
    }

    /* Test RULE_ADD another rule */
    printf("\n5. Testing RULE_ADD (id=101, deny exec type=malware)...\n");
    memset(&rule, 0, sizeof(rule));
    rule.vr_id = 101;
    rule.vr_action = VLABEL_ACTION_DENY;
    rule.vr_operations = VLABEL_OP_EXEC;
    rule.vr_subject.vp_flags = 0;
    rule.vr_object.vp_flags = VLABEL_MATCH_TYPE;
    strlcpy(rule.vr_object.vp_type, "malware", sizeof(rule.vr_object.vp_type));

    if (ioctl(fd, VLABEL_IOC_RULE_ADD, &rule) < 0) {
        perror("   RULE_ADD failed");
    } else {
        printf("   Rule 101 added successfully\n");
    }

    /* Test RULE_REMOVE */
    printf("\n6. Testing RULE_REMOVE (id=100)...\n");
    rule_id = 100;
    if (ioctl(fd, VLABEL_IOC_RULE_REMOVE, &rule_id) < 0) {
        perror("   RULE_REMOVE failed");
    } else {
        printf("   Rule 100 removed successfully\n");
    }

    /* Final stats */
    printf("\n7. Final GETSTATS...\n");
    memset(&stats, 0, sizeof(stats));
    if (ioctl(fd, VLABEL_IOC_GETSTATS, &stats) < 0) {
        perror("   GETSTATS failed");
    } else {
        print_stats(&stats);
    }

    /* Test RULES_CLEAR */
    printf("\n8. Testing RULES_CLEAR...\n");
    if (ioctl(fd, VLABEL_IOC_RULES_CLEAR) < 0) {
        perror("   RULES_CLEAR failed");
    } else {
        printf("   All rules cleared\n");
    }

    /* Stats after clear */
    printf("\n9. GETSTATS after clear...\n");
    memset(&stats, 0, sizeof(stats));
    if (ioctl(fd, VLABEL_IOC_GETSTATS, &stats) < 0) {
        perror("   GETSTATS failed");
    } else {
        print_stats(&stats);
    }

    close(fd);
    printf("\n=== Test complete ===\n");
    return 0;
}
