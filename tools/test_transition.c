/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 vLabel Project
 *
 * Test program for label transitions on exec
 * Compile on VM: cc -o test_transition test_transition.c
 *
 * Usage: ./test_transition
 *
 * This test:
 * 1. Adds a TRANSITION rule for type=privileged-helper
 * 2. Forks and execs /root/test_privileged_helper
 * 3. The child should have a new label after exec
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

/* Must match kernel mac_vlabel.h */
#define VLABEL_MAX_VALUE_LEN    64
#define VLABEL_MAX_LABEL_LEN    256

#define VLABEL_OP_EXEC          0x00000001

#define VLABEL_ACTION_ALLOW     0
#define VLABEL_ACTION_DENY      1
#define VLABEL_ACTION_TRANSITION 2

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
    char                        vr_newlabel[VLABEL_MAX_LABEL_LEN];
};

/* ioctl commands - must match kernel */
#define VLABEL_IOC_GETMODE      _IOR('V', 1, int)
#define VLABEL_IOC_GETSTATS     _IOR('V', 5, struct vlabel_stats)
#define VLABEL_IOC_RULE_ADD     _IOW('V', 10, struct vlabel_rule_io)
#define VLABEL_IOC_RULE_REMOVE  _IOW('V', 11, uint32_t)

/*
 * Helper to read current process label via mac_get_proc (if available)
 * For now, we just check dmesg output for transition messages
 */

int main(int argc, char *argv[])
{
    int fd, ret, status;
    struct vlabel_rule_io rule;
    uint32_t rule_id;
    pid_t pid;

    printf("=== vLabel Transition Test ===\n\n");

    fd = open("/dev/vlabel", O_RDWR);
    if (fd < 0) {
        perror("open /dev/vlabel");
        return 1;
    }

    /* Add a TRANSITION rule:
     * When any subject executes type=privileged-helper,
     * transition to type=privileged,domain=elevated
     */
    printf("1. Adding TRANSITION rule (id=200)...\n");
    printf("   Subject: any\n");
    printf("   Object: type=privileged-helper\n");
    printf("   New label: type=privileged,domain=elevated\n\n");

    memset(&rule, 0, sizeof(rule));
    rule.vr_id = 200;
    rule.vr_action = VLABEL_ACTION_TRANSITION;
    rule.vr_operations = VLABEL_OP_EXEC;
    /* Subject: wildcard (flags=0) */
    rule.vr_subject.vp_flags = 0;
    /* Object: match type=privileged-helper */
    rule.vr_object.vp_flags = VLABEL_MATCH_TYPE;
    strlcpy(rule.vr_object.vp_type, "privileged-helper",
        sizeof(rule.vr_object.vp_type));
    /* New label for the transitioned process */
    strlcpy(rule.vr_newlabel, "type=privileged,domain=elevated",
        sizeof(rule.vr_newlabel));

    if (ioctl(fd, VLABEL_IOC_RULE_ADD, &rule) < 0) {
        perror("   RULE_ADD failed");
        close(fd);
        return 1;
    }
    printf("   Rule added successfully\n\n");

    /* Fork and exec the privileged helper */
    printf("2. Forking and executing /root/test_privileged_helper...\n");
    printf("   (Check dmesg for transition messages)\n\n");

    pid = fork();
    if (pid < 0) {
        perror("fork");
        goto cleanup;
    }

    if (pid == 0) {
        /* Child process - exec the privileged helper */
        execl("/root/test_privileged_helper", "test_privileged_helper",
            "transition test output", NULL);
        perror("execl failed");
        _exit(127);
    }

    /* Parent - wait for child */
    waitpid(pid, &status, 0);
    printf("   Child exited with status: %d\n\n", WEXITSTATUS(status));

    /* Show stats */
    printf("3. Checking stats...\n");
    struct vlabel_stats stats;
    if (ioctl(fd, VLABEL_IOC_GETSTATS, &stats) == 0) {
        printf("   checks: %lu, allowed: %lu, denied: %lu\n",
            (unsigned long)stats.vs_checks,
            (unsigned long)stats.vs_allowed,
            (unsigned long)stats.vs_denied);
    }

cleanup:
    /* Remove our test rule */
    printf("\n4. Removing test rule...\n");
    rule_id = 200;
    if (ioctl(fd, VLABEL_IOC_RULE_REMOVE, &rule_id) < 0) {
        perror("   RULE_REMOVE failed");
    } else {
        printf("   Rule removed\n");
    }

    close(fd);

    printf("\n=== Check dmesg for transition output ===\n");
    printf("Run: dmesg | grep -i vlabel | tail -20\n\n");

    return 0;
}
