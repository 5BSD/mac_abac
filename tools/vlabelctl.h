/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 vLabel Project
 * All rights reserved.
 *
 * vlabelctl - Internal header for shared declarations
 */

#ifndef VLABELCTL_H
#define VLABELCTL_H

#include <sys/types.h>
#include <stdint.h>

#define VLABEL_POLICY_NAME	"mac_vlabel"

/*
 * Shared utility functions (vlabelctl.c)
 */
int vlabel_syscall(int cmd, void *arg);
char *convert_label_format(const char *input);
const char *ops_to_string(uint32_t ops, char *buf, size_t buflen);
const char *get_extattr_name(void);
void usage(void);

/*
 * Command handlers
 */
int cmd_mode(int argc, char *argv[]);
int cmd_default(int argc, char *argv[]);
int cmd_stats(int argc, char *argv[]);
int cmd_status(int argc, char *argv[]);
int cmd_limits(int argc, char *argv[]);

/* vlabelctl_rule.c */
int cmd_rule(int argc, char *argv[]);

/* vlabelctl_label.c */
int cmd_label(int argc, char *argv[]);
int cmd_test(int argc, char *argv[]);

/* vlabelctl_set.c */
int cmd_set(int argc, char *argv[]);

#endif /* VLABELCTL_H */
