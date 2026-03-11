/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 vLabel Project
 * All rights reserved.
 */

#ifndef _VLABELD_H_
#define _VLABELD_H_

#include <stdbool.h>
#include <stdint.h>

/*
 * Include the shared kernel/userland header for mac_syscall definitions
 */
#include "../kernel/mac_vlabel.h"

/*
 * Default paths
 */
#define VLABELD_DEFAULT_CONFIG	"/usr/local/etc/vlabel/policy.conf"
#define VLABELD_DEFAULT_PIDFILE	"/var/run/vlabeld.pid"

/*
 * Policy name for mac_syscall
 */
#define VLABEL_POLICY_NAME	"mac_vlabel"

/*
 * Daemon configuration
 */
struct vlabeld_config {
	const char	*config_file;
	const char	*pidfile;
	bool		daemonize;
	bool		verbose;
	bool		test_mode;
};

/*
 * Logging function (vlabeld.c)
 */
void vlabeld_log(int priority, const char *fmt, ...);

/*
 * Kernel communication functions (vlabeld.c)
 */
int vlabeld_add_rule(struct vlabel_rule_io *rule);
int vlabeld_clear_rules(void);
int vlabeld_set_mode(int mode);
int vlabeld_set_default_policy(int policy);

/*
 * Policy parsing functions (parse_ucl.c)
 *
 * vlabeld_parse_ucl_check_append: Parse and check if append mode is set
 *   Returns: 0 = success (no append), 1 = success (append mode), -1 = error
 *
 * vlabeld_parse_ucl: Parse and load rules (legacy interface)
 */
int vlabeld_parse_ucl(const char *path, bool verbose);
int vlabeld_parse_ucl_check_append(const char *path, bool verbose, bool *append_mode);

/*
 * Line format parsing (parse_line.c)
 */
int vlabeld_parse_line(const char *line, struct vlabel_rule_io *rule);

/*
 * Callback type for rule iteration during UCL parsing
 * Return 0 to continue, non-zero to stop parsing
 */
typedef int (*vlabel_rule_callback_t)(struct vlabel_rule_io *rule, void *ctx);

/*
 * Parse UCL file and call callback for each rule (parse_ucl.c)
 * Used by vlabelctl for building packed rule buffers
 */
int vlabeld_parse_ucl_with_callback(const char *path, bool verbose,
    vlabel_rule_callback_t callback, void *ctx);

#endif /* !_VLABELD_H_ */
