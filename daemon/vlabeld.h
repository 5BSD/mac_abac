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

/*
 * Policy parsing functions (parse_ucl.c)
 */
int vlabeld_parse_ucl(const char *path, bool verbose);

/*
 * Line format parsing (parse_line.c)
 */
int vlabeld_parse_line(const char *line, struct vlabel_rule_io *rule);

#endif /* !_VLABELD_H_ */
