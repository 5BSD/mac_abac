/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 vLabel Project
 * All rights reserved.
 *
 * vlabeld - vLabel Policy Daemon
 *
 * Loads security policy from configuration files.
 * Uses mac_syscall() to communicate with the kernel module.
 * Supports UCL, JSON, and simple line-based policy formats.
 */

#include <sys/types.h>
#include <sys/mac.h>
#include <sys/time.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <libutil.h>
#include <paths.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <ucl.h>

#include "vlabeld.h"

/* Global state */
static struct vlabeld_config config;
static volatile sig_atomic_t reload_pending = 0;
static volatile sig_atomic_t shutdown_pending = 0;
static struct pidfh *pfh = NULL;

/* Forward declarations */
static void usage(void);
static void signal_handler(int sig);
static int setup_signals(void);
static int load_policy(const char *path);
static void main_loop(void);
static void cleanup(void);
static void daemonize(void);

/*
 * Wrapper for mac_syscall with error checking
 */
static int
vlabel_syscall(int cmd, void *arg)
{
	int error;

	error = mac_syscall(VLABEL_POLICY_NAME, cmd, arg);
	if (error < 0 && errno == ENOSYS) {
		vlabeld_log(LOG_ERR, "vLabel module not loaded");
		return (-1);
	}
	return (error);
}

/*
 * Logging wrapper - logs to syslog when daemonized, stderr otherwise
 */
void
vlabeld_log(int priority, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (config.daemonize) {
		vsyslog(priority, fmt, ap);
	} else {
		vfprintf(stderr, fmt, ap);
		fprintf(stderr, "\n");
	}
	va_end(ap);
}

static void
usage(void)
{
	fprintf(stderr,
	    "usage: vlabeld [-dfv] [-c config] [-p pidfile]\n"
	    "       vlabeld -t [-v] [-c config]\n"
	    "\n"
	    "Options:\n"
	    "  -c config   Policy configuration file (default: %s)\n"
	    "  -d          Debug mode (don't daemonize, verbose logging)\n"
	    "  -f          Run in foreground (don't daemonize)\n"
	    "  -p pidfile  PID file path (default: %s)\n"
	    "  -t          Test configuration and exit\n"
	    "  -v          Verbose output\n",
	    VLABELD_DEFAULT_CONFIG,
	    VLABELD_DEFAULT_PIDFILE);
	exit(1);
}

static void
signal_handler(int sig)
{
	switch (sig) {
	case SIGHUP:
		reload_pending = 1;
		break;
	case SIGINT:
	case SIGTERM:
		shutdown_pending = 1;
		break;
	}
}

static int
setup_signals(void)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = signal_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;

	if (sigaction(SIGHUP, &sa, NULL) < 0) {
		vlabeld_log(LOG_ERR, "sigaction(SIGHUP): %s", strerror(errno));
		return (-1);
	}
	if (sigaction(SIGINT, &sa, NULL) < 0) {
		vlabeld_log(LOG_ERR, "sigaction(SIGINT): %s", strerror(errno));
		return (-1);
	}
	if (sigaction(SIGTERM, &sa, NULL) < 0) {
		vlabeld_log(LOG_ERR, "sigaction(SIGTERM): %s", strerror(errno));
		return (-1);
	}

	/* Ignore SIGPIPE */
	sa.sa_handler = SIG_IGN;
	if (sigaction(SIGPIPE, &sa, NULL) < 0) {
		vlabeld_log(LOG_ERR, "sigaction(SIGPIPE): %s", strerror(errno));
		return (-1);
	}

	return (0);
}

/*
 * Clear all rules in the kernel
 */
int
vlabeld_clear_rules(void)
{
	/* In test mode, nothing to clear */
	if (config.test_mode)
		return (0);

	if (vlabel_syscall(VLABEL_SYS_RULE_CLEAR, NULL) < 0) {
		vlabeld_log(LOG_ERR, "RULE_CLEAR: %s", strerror(errno));
		return (-1);
	}

	if (config.verbose)
		vlabeld_log(LOG_DEBUG, "cleared all rules");

	return (0);
}

/*
 * Set enforcement mode
 */
int
vlabeld_set_mode(int mode)
{
	/* In test mode, just validate */
	if (config.test_mode) {
		if (config.verbose)
			vlabeld_log(LOG_DEBUG, "would set mode to %d", mode);
		return (0);
	}

	if (vlabel_syscall(VLABEL_SYS_SETMODE, &mode) < 0) {
		vlabeld_log(LOG_ERR, "SETMODE: %s", strerror(errno));
		return (-1);
	}

	if (config.verbose)
		vlabeld_log(LOG_DEBUG, "set mode to %d", mode);

	return (0);
}

/*
 * Build a rule_arg buffer from vlabel_rule_io (legacy format)
 * and send it to the kernel via mac_syscall.
 */
static int
send_rule_to_kernel(struct vlabel_rule_io *rule_io)
{
	struct vlabel_rule_arg *arg;
	char *buf, *data;
	size_t subject_len, object_len, newlabel_len, total_len;

	/* Calculate lengths (include null terminators) */
	subject_len = strlen(rule_io->vr_subject.vp_pattern) + 1;
	object_len = strlen(rule_io->vr_object.vp_pattern) + 1;
	newlabel_len = (rule_io->vr_action == VLABEL_ACTION_TRANSITION) ?
	    strlen(rule_io->vr_newlabel) + 1 : 0;

	total_len = sizeof(struct vlabel_rule_arg) + subject_len + object_len + newlabel_len;

	buf = calloc(1, total_len);
	if (buf == NULL) {
		vlabeld_log(LOG_ERR, "malloc: %s", strerror(errno));
		return (-1);
	}

	arg = (struct vlabel_rule_arg *)buf;
	arg->vr_action = rule_io->vr_action;
	arg->vr_operations = rule_io->vr_operations;
	arg->vr_subject_flags = rule_io->vr_subject.vp_flags;
	arg->vr_object_flags = rule_io->vr_object.vp_flags;
	arg->vr_context.vc_flags = rule_io->vr_context.vc_flags;
	arg->vr_context.vc_cap_sandboxed = rule_io->vr_context.vc_cap_sandboxed;
	arg->vr_context.vc_has_tty = rule_io->vr_context.vc_has_tty;
	arg->vr_context.vc_jail_check = rule_io->vr_context.vc_jail_check;
	arg->vr_context.vc_uid = rule_io->vr_context.vc_uid;
	arg->vr_context.vc_gid = rule_io->vr_context.vc_gid;
	arg->vr_subject_len = subject_len;
	arg->vr_object_len = object_len;
	arg->vr_newlabel_len = newlabel_len;

	/* Copy strings after the header */
	data = buf + sizeof(struct vlabel_rule_arg);
	memcpy(data, rule_io->vr_subject.vp_pattern, subject_len);
	data += subject_len;
	memcpy(data, rule_io->vr_object.vp_pattern, object_len);
	data += object_len;
	if (newlabel_len > 0)
		memcpy(data, rule_io->vr_newlabel, newlabel_len);

	/* Send to kernel */
	if (vlabel_syscall(VLABEL_SYS_RULE_ADD, buf) < 0) {
		vlabeld_log(LOG_ERR, "RULE_ADD: %s", strerror(errno));
		free(buf);
		return (-1);
	}

	free(buf);
	return (0);
}

/*
 * Add a rule to the kernel
 */
int
vlabeld_add_rule(struct vlabel_rule_io *rule)
{
	/* In test mode, just validate - don't send to kernel */
	if (config.test_mode) {
		if (config.verbose)
			vlabeld_log(LOG_DEBUG, "validated rule %u: action=%d ops=0x%x",
			    rule->vr_id, rule->vr_action, rule->vr_operations);
		return (0);
	}

	if (send_rule_to_kernel(rule) < 0)
		return (-1);

	if (config.verbose)
		vlabeld_log(LOG_DEBUG, "added rule %u: action=%d ops=0x%x",
		    rule->vr_id, rule->vr_action, rule->vr_operations);

	return (0);
}

/*
 * Load policy from a configuration file
 */
static int
load_policy(const char *path)
{
	int error;

	vlabeld_log(LOG_INFO, "loading policy from %s", path);

	/* Clear existing rules first */
	if (!config.test_mode) {
		if (vlabeld_clear_rules() < 0)
			return (-1);
	}

	/* Determine format and parse */
	error = vlabeld_parse_ucl(path, config.verbose);
	if (error != 0) {
		vlabeld_log(LOG_ERR, "failed to parse policy: %s", path);
		return (-1);
	}

	vlabeld_log(LOG_INFO, "policy loaded successfully");
	return (0);
}

static void
main_loop(void)
{
	vlabeld_log(LOG_INFO, "daemon started");

	while (!shutdown_pending) {
		/* Check for pending reload */
		if (reload_pending) {
			reload_pending = 0;
			vlabeld_log(LOG_INFO, "reloading policy");
			load_policy(config.config_file);
		}

		/* Sleep - audit events are handled by FreeBSD's audit subsystem */
		sleep(1);
	}

	vlabeld_log(LOG_INFO, "shutting down");
}

static void
cleanup(void)
{
	if (pfh != NULL) {
		pidfile_remove(pfh);
		pfh = NULL;
	}
}

static void
daemonize(void)
{
	pid_t otherpid;

	/* Check/create pidfile */
	pfh = pidfile_open(config.pidfile, 0600, &otherpid);
	if (pfh == NULL) {
		if (errno == EEXIST) {
			errx(1, "daemon already running, pid: %jd",
			    (intmax_t)otherpid);
		}
		err(1, "pidfile_open");
	}

	/* Daemonize */
	if (daemon(0, 0) < 0) {
		pidfile_remove(pfh);
		err(1, "daemon");
	}

	/* Write PID */
	pidfile_write(pfh);

	/* Open syslog */
	openlog("vlabeld", LOG_PID | LOG_NDELAY, LOG_SECURITY);
}

int
main(int argc, char *argv[])
{
	int ch;

	/* Initialize config with defaults */
	memset(&config, 0, sizeof(config));
	config.config_file = VLABELD_DEFAULT_CONFIG;
	config.pidfile = VLABELD_DEFAULT_PIDFILE;
	config.daemonize = true;
	config.verbose = false;
	config.test_mode = false;

	while ((ch = getopt(argc, argv, "c:dfp:tv")) != -1) {
		switch (ch) {
		case 'c':
			config.config_file = optarg;
			break;
		case 'd':
			config.daemonize = false;
			config.verbose = true;
			break;
		case 'f':
			config.daemonize = false;
			break;
		case 'p':
			config.pidfile = optarg;
			break;
		case 't':
			config.test_mode = true;
			config.daemonize = false;
			break;
		case 'v':
			config.verbose = true;
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 0)
		usage();

	/* Must be root */
	if (geteuid() != 0)
		errx(1, "must be run as root");

	/* Setup signal handlers */
	if (setup_signals() < 0)
		exit(1);

	/* Verify module is loaded (not needed for test mode) */
	if (!config.test_mode) {
		int mode;
		if (vlabel_syscall(VLABEL_SYS_GETMODE, &mode) < 0) {
			errx(1, "cannot communicate with vLabel module");
		}
	}

	/* Load policy */
	if (load_policy(config.config_file) < 0) {
		cleanup();
		exit(1);
	}

	/* Test mode - just validate and exit */
	if (config.test_mode) {
		printf("configuration OK\n");
		exit(0);
	}

	/* Daemonize if requested */
	if (config.daemonize)
		daemonize();

	/* Main event loop */
	main_loop();

	/* Cleanup */
	cleanup();

	return (0);
}
