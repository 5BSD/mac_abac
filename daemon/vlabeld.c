/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 vLabel Project
 * All rights reserved.
 *
 * vlabeld - vLabel Policy Daemon
 *
 * Loads security policy from configuration files and monitors audit events.
 * Supports UCL, JSON, and simple line-based policy formats.
 */

#include <sys/types.h>
#include <sys/event.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
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
static int dev_fd = -1;
static int kq_fd = -1;
static volatile sig_atomic_t reload_pending = 0;
static volatile sig_atomic_t shutdown_pending = 0;
static struct pidfh *pfh = NULL;

/* Forward declarations */
static void usage(void);
static void signal_handler(int sig);
static int setup_signals(void);
static int open_device(void);
static int setup_kqueue(void);
static int load_policy(const char *path);
static int process_audit_events(void);
static void main_loop(void);
static void cleanup(void);
static void daemonize(void);

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

static int
open_device(void)
{
	dev_fd = open(VLABELD_DEVICE, O_RDWR);
	if (dev_fd < 0) {
		vlabeld_log(LOG_ERR, "open(%s): %s", VLABELD_DEVICE,
		    strerror(errno));
		return (-1);
	}

	if (config.verbose)
		vlabeld_log(LOG_DEBUG, "opened %s", VLABELD_DEVICE);

	return (0);
}

static int
setup_kqueue(void)
{
	struct kevent kev[2];
	int n = 0;

	kq_fd = kqueue();
	if (kq_fd < 0) {
		vlabeld_log(LOG_ERR, "kqueue: %s", strerror(errno));
		return (-1);
	}

	/* Watch for readable events on /dev/vlabel (audit events) */
	EV_SET(&kev[n++], dev_fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, NULL);

	/* Watch for signals */
	EV_SET(&kev[n++], SIGHUP, EVFILT_SIGNAL, EV_ADD | EV_ENABLE, 0, 0, NULL);

	if (kevent(kq_fd, kev, n, NULL, 0, NULL) < 0) {
		vlabeld_log(LOG_ERR, "kevent: %s", strerror(errno));
		close(kq_fd);
		kq_fd = -1;
		return (-1);
	}

	return (0);
}

/*
 * Clear all rules in the kernel
 */
static int
clear_rules(void)
{
	/* In test mode, nothing to clear */
	if (config.test_mode)
		return (0);

	if (ioctl(dev_fd, VLABEL_IOC_RULES_CLEAR) < 0) {
		vlabeld_log(LOG_ERR, "ioctl(RULES_CLEAR): %s", strerror(errno));
		return (-1);
	}

	if (config.verbose)
		vlabeld_log(LOG_DEBUG, "cleared all rules");

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

	if (ioctl(dev_fd, VLABEL_IOC_RULE_ADD, rule) < 0) {
		vlabeld_log(LOG_ERR, "ioctl(RULE_ADD): %s", strerror(errno));
		return (-1);
	}

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
		if (clear_rules() < 0)
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

/*
 * Process audit events from /dev/vlabel
 */
static int
process_audit_events(void)
{
	struct vlabel_audit_entry entry;
	ssize_t n;
	char timebuf[32];
	struct tm *tm;
	time_t ts;

	while ((n = read(dev_fd, &entry, sizeof(entry))) > 0) {
		if (n != sizeof(entry)) {
			vlabeld_log(LOG_WARNING, "short read: %zd bytes", n);
			continue;
		}

		ts = (time_t)entry.vae_timestamp;
		tm = localtime(&ts);
		if (tm != NULL)
			strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", tm);
		else
			strlcpy(timebuf, "(invalid time)", sizeof(timebuf));

		vlabeld_log(LOG_INFO,
		    "[%s] %s pid=%d uid=%u jail=%d subj=%s obj=%s",
		    timebuf,
		    entry.vae_result == 0 ? "ALLOW" : "DENY",
		    entry.vae_pid,
		    entry.vae_uid,
		    entry.vae_jailid,
		    entry.vae_subject_label[0] ? entry.vae_subject_label : "-",
		    entry.vae_object_label[0] ? entry.vae_object_label : "-");

		if (entry.vae_path[0])
			vlabeld_log(LOG_INFO, "  path=%s", entry.vae_path);
	}

	if (n < 0 && errno != EAGAIN && errno != EINTR) {
		vlabeld_log(LOG_ERR, "read: %s", strerror(errno));
		return (-1);
	}

	return (0);
}

static void
main_loop(void)
{
	struct kevent kev;
	int n;

	vlabeld_log(LOG_INFO, "entering main loop");

	while (!shutdown_pending) {
		/* Check for pending reload */
		if (reload_pending) {
			reload_pending = 0;
			vlabeld_log(LOG_INFO, "reloading policy");
			load_policy(config.config_file);
		}

		/* Wait for events with 1 second timeout */
		struct timespec timeout = { .tv_sec = 1, .tv_nsec = 0 };
		n = kevent(kq_fd, NULL, 0, &kev, 1, &timeout);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			vlabeld_log(LOG_ERR, "kevent: %s", strerror(errno));
			break;
		}

		if (n == 0)
			continue;	/* Timeout */

		if (kev.filter == EVFILT_READ && (int)kev.ident == dev_fd) {
			process_audit_events();
		} else if (kev.filter == EVFILT_SIGNAL) {
			/* Signal already handled by signal_handler */
		}
	}

	vlabeld_log(LOG_INFO, "shutting down");
}

static void
cleanup(void)
{
	if (kq_fd >= 0) {
		close(kq_fd);
		kq_fd = -1;
	}
	if (dev_fd >= 0) {
		close(dev_fd);
		dev_fd = -1;
	}
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

	/* Open /dev/vlabel (not needed for test mode) */
	if (!config.test_mode) {
		if (open_device() < 0)
			exit(1);
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

	/* Setup kqueue for event loop */
	if (setup_kqueue() < 0) {
		cleanup();
		exit(1);
	}

	/* Main event loop */
	main_loop();

	/* Cleanup */
	cleanup();

	return (0);
}
