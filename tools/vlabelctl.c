/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 vLabel Project
 * All rights reserved.
 *
 * vlabelctl - vLabel Control Utility
 *
 * Command-line tool for managing the vLabel MAC policy module.
 */

#include <sys/types.h>
#include <sys/extattr.h>
#include <sys/ioctl.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include "../kernel/mac_vlabel.h"
#include "../daemon/vlabeld.h"

#define VLABEL_DEVICE	"/dev/vlabel"

static int dev_fd = -1;

static void usage(void);
static int cmd_mode(int argc, char *argv[]);
static int cmd_audit(int argc, char *argv[]);
static int cmd_stats(int argc, char *argv[]);
static int cmd_rule(int argc, char *argv[]);
static int cmd_label(int argc, char *argv[]);
static int cmd_monitor(int argc, char *argv[]);

static void
usage(void)
{
	fprintf(stderr,
	    "usage: vlabelctl <command> [arguments]\n"
	    "\n"
	    "Commands:\n"
	    "  mode [disabled|permissive|enforcing]\n"
	    "      Get or set enforcement mode\n"
	    "\n"
	    "  audit [none|denials|decisions|verbose]\n"
	    "      Get or set audit level\n"
	    "\n"
	    "  stats\n"
	    "      Show statistics\n"
	    "\n"
	    "  rule add \"<rule>\"\n"
	    "      Add a rule (line format)\n"
	    "      Example: vlabelctl rule add \"deny exec * -> type=untrusted\"\n"
	    "\n"
	    "  rule remove <id>\n"
	    "      Remove a rule by ID\n"
	    "\n"
	    "  rule clear\n"
	    "      Clear all rules\n"
	    "\n"
	    "  label get <path>\n"
	    "      Get the vLabel of a file\n"
	    "\n"
	    "  label set <path> \"<label>\"\n"
	    "      Set the vLabel of a file\n"
	    "      Example: vlabelctl label set /bin/foo \"type=trusted,domain=system\"\n"
	    "\n"
	    "  label remove <path>\n"
	    "      Remove the vLabel from a file\n"
	    "\n"
	    "  monitor\n"
	    "      Monitor audit events in real-time\n"
	);
	exit(EX_USAGE);
}

static int
open_device(void)
{
	dev_fd = open(VLABEL_DEVICE, O_RDWR);
	if (dev_fd < 0) {
		if (errno == ENOENT)
			errx(EX_UNAVAILABLE, "vLabel module not loaded");
		err(EX_NOPERM, "open %s", VLABEL_DEVICE);
	}
	return (0);
}

/*
 * mode [disabled|permissive|enforcing]
 */
static int
cmd_mode(int argc, char *argv[])
{
	int mode;
	const char *modestr;

	open_device();

	if (argc == 0) {
		/* Get mode */
		if (ioctl(dev_fd, VLABEL_IOC_GETMODE, &mode) < 0)
			err(EX_OSERR, "ioctl(GETMODE)");

		switch (mode) {
		case VLABEL_MODE_DISABLED:
			modestr = "disabled";
			break;
		case VLABEL_MODE_PERMISSIVE:
			modestr = "permissive";
			break;
		case VLABEL_MODE_ENFORCING:
			modestr = "enforcing";
			break;
		default:
			modestr = "unknown";
			break;
		}
		printf("%s\n", modestr);
		return (0);
	}

	/* Set mode */
	if (strcmp(argv[0], "disabled") == 0)
		mode = VLABEL_MODE_DISABLED;
	else if (strcmp(argv[0], "permissive") == 0)
		mode = VLABEL_MODE_PERMISSIVE;
	else if (strcmp(argv[0], "enforcing") == 0)
		mode = VLABEL_MODE_ENFORCING;
	else
		errx(EX_USAGE, "invalid mode: %s", argv[0]);

	if (ioctl(dev_fd, VLABEL_IOC_SETMODE, &mode) < 0)
		err(EX_OSERR, "ioctl(SETMODE)");

	printf("mode set to %s\n", argv[0]);
	return (0);
}

/*
 * audit [none|denials|decisions|verbose]
 */
static int
cmd_audit(int argc, char *argv[])
{
	int level;
	const char *levelstr;

	open_device();

	if (argc == 0) {
		/* Get audit level - we don't have a GETAUDIT ioctl yet */
		printf("(audit level query not implemented)\n");
		return (0);
	}

	/* Set audit level */
	if (strcmp(argv[0], "none") == 0)
		level = VLABEL_AUDIT_NONE;
	else if (strcmp(argv[0], "denials") == 0)
		level = VLABEL_AUDIT_DENIALS;
	else if (strcmp(argv[0], "decisions") == 0)
		level = VLABEL_AUDIT_DECISIONS;
	else if (strcmp(argv[0], "verbose") == 0)
		level = VLABEL_AUDIT_VERBOSE;
	else
		errx(EX_USAGE, "invalid audit level: %s", argv[0]);

	if (ioctl(dev_fd, VLABEL_IOC_SETAUDIT, &level) < 0)
		err(EX_OSERR, "ioctl(SETAUDIT)");

	printf("audit level set to %s\n", argv[0]);
	return (0);
}

/*
 * stats
 */
static int
cmd_stats(int argc, char *argv[])
{
	struct vlabel_stats stats;

	open_device();

	if (ioctl(dev_fd, VLABEL_IOC_GETSTATS, &stats) < 0)
		err(EX_OSERR, "ioctl(GETSTATS)");

	printf("vLabel Statistics:\n");
	printf("  Access checks:    %ju\n", (uintmax_t)stats.vs_checks);
	printf("  Allowed:          %ju\n", (uintmax_t)stats.vs_allowed);
	printf("  Denied:           %ju\n", (uintmax_t)stats.vs_denied);
	printf("  Labels read:      %ju\n", (uintmax_t)stats.vs_labels_read);
	printf("  Default labels:   %ju\n", (uintmax_t)stats.vs_labels_default);
	printf("  Active rules:     %u\n", stats.vs_rule_count);

	return (0);
}

/*
 * rule add|remove|clear
 */
static int
cmd_rule(int argc, char *argv[])
{
	struct vlabel_rule_io rule;
	uint32_t id;
	int ret;

	if (argc < 1)
		usage();

	open_device();

	if (strcmp(argv[0], "add") == 0) {
		if (argc < 2)
			errx(EX_USAGE, "rule add requires a rule string");

		ret = vlabeld_parse_line(argv[1], &rule);
		if (ret < 0)
			errx(EX_DATAERR, "invalid rule syntax");
		if (ret > 0)
			errx(EX_DATAERR, "empty rule");

		if (ioctl(dev_fd, VLABEL_IOC_RULE_ADD, &rule) < 0)
			err(EX_OSERR, "ioctl(RULE_ADD)");

		printf("added rule %u\n", rule.vr_id);

	} else if (strcmp(argv[0], "remove") == 0) {
		if (argc < 2)
			errx(EX_USAGE, "rule remove requires a rule ID");

		id = (uint32_t)strtoul(argv[1], NULL, 10);
		if (ioctl(dev_fd, VLABEL_IOC_RULE_REMOVE, &id) < 0)
			err(EX_OSERR, "ioctl(RULE_REMOVE)");

		printf("removed rule %u\n", id);

	} else if (strcmp(argv[0], "clear") == 0) {
		if (ioctl(dev_fd, VLABEL_IOC_RULES_CLEAR) < 0)
			err(EX_OSERR, "ioctl(RULES_CLEAR)");

		printf("all rules cleared\n");

	} else {
		errx(EX_USAGE, "unknown rule command: %s", argv[0]);
	}

	return (0);
}

/*
 * label get|set|remove <path>
 */
static int
cmd_label(int argc, char *argv[])
{
	char buf[VLABEL_MAX_LABEL_LEN];
	ssize_t len;
	int ret;

	if (argc < 2)
		usage();

	if (strcmp(argv[0], "get") == 0) {
		len = extattr_get_file(argv[1], EXTATTR_NAMESPACE_SYSTEM,
		    "vlabel", buf, sizeof(buf) - 1);
		if (len < 0) {
			if (errno == ENOATTR) {
				printf("(no label)\n");
				return (0);
			}
			err(EX_OSERR, "extattr_get_file");
		}
		buf[len] = '\0';
		printf("%s\n", buf);

	} else if (strcmp(argv[0], "set") == 0) {
		if (argc < 3)
			errx(EX_USAGE, "label set requires path and label");

		ret = extattr_set_file(argv[1], EXTATTR_NAMESPACE_SYSTEM,
		    "vlabel", argv[2], strlen(argv[2]));
		if (ret < 0)
			err(EX_OSERR, "extattr_set_file");

		printf("label set on %s\n", argv[1]);

	} else if (strcmp(argv[0], "remove") == 0) {
		ret = extattr_delete_file(argv[1], EXTATTR_NAMESPACE_SYSTEM,
		    "vlabel");
		if (ret < 0) {
			if (errno == ENOATTR) {
				printf("(no label to remove)\n");
				return (0);
			}
			err(EX_OSERR, "extattr_delete_file");
		}
		printf("label removed from %s\n", argv[1]);

	} else {
		errx(EX_USAGE, "unknown label command: %s", argv[0]);
	}

	return (0);
}

/*
 * monitor - watch audit events
 */
static int
cmd_monitor(int argc, char *argv[])
{
	struct vlabel_audit_entry entry;
	char timebuf[32];
	struct tm *tm;
	time_t ts;
	ssize_t n;

	open_device();

	printf("Monitoring vLabel audit events (Ctrl+C to stop)...\n\n");

	while ((n = read(dev_fd, &entry, sizeof(entry))) > 0) {
		if (n != sizeof(entry)) {
			warnx("short read: %zd bytes", n);
			continue;
		}

		ts = (time_t)entry.vae_timestamp;
		tm = localtime(&ts);
		strftime(timebuf, sizeof(timebuf), "%H:%M:%S", tm);

		printf("[%s] %s op=0x%04x pid=%d uid=%u",
		    timebuf,
		    entry.vae_result == 0 ? "ALLOW" : "DENY",
		    entry.vae_operation,
		    entry.vae_pid,
		    entry.vae_uid);

		if (entry.vae_jailid != 0)
			printf(" jail=%d", entry.vae_jailid);

		if (entry.vae_subject_label[0])
			printf(" subj=%s", entry.vae_subject_label);

		if (entry.vae_object_label[0])
			printf(" obj=%s", entry.vae_object_label);

		if (entry.vae_path[0])
			printf(" path=%s", entry.vae_path);

		printf("\n");
	}

	if (n < 0)
		err(EX_OSERR, "read");

	return (0);
}

int
main(int argc, char *argv[])
{
	if (argc < 2)
		usage();

	argc--;
	argv++;

	if (strcmp(argv[0], "mode") == 0)
		return (cmd_mode(argc - 1, argv + 1));
	else if (strcmp(argv[0], "audit") == 0)
		return (cmd_audit(argc - 1, argv + 1));
	else if (strcmp(argv[0], "stats") == 0)
		return (cmd_stats(argc - 1, argv + 1));
	else if (strcmp(argv[0], "rule") == 0)
		return (cmd_rule(argc - 1, argv + 1));
	else if (strcmp(argv[0], "label") == 0)
		return (cmd_label(argc - 1, argv + 1));
	else if (strcmp(argv[0], "monitor") == 0)
		return (cmd_monitor(argc - 1, argv + 1));
	else if (strcmp(argv[0], "help") == 0 || strcmp(argv[0], "-h") == 0)
		usage();
	else
		errx(EX_USAGE, "unknown command: %s", argv[0]);

	return (0);
}
