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
#include <strings.h>
#include <sysexits.h>
#include <time.h>
#include <unistd.h>

#include "../kernel/mac_vlabel.h"
#include "../daemon/vlabeld.h"

#define VLABEL_DEVICE	"/dev/vlabel"

static int dev_fd = -1;

static void usage(void);
static int cmd_mode(int argc, char *argv[]);
static int cmd_audit(int argc, char *argv[]);
static int cmd_stats(int argc, char *argv[]);
static int cmd_status(int argc, char *argv[]);
static int cmd_rule(int argc, char *argv[]);
static int cmd_label(int argc, char *argv[]);
static int cmd_monitor(int argc, char *argv[]);
static int cmd_test(int argc, char *argv[]);

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
	    "  status\n"
	    "      Show combined status (mode, audit, stats, rules)\n"
	    "\n"
	    "  rule add \"<rule>\"\n"
	    "      Add a rule (line format)\n"
	    "      Example: vlabelctl rule add \"deny exec * -> type=untrusted\"\n"
	    "\n"
	    "  rule remove <id>\n"
	    "      Remove a rule by ID\n"
	    "\n"
	    "  rule list\n"
	    "      List all loaded rules\n"
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
	    "\n"
	    "  test <operation> <subject-label> <object-label>\n"
	    "      Test if an operation would be allowed\n"
	    "      Example: vlabelctl test exec \"type=user\" \"type=untrusted\"\n"
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
		/* Get audit level */
		if (ioctl(dev_fd, VLABEL_IOC_GETAUDIT, &level) < 0)
			err(EX_OSERR, "ioctl(GETAUDIT)");

		switch (level) {
		case VLABEL_AUDIT_NONE:
			levelstr = "none";
			break;
		case VLABEL_AUDIT_DENIALS:
			levelstr = "denials";
			break;
		case VLABEL_AUDIT_DECISIONS:
			levelstr = "decisions";
			break;
		case VLABEL_AUDIT_VERBOSE:
			levelstr = "verbose";
			break;
		default:
			levelstr = "unknown";
			break;
		}
		printf("%s\n", levelstr);
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
 * status - combined view of mode, audit, stats, rules
 */
static int
cmd_status(int argc, char *argv[])
{
	struct vlabel_stats stats;
	struct vlabel_rule_list_io list_io;
	int mode, audit;
	const char *modestr, *auditstr;

	open_device();

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

	/* Get audit level */
	if (ioctl(dev_fd, VLABEL_IOC_GETAUDIT, &audit) < 0)
		err(EX_OSERR, "ioctl(GETAUDIT)");

	switch (audit) {
	case VLABEL_AUDIT_NONE:
		auditstr = "none";
		break;
	case VLABEL_AUDIT_DENIALS:
		auditstr = "denials";
		break;
	case VLABEL_AUDIT_DECISIONS:
		auditstr = "decisions";
		break;
	case VLABEL_AUDIT_VERBOSE:
		auditstr = "verbose";
		break;
	default:
		auditstr = "unknown";
		break;
	}

	/* Get stats */
	if (ioctl(dev_fd, VLABEL_IOC_GETSTATS, &stats) < 0)
		err(EX_OSERR, "ioctl(GETSTATS)");

	/* Get rule count */
	memset(&list_io, 0, sizeof(list_io));
	if (ioctl(dev_fd, VLABEL_IOC_RULE_LIST, &list_io) < 0)
		err(EX_OSERR, "ioctl(RULE_LIST)");

	/* Print combined status */
	printf("vLabel Status:\n");
	printf("  Mode:             %s\n", modestr);
	printf("  Audit:            %s\n", auditstr);
	printf("  Active rules:     %u\n", list_io.vrl_total);
	printf("\n");
	printf("Statistics:\n");
	printf("  Access checks:    %ju\n", (uintmax_t)stats.vs_checks);
	printf("  Allowed:          %ju\n", (uintmax_t)stats.vs_allowed);
	printf("  Denied:           %ju\n", (uintmax_t)stats.vs_denied);

	if (stats.vs_checks > 0) {
		double deny_pct = (100.0 * stats.vs_denied) / stats.vs_checks;
		printf("  Denial rate:      %.1f%%\n", deny_pct);
	}

	return (0);
}

/*
 * Helper to format an operation bitmask as a string
 */
static const char *
ops_to_string(uint32_t ops, char *buf, size_t buflen)
{
	size_t len;

	if (ops == VLABEL_OP_ALL)
		return "all";

	buf[0] = '\0';

	if (ops & VLABEL_OP_EXEC)
		strlcat(buf, "exec,", buflen);
	if (ops & VLABEL_OP_READ)
		strlcat(buf, "read,", buflen);
	if (ops & VLABEL_OP_WRITE)
		strlcat(buf, "write,", buflen);
	if (ops & VLABEL_OP_MMAP)
		strlcat(buf, "mmap,", buflen);
	if (ops & VLABEL_OP_LINK)
		strlcat(buf, "link,", buflen);
	if (ops & VLABEL_OP_RENAME)
		strlcat(buf, "rename,", buflen);
	if (ops & VLABEL_OP_UNLINK)
		strlcat(buf, "unlink,", buflen);
	if (ops & VLABEL_OP_CHDIR)
		strlcat(buf, "chdir,", buflen);
	if (ops & VLABEL_OP_STAT)
		strlcat(buf, "stat,", buflen);
	if (ops & VLABEL_OP_READDIR)
		strlcat(buf, "readdir,", buflen);
	if (ops & VLABEL_OP_CREATE)
		strlcat(buf, "create,", buflen);
	if (ops & VLABEL_OP_OPEN)
		strlcat(buf, "open,", buflen);
	if (ops & VLABEL_OP_ACCESS)
		strlcat(buf, "access,", buflen);
	if (ops & VLABEL_OP_LOOKUP)
		strlcat(buf, "lookup,", buflen);
	if (ops & VLABEL_OP_SETEXTATTR)
		strlcat(buf, "setextattr,", buflen);
	if (ops & VLABEL_OP_GETEXTATTR)
		strlcat(buf, "getextattr,", buflen);

	/* Remove trailing comma */
	len = strlen(buf);
	if (len > 0 && buf[len - 1] == ',')
		buf[len - 1] = '\0';

	return buf[0] ? buf : "none";
}

/*
 * Helper to format a pattern as a string
 */
static const char *
pattern_to_string(const struct vlabel_pattern_io *p, char *buf, size_t buflen)
{
	int first = 1;

	buf[0] = '\0';

	if ((p->vp_flags & ~VLABEL_MATCH_NEGATE) == 0)
		return "*";

	if (p->vp_flags & VLABEL_MATCH_NEGATE)
		strlcat(buf, "!", buflen);

	if (p->vp_flags & VLABEL_MATCH_TYPE) {
		if (!first) strlcat(buf, ",", buflen);
		strlcat(buf, "type=", buflen);
		strlcat(buf, p->vp_type[0] ? p->vp_type : "*", buflen);
		first = 0;
	}

	if (p->vp_flags & VLABEL_MATCH_DOMAIN) {
		if (!first) strlcat(buf, ",", buflen);
		strlcat(buf, "domain=", buflen);
		strlcat(buf, p->vp_domain[0] ? p->vp_domain : "*", buflen);
		first = 0;
	}

	if (p->vp_flags & VLABEL_MATCH_NAME) {
		if (!first) strlcat(buf, ",", buflen);
		strlcat(buf, "name=", buflen);
		strlcat(buf, p->vp_name[0] ? p->vp_name : "*", buflen);
		first = 0;
	}

	if (p->vp_flags & VLABEL_MATCH_LEVEL) {
		if (!first) strlcat(buf, ",", buflen);
		strlcat(buf, "level=", buflen);
		strlcat(buf, p->vp_level[0] ? p->vp_level : "*", buflen);
		first = 0;
	}

	return buf;
}

/*
 * rule add|remove|clear|list
 */
static int
cmd_rule(int argc, char *argv[])
{
	struct vlabel_rule_io rule;
	struct vlabel_rule_list_io list_io;
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

	} else if (strcmp(argv[0], "list") == 0) {
		struct vlabel_rule_io *rules;
		uint32_t i;
		const char *action_str;

		/* Query rule count first */
		memset(&list_io, 0, sizeof(list_io));
		list_io.vrl_count = 0;
		list_io.vrl_offset = 0;
		list_io.vrl_rules = NULL;

		if (ioctl(dev_fd, VLABEL_IOC_RULE_LIST, &list_io) < 0)
			err(EX_OSERR, "ioctl(RULE_LIST)");

		if (list_io.vrl_total == 0) {
			printf("(no rules loaded)\n");
			return (0);
		}

		/* Allocate buffer for rules */
		rules = calloc(list_io.vrl_total, sizeof(struct vlabel_rule_io));
		if (rules == NULL)
			err(EX_OSERR, "calloc");

		/* Fetch rules */
		list_io.vrl_count = list_io.vrl_total;
		list_io.vrl_offset = 0;
		list_io.vrl_rules = rules;

		if (ioctl(dev_fd, VLABEL_IOC_RULE_LIST, &list_io) < 0) {
			free(rules);
			err(EX_OSERR, "ioctl(RULE_LIST)");
		}

		printf("Loaded rules: %u\n\n", list_io.vrl_count);

		for (i = 0; i < list_io.vrl_count; i++) {
			struct vlabel_rule_io *r = &rules[i];
			char opsbuf[128], subjbuf[256], objbuf[256];

			switch (r->vr_action) {
			case VLABEL_ACTION_ALLOW:
				action_str = "allow";
				break;
			case VLABEL_ACTION_DENY:
				action_str = "deny";
				break;
			case VLABEL_ACTION_TRANSITION:
				action_str = "transition";
				break;
			default:
				action_str = "unknown";
				break;
			}

			printf("  [%u] %s %s %s -> %s",
			    r->vr_id,
			    action_str,
			    ops_to_string(r->vr_operations, opsbuf, sizeof(opsbuf)),
			    pattern_to_string(&r->vr_subject, subjbuf, sizeof(subjbuf)),
			    pattern_to_string(&r->vr_object, objbuf, sizeof(objbuf)));

			if (r->vr_action == VLABEL_ACTION_TRANSITION &&
			    r->vr_newlabel[0] != '\0')
				printf(" => %s", r->vr_newlabel);

			printf("\n");
		}

		free(rules);

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
		if (tm != NULL)
			strftime(timebuf, sizeof(timebuf), "%H:%M:%S", tm);
		else
			strlcpy(timebuf, "??:??:??", sizeof(timebuf));

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

/*
 * Parse operation name to bitmask
 */
static uint32_t
parse_operation(const char *opstr)
{
	if (strcasecmp(opstr, "exec") == 0)
		return VLABEL_OP_EXEC;
	if (strcasecmp(opstr, "read") == 0)
		return VLABEL_OP_READ;
	if (strcasecmp(opstr, "write") == 0)
		return VLABEL_OP_WRITE;
	if (strcasecmp(opstr, "mmap") == 0)
		return VLABEL_OP_MMAP;
	if (strcasecmp(opstr, "link") == 0)
		return VLABEL_OP_LINK;
	if (strcasecmp(opstr, "rename") == 0)
		return VLABEL_OP_RENAME;
	if (strcasecmp(opstr, "unlink") == 0)
		return VLABEL_OP_UNLINK;
	if (strcasecmp(opstr, "chdir") == 0)
		return VLABEL_OP_CHDIR;
	if (strcasecmp(opstr, "stat") == 0)
		return VLABEL_OP_STAT;
	if (strcasecmp(opstr, "readdir") == 0)
		return VLABEL_OP_READDIR;
	if (strcasecmp(opstr, "create") == 0)
		return VLABEL_OP_CREATE;
	if (strcasecmp(opstr, "open") == 0)
		return VLABEL_OP_OPEN;
	if (strcasecmp(opstr, "access") == 0)
		return VLABEL_OP_ACCESS;
	if (strcasecmp(opstr, "lookup") == 0)
		return VLABEL_OP_LOOKUP;
	if (strcasecmp(opstr, "setextattr") == 0)
		return VLABEL_OP_SETEXTATTR;
	if (strcasecmp(opstr, "getextattr") == 0)
		return VLABEL_OP_GETEXTATTR;
	if (strcasecmp(opstr, "all") == 0)
		return VLABEL_OP_ALL;

	return 0;
}

/*
 * test <operation> <subject-label> <object-label>
 *
 * Test if an operation would be allowed without actually performing it.
 */
static int
cmd_test(int argc, char *argv[])
{
	struct vlabel_test_io test_io;
	uint32_t op;

	if (argc < 3)
		errx(EX_USAGE, "test requires: <operation> <subject-label> <object-label>");

	open_device();

	/* Parse operation */
	op = parse_operation(argv[0]);
	if (op == 0)
		errx(EX_USAGE, "unknown operation: %s", argv[0]);

	/* Setup test request */
	memset(&test_io, 0, sizeof(test_io));
	strlcpy(test_io.vt_subject_label, argv[1], sizeof(test_io.vt_subject_label));
	strlcpy(test_io.vt_object_label, argv[2], sizeof(test_io.vt_object_label));
	test_io.vt_operation = op;

	/* Perform test */
	if (ioctl(dev_fd, VLABEL_IOC_TEST_ACCESS, &test_io) < 0)
		err(EX_OSERR, "ioctl(TEST_ACCESS)");

	/* Print result */
	printf("Operation:   %s\n", argv[0]);
	printf("Subject:     %s\n", argv[1]);
	printf("Object:      %s\n", argv[2]);
	printf("Result:      %s\n", test_io.vt_result == 0 ? "ALLOW" : "DENY");

	if (test_io.vt_rule_id != 0)
		printf("Matched:     rule %u\n", test_io.vt_rule_id);
	else
		printf("Matched:     (default policy)\n");

	/* Exit with non-zero if denied, for scripting */
	return (test_io.vt_result == 0) ? 0 : 1;
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
	else if (strcmp(argv[0], "status") == 0)
		return (cmd_status(argc - 1, argv + 1));
	else if (strcmp(argv[0], "rule") == 0)
		return (cmd_rule(argc - 1, argv + 1));
	else if (strcmp(argv[0], "label") == 0)
		return (cmd_label(argc - 1, argv + 1));
	else if (strcmp(argv[0], "monitor") == 0)
		return (cmd_monitor(argc - 1, argv + 1));
	else if (strcmp(argv[0], "test") == 0)
		return (cmd_test(argc - 1, argv + 1));
	else if (strcmp(argv[0], "help") == 0 || strcmp(argv[0], "-h") == 0)
		usage();
	else
		errx(EX_USAGE, "unknown command: %s", argv[0]);

	return (0);
}
