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

/*
 * Validate a label string before sending to kernel.
 * Labels use newline-separated format: "key1=val1\nkey2=val2\n"
 * Returns 0 if valid, prints error and returns -1 if invalid.
 */
static int
validate_label(const char *label)
{
	size_t len, keylen, valuelen;
	const char *p, *end, *nl, *eq;
	int npairs = 0;

	if (label == NULL) {
		warnx("label is NULL");
		return (-1);
	}

	len = strlen(label);
	if (len == 0) {
		/* Empty label is valid */
		return (0);
	}

	if (len > VLABEL_MAX_LABEL_LEN) {
		warnx("label too long: %zu bytes (max %d)",
		    len, VLABEL_MAX_LABEL_LEN);
		return (-1);
	}

	p = label;
	end = label + len;

	while (p < end) {
		/* Find next newline */
		nl = memchr(p, '\n', end - p);
		if (nl == NULL)
			nl = end;

		/* Skip empty lines */
		if (nl == p) {
			p = nl + 1;
			continue;
		}

		npairs++;
		if (npairs > VLABEL_MAX_PAIRS) {
			warnx("too many key=value pairs: %d (max %d)",
			    npairs, VLABEL_MAX_PAIRS);
			return (-1);
		}

		/* Find '=' */
		eq = memchr(p, '=', nl - p);
		if (eq == NULL) {
			warnx("missing '=' in pair: %.*s", (int)(nl - p), p);
			return (-1);
		}

		keylen = eq - p;
		valuelen = nl - eq - 1;

		if (keylen == 0) {
			warnx("empty key in pair");
			return (-1);
		}
		if (keylen >= VLABEL_MAX_KEY_LEN) {
			warnx("key too long: %zu bytes (max %d)",
			    keylen, VLABEL_MAX_KEY_LEN - 1);
			return (-1);
		}
		if (valuelen >= VLABEL_MAX_VALUE_LEN) {
			warnx("value too long: %zu bytes (max %d)",
			    valuelen, VLABEL_MAX_VALUE_LEN - 1);
			return (-1);
		}

		p = nl + 1;
	}

	return (0);
}

/*
 * Convert a user-provided label from comma format to newline format.
 * Input:  "key1=val1,key2=val2"
 * Output: "key1=val1\nkey2=val2\n"
 * Returns newly allocated string (caller must free), or NULL on error.
 */
static char *
convert_label_format(const char *input)
{
	size_t len, outlen;
	char *output, *outp;
	const char *p, *end, *comma;

	if (input == NULL)
		return (NULL);

	len = strlen(input);
	if (len == 0)
		return (strdup(""));

	/* Output size: same length, commas become newlines, plus trailing \n + \0 */
	outlen = len + 2;
	output = malloc(outlen);
	if (output == NULL) {
		warn("malloc");
		return (NULL);
	}

	p = input;
	end = input + len;
	outp = output;

	while (p < end) {
		/* Find next comma or end */
		comma = memchr(p, ',', end - p);
		if (comma == NULL)
			comma = end;

		/* Copy this segment */
		if (comma > p) {
			memcpy(outp, p, comma - p);
			outp += comma - p;
			*outp++ = '\n';
		}

		p = comma + 1;
	}

	*outp = '\0';
	return (output);
}

static void usage(void);
static int cmd_mode(int argc, char *argv[]);
static int cmd_audit(int argc, char *argv[]);
static int cmd_default(int argc, char *argv[]);
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
	    "  default [allow|deny]\n"
	    "      Get or set default policy when no rule matches\n"
	    "\n"
	    "  stats\n"
	    "      Show statistics\n"
	    "\n"
	    "  status\n"
	    "      Show combined status (mode, audit, stats, rules)\n"
	    "\n"
	    "  limits\n"
	    "      Show kernel limits, supported operations, and syntax\n"
	    "\n"
	    "  rule add \"<rule>\"\n"
	    "      Add a rule (line format)\n"
	    "      Example: vlabelctl rule add \"deny exec * -> type=untrusted\"\n"
	    "\n"
	    "  rule remove <id>\n"
	    "      Remove a rule by ID\n"
	    "\n"
	    "  rule load <file>\n"
	    "      Load rules from a file (one rule per line)\n"
	    "      Lines starting with # are comments\n"
	    "\n"
	    "  rule validate \"<rule>\"\n"
	    "      Validate a rule without loading it\n"
	    "\n"
	    "  rule validate -f <file>\n"
	    "      Validate all rules in a file\n"
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
 * default [allow|deny]
 */
static int
cmd_default(int argc, char *argv[])
{
	int policy;
	const char *policystr;

	open_device();

	if (argc == 0) {
		/* Get default policy */
		if (ioctl(dev_fd, VLABEL_IOC_GETDEFPOL, &policy) < 0)
			err(EX_OSERR, "ioctl(GETDEFPOL)");

		policystr = (policy == 0) ? "allow" : "deny";
		printf("%s\n", policystr);
		return (0);
	}

	/* Set default policy */
	if (strcmp(argv[0], "allow") == 0)
		policy = 0;
	else if (strcmp(argv[0], "deny") == 0)
		policy = 1;
	else
		errx(EX_USAGE, "invalid default policy: %s (use 'allow' or 'deny')",
		    argv[0]);

	if (ioctl(dev_fd, VLABEL_IOC_SETDEFPOL, &policy) < 0)
		err(EX_OSERR, "ioctl(SETDEFPOL)");

	printf("default policy set to %s\n", argv[0]);
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
	int mode, audit, defpol;
	const char *modestr, *auditstr, *defpolstr;

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

	/* Get default policy */
	if (ioctl(dev_fd, VLABEL_IOC_GETDEFPOL, &defpol) < 0)
		err(EX_OSERR, "ioctl(GETDEFPOL)");

	defpolstr = (defpol == 0) ? "allow" : "deny";

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
	printf("  Default policy:   %s\n", defpolstr);
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
 * limits - show kernel limits and supported operations
 */
static int
cmd_limits(int argc __unused, char *argv[] __unused)
{

	printf("vLabel Limits:\n");
	printf("\n");
	printf("  Label Limits (per label):\n");
	printf("    Max label size:       %d bytes\n", VLABEL_MAX_LABEL_LEN);
	printf("    Max key length:       %d bytes\n", VLABEL_MAX_KEY_LEN);
	printf("    Max value length:     %d bytes\n", VLABEL_MAX_VALUE_LEN);
	printf("    Max key=value pairs:  %d\n", VLABEL_MAX_PAIRS);
	printf("\n");
	printf("  System Limits:\n");
	printf("    Max rules:            %d\n", VLABEL_MAX_RULES);
	printf("    Max pattern length:   %zu bytes\n", sizeof(((struct vlabel_pattern_io *)0)->vp_pattern));
	printf("\n");
	printf("  Supported Operations:\n");
	printf("    %-12s  0x%08x  %s\n", "exec",       VLABEL_OP_EXEC,       "execute file");
	printf("    %-12s  0x%08x  %s\n", "read",       VLABEL_OP_READ,       "read file contents");
	printf("    %-12s  0x%08x  %s\n", "write",      VLABEL_OP_WRITE,      "write file contents");
	printf("    %-12s  0x%08x  %s\n", "mmap",       VLABEL_OP_MMAP,       "memory map file");
	printf("    %-12s  0x%08x  %s\n", "link",       VLABEL_OP_LINK,       "create hard link");
	printf("    %-12s  0x%08x  %s\n", "rename",     VLABEL_OP_RENAME,     "rename file");
	printf("    %-12s  0x%08x  %s\n", "unlink",     VLABEL_OP_UNLINK,     "delete file");
	printf("    %-12s  0x%08x  %s\n", "chdir",      VLABEL_OP_CHDIR,      "change directory");
	printf("    %-12s  0x%08x  %s\n", "stat",       VLABEL_OP_STAT,       "stat file");
	printf("    %-12s  0x%08x  %s\n", "readdir",    VLABEL_OP_READDIR,    "read directory");
	printf("    %-12s  0x%08x  %s\n", "create",     VLABEL_OP_CREATE,     "create file");
	printf("    %-12s  0x%08x  %s\n", "setextattr", VLABEL_OP_SETEXTATTR, "set extended attribute");
	printf("    %-12s  0x%08x  %s\n", "getextattr", VLABEL_OP_GETEXTATTR, "get extended attribute");
	printf("    %-12s  0x%08x  %s\n", "lookup",     VLABEL_OP_LOOKUP,     "lookup path component");
	printf("    %-12s  0x%08x  %s\n", "open",       VLABEL_OP_OPEN,       "open file");
	printf("    %-12s  0x%08x  %s\n", "access",     VLABEL_OP_ACCESS,     "check access permissions");
	printf("    %-12s  0x%08x  %s\n", "debug",      VLABEL_OP_DEBUG,      "ptrace/procfs debug");
	printf("    %-12s  0x%08x  %s\n", "signal",     VLABEL_OP_SIGNAL,     "send signal");
	printf("    %-12s  0x%08x  %s\n", "sched",      VLABEL_OP_SCHED,      "scheduler control");
	printf("    %-12s  0x%08x  %s\n", "all",        VLABEL_OP_ALL,        "all operations");
	printf("\n");
	printf("  Enforced Operations:\n");
	printf("    exec, debug, signal, sched\n");
	printf("\n");
	printf("  Stub Operations (always allow, not yet enforced):\n");
	printf("    read, write, mmap, open, link, rename, unlink,\n");
	printf("    chdir, stat, readdir, create, setextattr, getextattr,\n");
	printf("    lookup, access\n");
	printf("\n");
	printf("  Rule Syntax:\n");
	printf("    action operation subject -> object [context:...]\n");
	printf("\n");
	printf("  Actions:\n");
	printf("    allow       - permit the operation\n");
	printf("    deny        - block the operation (returns EACCES)\n");
	printf("    transition  - change process label on exec\n");
	printf("\n");
	printf("  Pattern Format:\n");
	printf("    *                   - match anything (wildcard)\n");
	printf("    type=value          - match type field\n");
	printf("    domain=value        - match domain field\n");
	printf("    name=value          - match name field\n");
	printf("    level=value         - match level field\n");
	printf("    type=a,domain=b     - match multiple fields\n");
	printf("    !pattern            - negate the match\n");
	printf("\n");
	printf("  Context Constraints:\n");
	printf("    context:jail=host       - must be on host (not in jail)\n");
	printf("    context:jail=any        - must be in a jail\n");
	printf("    context:jail=<id>       - must be in specific jail\n");
	printf("    context:sandboxed=true  - must be in Capsicum sandbox\n");
	printf("    context:uid=<n>         - must have effective UID\n");
	printf("    context:gid=<n>         - must have effective GID\n");
	printf("    context:tty=true        - must have controlling TTY\n");

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
	if (ops & VLABEL_OP_DEBUG)
		strlcat(buf, "debug,", buflen);
	if (ops & VLABEL_OP_SIGNAL)
		strlcat(buf, "signal,", buflen);
	if (ops & VLABEL_OP_SCHED)
		strlcat(buf, "sched,", buflen);

	/* Remove trailing comma */
	len = strlen(buf);
	if (len > 0 && buf[len - 1] == ',')
		buf[len - 1] = '\0';

	return buf[0] ? buf : "none";
}

/*
 * Helper to format a pattern as a string
 *
 * The new vlabel_pattern_io uses a simple string field (vp_pattern)
 * instead of fixed type/domain/name/level fields.
 */
static const char *
pattern_to_string(const struct vlabel_pattern_io *p, char *buf, size_t buflen)
{

	buf[0] = '\0';

	/* Handle negation prefix */
	if (p->vp_flags & VLABEL_MATCH_NEGATE)
		strlcat(buf, "!", buflen);

	/* Empty pattern or "*" means wildcard */
	if (p->vp_pattern[0] == '\0' || strcmp(p->vp_pattern, "*") == 0) {
		strlcat(buf, "*", buflen);
		return buf;
	}

	/* Just append the pattern string */
	strlcat(buf, p->vp_pattern, buflen);

	return buf;
}

/*
 * rule add|remove|clear|list|load|validate
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

	/*
	 * validate doesn't need the device - it just parses locally.
	 * All other commands need it.
	 */
	if (strcmp(argv[0], "validate") != 0)
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

	} else if (strcmp(argv[0], "load") == 0) {
		FILE *fp;
		char line[2048];
		char *start, *end, *comment;
		int lineno = 0;
		int loaded = 0;
		int errors = 0;

		if (argc < 2)
			errx(EX_USAGE, "rule load requires a file path");

		fp = fopen(argv[1], "r");
		if (fp == NULL)
			err(EX_NOINPUT, "open %s", argv[1]);

		while (fgets(line, sizeof(line), fp) != NULL) {
			lineno++;

			/* Strip comments */
			comment = strchr(line, '#');
			if (comment != NULL)
				*comment = '\0';

			/* Trim leading whitespace */
			start = line;
			while (*start == ' ' || *start == '\t')
				start++;

			/* Trim trailing whitespace */
			end = start + strlen(start) - 1;
			while (end > start && (*end == '\n' || *end == '\r' ||
			    *end == ' ' || *end == '\t')) {
				*end = '\0';
				end--;
			}

			/* Skip empty lines */
			if (*start == '\0')
				continue;

			/* Parse and add rule */
			ret = vlabeld_parse_line(start, &rule);
			if (ret < 0) {
				warnx("%s:%d: invalid rule syntax: %s",
				    argv[1], lineno, start);
				errors++;
				continue;
			}
			if (ret > 0) /* empty after parsing */
				continue;

			if (ioctl(dev_fd, VLABEL_IOC_RULE_ADD, &rule) < 0) {
				warn("%s:%d: failed to add rule", argv[1], lineno);
				errors++;
				continue;
			}

			loaded++;
		}

		fclose(fp);

		printf("loaded %d rules", loaded);
		if (errors > 0)
			printf(" (%d errors)", errors);
		printf("\n");

		return (errors > 0 ? 1 : 0);

	} else if (strcmp(argv[0], "validate") == 0) {
		FILE *fp;
		char line[2048];
		char *start, *end, *comment;
		int lineno = 0;
		int valid = 0;
		int errors = 0;
		int warnings = 0;
		int from_file = 0;
		const char *input;

		/* Parse arguments: validate "rule" or validate -f file */
		if (argc >= 3 && strcmp(argv[1], "-f") == 0) {
			from_file = 1;
			input = argv[2];
		} else if (argc >= 2) {
			from_file = 0;
			input = argv[1];
		} else {
			errx(EX_USAGE,
			    "rule validate requires a rule or -f <file>");
		}

		if (!from_file) {
			/* Validate single rule - doesn't need device */
			ret = vlabeld_parse_line(input, &rule);
			if (ret < 0) {
				printf("ERROR: invalid rule syntax\n");
				return (1);
			}
			if (ret > 0) {
				printf("ERROR: empty rule\n");
				return (1);
			}

			/* Check for warnings */
			if (rule.vr_action == VLABEL_ACTION_TRANSITION &&
			    rule.vr_newlabel[0] == '\0') {
				printf("WARNING: transition rule has no newlabel\n");
			}

			printf("OK\n");
			return (0);
		}

		/* Validate file */
		fp = fopen(input, "r");
		if (fp == NULL)
			err(EX_NOINPUT, "open %s", input);

		while (fgets(line, sizeof(line), fp) != NULL) {
			lineno++;

			/* Strip comments */
			comment = strchr(line, '#');
			if (comment != NULL)
				*comment = '\0';

			/* Trim leading whitespace */
			start = line;
			while (*start == ' ' || *start == '\t')
				start++;

			/* Trim trailing whitespace */
			end = start + strlen(start) - 1;
			while (end > start && (*end == '\n' || *end == '\r' ||
			    *end == ' ' || *end == '\t')) {
				*end = '\0';
				end--;
			}

			/* Skip empty lines */
			if (*start == '\0')
				continue;

			/* Parse rule */
			ret = vlabeld_parse_line(start, &rule);
			if (ret < 0) {
				printf("Line %d: ERROR - %s\n", lineno, start);
				errors++;
				continue;
			}
			if (ret > 0)
				continue;

			/* Check for warnings */
			if (rule.vr_action == VLABEL_ACTION_TRANSITION &&
			    rule.vr_newlabel[0] == '\0') {
				printf("Line %d: WARNING - transition without "
				    "newlabel: %s\n", lineno, start);
				warnings++;
			}

			printf("Line %d: OK - %s\n", lineno, start);
			valid++;
		}

		fclose(fp);

		printf("\nSummary: %d valid, %d errors, %d warnings\n",
		    valid, errors, warnings);

		return (errors > 0 ? 1 : 0);

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
		char *p;

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

		/*
		 * Convert newlines to commas for display.
		 * Storage: "type=app\ndomain=web\n"
		 * Display: "type=app,domain=web"
		 */
		for (p = buf; *p; p++) {
			if (*p == '\n') {
				if (*(p + 1) == '\0' || *(p + 1) == '\n')
					*p = '\0';  /* Remove trailing newline */
				else
					*p = ',';   /* Convert to comma */
			}
		}
		printf("%s\n", buf);

	} else if (strcmp(argv[0], "set") == 0) {
		char *converted;

		if (argc < 3)
			errx(EX_USAGE, "label set requires path and label");

		/*
		 * Convert from comma format (user-friendly) to newline format
		 * (storage format). User types: type=app,domain=web
		 * We store: type=app\ndomain=web\n
		 */
		converted = convert_label_format(argv[2]);
		if (converted == NULL)
			errx(EX_OSERR, "failed to convert label format");

		/* Validate the converted label */
		if (validate_label(converted) != 0) {
			free(converted);
			errx(EX_DATAERR, "invalid label format");
		}

		ret = extattr_set_file(argv[1], EXTATTR_NAMESPACE_SYSTEM,
		    "vlabel", converted, strlen(converted));
		free(converted);
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
	if (strcasecmp(opstr, "debug") == 0)
		return VLABEL_OP_DEBUG;
	if (strcasecmp(opstr, "signal") == 0)
		return VLABEL_OP_SIGNAL;
	if (strcasecmp(opstr, "sched") == 0)
		return VLABEL_OP_SCHED;
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
	else if (strcmp(argv[0], "default") == 0)
		return (cmd_default(argc - 1, argv + 1));
	else if (strcmp(argv[0], "stats") == 0)
		return (cmd_stats(argc - 1, argv + 1));
	else if (strcmp(argv[0], "status") == 0)
		return (cmd_status(argc - 1, argv + 1));
	else if (strcmp(argv[0], "limits") == 0)
		return (cmd_limits(argc - 1, argv + 1));
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
