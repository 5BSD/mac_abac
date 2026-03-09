/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 vLabel Project
 * All rights reserved.
 *
 * vlabelctl - vLabel Control Utility
 *
 * Command-line tool for managing the vLabel MAC policy module.
 * Uses mac_syscall() to communicate with the kernel module.
 */

#include <sys/types.h>
#include <sys/extattr.h>
#include <sys/mac.h>

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

#define VLABEL_POLICY_NAME	"mac_vlabel"

/*
 * Wrapper for mac_syscall with error checking
 */
static int
vlabel_syscall(int cmd, void *arg)
{
	int error;

	error = mac_syscall(VLABEL_POLICY_NAME, cmd, arg);
	if (error < 0 && errno == ENOSYS)
		errx(EX_UNAVAILABLE, "vLabel module not loaded");
	return (error);
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
static int cmd_default(int argc, char *argv[]);
static int cmd_stats(int argc, char *argv[]);
static int cmd_status(int argc, char *argv[]);
static int cmd_rule(int argc, char *argv[]);
static int cmd_label(int argc, char *argv[]);
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
	    "  default [allow|deny]\n"
	    "      Get or set default policy when no rule matches\n"
	    "\n"
	    "  stats\n"
	    "      Show statistics\n"
	    "\n"
	    "  status\n"
	    "      Show combined status (mode, stats, rules)\n"
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
	    "  rule list\n"
	    "      List all loaded rules\n"
	    "\n"
	    "  rule clear\n"
	    "      Clear all rules\n"
	    "\n"
	    "  rule validate \"<rule>\"\n"
	    "      Validate a rule without loading it\n"
	    "      Returns OK if valid, ERROR if invalid\n"
	    "\n"
	    "  rule validate -f <file>\n"
	    "      Validate all rules in a file\n"
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
	    "  test <operation> <subject-label> <object-label>\n"
	    "      Test if an operation would be allowed\n"
	    "      Example: vlabelctl test exec \"type=user\" \"type=untrusted\"\n"
	    "\n"
	    "Note: Audit events are logged via FreeBSD's standard audit subsystem.\n"
	    "Use 'praudit' and 'auditreduce' to view MAC policy decisions.\n"
	);
	exit(EX_USAGE);
}

/*
 * mode [disabled|permissive|enforcing]
 */
static int
cmd_mode(int argc, char *argv[])
{
	int mode;
	const char *modestr;

	if (argc == 0) {
		/* Get mode */
		if (vlabel_syscall(VLABEL_SYS_GETMODE, &mode) < 0)
			err(EX_OSERR, "GETMODE");

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

	if (vlabel_syscall(VLABEL_SYS_SETMODE, &mode) < 0)
		err(EX_OSERR, "SETMODE");

	printf("mode set to %s\n", argv[0]);
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

	if (argc == 0) {
		/* Get default policy */
		if (vlabel_syscall(VLABEL_SYS_GETDEFPOL, &policy) < 0)
			err(EX_OSERR, "GETDEFPOL");

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

	if (vlabel_syscall(VLABEL_SYS_SETDEFPOL, &policy) < 0)
		err(EX_OSERR, "SETDEFPOL");

	printf("default policy set to %s\n", argv[0]);
	return (0);
}

/*
 * stats
 */
static int
cmd_stats(int argc __unused, char *argv[] __unused)
{
	struct vlabel_stats stats;

	if (vlabel_syscall(VLABEL_SYS_GETSTATS, &stats) < 0)
		err(EX_OSERR, "GETSTATS");

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
 * status - combined view of mode, stats, rules
 */
static int
cmd_status(int argc __unused, char *argv[] __unused)
{
	struct vlabel_stats stats;
	struct vlabel_rule_list_arg list_arg;
	int mode, defpol;
	const char *modestr, *defpolstr;

	/* Get mode */
	if (vlabel_syscall(VLABEL_SYS_GETMODE, &mode) < 0)
		err(EX_OSERR, "GETMODE");

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

	/* Get default policy */
	if (vlabel_syscall(VLABEL_SYS_GETDEFPOL, &defpol) < 0)
		err(EX_OSERR, "GETDEFPOL");

	defpolstr = (defpol == 0) ? "allow" : "deny";

	/* Get stats */
	if (vlabel_syscall(VLABEL_SYS_GETSTATS, &stats) < 0)
		err(EX_OSERR, "GETSTATS");

	/* Get rule count */
	memset(&list_arg, 0, sizeof(list_arg));
	if (vlabel_syscall(VLABEL_SYS_RULE_LIST, &list_arg) < 0)
		err(EX_OSERR, "RULE_LIST");

	/* Print combined status */
	printf("vLabel Status:\n");
	printf("  Mode:             %s\n", modestr);
	printf("  Default policy:   %s\n", defpolstr);
	printf("  Active rules:     %u\n", list_arg.vrl_total);
	printf("\n");
	printf("Statistics:\n");
	printf("  Access checks:    %ju\n", (uintmax_t)stats.vs_checks);
	printf("  Allowed:          %ju\n", (uintmax_t)stats.vs_allowed);
	printf("  Denied:           %ju\n", (uintmax_t)stats.vs_denied);

	if (stats.vs_checks > 0) {
		double deny_pct = (100.0 * stats.vs_denied) / stats.vs_checks;
		printf("  Denial rate:      %.1f%%\n", deny_pct);
	}

	printf("\n");
	printf("Note: Audit events are logged via FreeBSD's standard audit\n");
	printf("subsystem. Use 'praudit' and 'auditreduce' to view decisions.\n");

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
	printf("\n");
	printf("  Supported Operations:\n");
	printf("    %-12s  0x%08x  %s\n", "exec",       VLABEL_OP_EXEC,       "execute file");
	printf("    %-12s  0x%08x  %s\n", "read",       VLABEL_OP_READ,       "read file contents");
	printf("    %-12s  0x%08x  %s\n", "write",      VLABEL_OP_WRITE,      "write file contents");
	printf("    %-12s  0x%08x  %s\n", "debug",      VLABEL_OP_DEBUG,      "ptrace/procfs debug");
	printf("    %-12s  0x%08x  %s\n", "signal",     VLABEL_OP_SIGNAL,     "send signal");
	printf("    %-12s  0x%08x  %s\n", "sched",      VLABEL_OP_SCHED,      "scheduler control");
	printf("    %-12s  0x%08x  %s\n", "all",        VLABEL_OP_ALL,        "all operations");
	printf("\n");
	printf("  Rule Syntax:\n");
	printf("    action operation subject -> object [=> newlabel]\n");
	printf("\n");
	printf("  Actions:\n");
	printf("    allow       - permit the operation\n");
	printf("    deny        - block the operation (returns EACCES)\n");
	printf("    transition  - change process label on exec\n");
	printf("\n");
	printf("  Pattern Format:\n");
	printf("    *                   - match anything (wildcard)\n");
	printf("    type=value          - match type field\n");
	printf("    type=a,domain=b     - match multiple fields\n");
	printf("    !pattern            - negate the match\n");

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
 * Build a rule_arg buffer from parsed rule
 *
 * The daemon's vlabeld_parse_line() returns vlabel_rule_io (userland format).
 * We convert it to vlabel_rule_arg (kernel mac_syscall format).
 */
static int
build_rule_arg(const char *rule_str, char **bufp, size_t *lenp)
{
	struct vlabel_rule_io rule_io;
	struct vlabel_rule_arg *arg;
	char *buf, *data;
	size_t subject_len, object_len, newlabel_len, total_len;
	int ret;

	/* Parse using existing parser */
	ret = vlabeld_parse_line(rule_str, &rule_io);
	if (ret != 0)
		return (ret);

	/* Calculate lengths (include null terminators) */
	subject_len = strlen(rule_io.vr_subject.vp_pattern) + 1;
	object_len = strlen(rule_io.vr_object.vp_pattern) + 1;
	newlabel_len = (rule_io.vr_action == VLABEL_ACTION_TRANSITION) ?
	    strlen(rule_io.vr_newlabel) + 1 : 0;

	total_len = sizeof(struct vlabel_rule_arg) + subject_len + object_len + newlabel_len;

	buf = calloc(1, total_len);
	if (buf == NULL)
		return (-1);

	arg = (struct vlabel_rule_arg *)buf;
	arg->vr_action = rule_io.vr_action;
	arg->vr_operations = rule_io.vr_operations;
	arg->vr_subject_flags = rule_io.vr_subject.vp_flags;
	arg->vr_object_flags = rule_io.vr_object.vp_flags;
	arg->vr_context.vc_flags = rule_io.vr_context.vc_flags;
	arg->vr_context.vc_cap_sandboxed = rule_io.vr_context.vc_cap_sandboxed;
	arg->vr_context.vc_has_tty = rule_io.vr_context.vc_has_tty;
	arg->vr_context.vc_jail_check = rule_io.vr_context.vc_jail_check;
	arg->vr_context.vc_uid = rule_io.vr_context.vc_uid;
	arg->vr_context.vc_gid = rule_io.vr_context.vc_gid;
	arg->vr_subject_len = subject_len;
	arg->vr_object_len = object_len;
	arg->vr_newlabel_len = newlabel_len;

	/* Copy strings */
	data = buf + sizeof(struct vlabel_rule_arg);
	memcpy(data, rule_io.vr_subject.vp_pattern, subject_len);
	data += subject_len;
	memcpy(data, rule_io.vr_object.vp_pattern, object_len);
	data += object_len;
	if (newlabel_len > 0)
		memcpy(data, rule_io.vr_newlabel, newlabel_len);

	*bufp = buf;
	*lenp = total_len;
	return (0);
}

/*
 * rule add|remove|clear|list|load
 */
static int
cmd_rule(int argc, char *argv[])
{
	uint32_t id;
	int ret;

	if (argc < 1)
		usage();

	if (strcmp(argv[0], "add") == 0) {
		char *buf;
		size_t len;

		if (argc < 2)
			errx(EX_USAGE, "rule add requires a rule string");

		ret = build_rule_arg(argv[1], &buf, &len);
		if (ret < 0)
			errx(EX_DATAERR, "invalid rule syntax");
		if (ret > 0)
			errx(EX_DATAERR, "empty rule");

		if (vlabel_syscall(VLABEL_SYS_RULE_ADD, buf) < 0) {
			free(buf);
			err(EX_OSERR, "RULE_ADD");
		}

		free(buf);
		printf("rule added\n");

	} else if (strcmp(argv[0], "remove") == 0) {
		if (argc < 2)
			errx(EX_USAGE, "rule remove requires a rule ID");

		id = (uint32_t)strtoul(argv[1], NULL, 10);
		if (vlabel_syscall(VLABEL_SYS_RULE_REMOVE, &id) < 0)
			err(EX_OSERR, "RULE_REMOVE");

		printf("removed rule %u\n", id);

	} else if (strcmp(argv[0], "clear") == 0) {
		if (vlabel_syscall(VLABEL_SYS_RULE_CLEAR, NULL) < 0)
			err(EX_OSERR, "RULE_CLEAR");

		printf("all rules cleared\n");

	} else if (strcmp(argv[0], "load") == 0) {
		FILE *fp;
		char line[2048];
		char *start, *end, *comment;
		char *buf;
		size_t len;
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
			ret = build_rule_arg(start, &buf, &len);
			if (ret < 0) {
				warnx("%s:%d: invalid rule syntax: %s",
				    argv[1], lineno, start);
				errors++;
				continue;
			}
			if (ret > 0) /* empty after parsing */
				continue;

			if (vlabel_syscall(VLABEL_SYS_RULE_ADD, buf) < 0) {
				warn("%s:%d: failed to add rule", argv[1], lineno);
				free(buf);
				errors++;
				continue;
			}

			free(buf);
			loaded++;
		}

		fclose(fp);

		printf("loaded %d rules", loaded);
		if (errors > 0)
			printf(" (%d errors)", errors);
		printf("\n");

		return (errors > 0 ? 1 : 0);

	} else if (strcmp(argv[0], "list") == 0) {
		struct vlabel_rule_list_arg list_arg;
		struct vlabel_rule_out *out;
		char *buf, *p;
		uint32_t i;
		const char *action_str;

		/* Query rule count first */
		memset(&list_arg, 0, sizeof(list_arg));
		if (vlabel_syscall(VLABEL_SYS_RULE_LIST, &list_arg) < 0)
			err(EX_OSERR, "RULE_LIST");

		if (list_arg.vrl_total == 0) {
			printf("(no rules loaded)\n");
			return (0);
		}

		/* Allocate buffer for rules (estimate size) */
		list_arg.vrl_buflen = list_arg.vrl_total * 512;
		buf = malloc(list_arg.vrl_buflen);
		if (buf == NULL)
			err(EX_OSERR, "malloc");

		list_arg.vrl_buf = buf;
		list_arg.vrl_offset = 0;

		if (vlabel_syscall(VLABEL_SYS_RULE_LIST, &list_arg) < 0) {
			free(buf);
			err(EX_OSERR, "RULE_LIST");
		}

		printf("Loaded rules: %u\n\n", list_arg.vrl_count);

		/* Parse and print rules */
		p = buf;
		for (i = 0; i < list_arg.vrl_count; i++) {
			char opsbuf[128];
			const char *subject, *object, *newlabel;

			out = (struct vlabel_rule_out *)p;
			subject = p + sizeof(struct vlabel_rule_out);
			object = subject + out->vr_subject_len;
			newlabel = object + out->vr_object_len;

			switch (out->vr_action) {
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

			printf("  [%u] %s %s %s%s -> %s%s",
			    out->vr_id,
			    action_str,
			    ops_to_string(out->vr_operations, opsbuf, sizeof(opsbuf)),
			    (out->vr_subject_flags & VLABEL_MATCH_NEGATE) ? "!" : "",
			    subject[0] ? subject : "*",
			    (out->vr_object_flags & VLABEL_MATCH_NEGATE) ? "!" : "",
			    object[0] ? object : "*");

			if (out->vr_action == VLABEL_ACTION_TRANSITION &&
			    out->vr_newlabel_len > 0)
				printf(" => %s", newlabel);

			printf("\n");

			/* Advance to next rule */
			p += sizeof(struct vlabel_rule_out) +
			    out->vr_subject_len + out->vr_object_len +
			    out->vr_newlabel_len;
		}

		free(buf);

	} else if (strcmp(argv[0], "validate") == 0) {
		/*
		 * Validate a rule or file without loading into kernel.
		 * Supports both single rule validation and file validation (-f).
		 */
		int valid_count = 0;
		int warning_count = 0;
		int error_count = 0;

		if (argc < 2)
			errx(EX_USAGE, "rule validate requires a rule string or -f <file>");

		if (strcmp(argv[1], "-f") == 0) {
			/* File validation mode */
			FILE *fp;
			char line[2048];
			char *start, *end, *comment;
			int lineno = 0;
			struct vlabel_rule_io rule_io;

			if (argc < 3)
				errx(EX_USAGE, "rule validate -f requires a file path");

			fp = fopen(argv[2], "r");
			if (fp == NULL)
				err(EX_NOINPUT, "open %s", argv[2]);

			printf("Validating %s...\n", argv[2]);

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
				ret = vlabeld_parse_line(start, &rule_io);
				if (ret < 0) {
					printf("  %s:%d: ERROR: invalid syntax: %s\n",
					    argv[2], lineno, start);
					error_count++;
					continue;
				}
				if (ret > 0) /* empty after parsing */
					continue;

				/* Check for warnings */
				if (rule_io.vr_action == VLABEL_ACTION_TRANSITION &&
				    rule_io.vr_newlabel[0] == '\0') {
					printf("  %s:%d: WARNING: transition without newlabel: %s\n",
					    argv[2], lineno, start);
					warning_count++;
				}

				valid_count++;
			}

			fclose(fp);

			printf("\nValidation complete: %d valid, %d warnings, %d errors\n",
			    valid_count, warning_count, error_count);

			return (error_count > 0 ? 1 : 0);

		} else {
			/* Single rule validation mode */
			struct vlabel_rule_io rule_io;

			ret = vlabeld_parse_line(argv[1], &rule_io);
			if (ret < 0) {
				printf("ERROR: invalid rule syntax\n");
				return (1);
			}
			if (ret > 0) {
				printf("ERROR: empty rule\n");
				return (1);
			}

			/* Check for warnings */
			if (rule_io.vr_action == VLABEL_ACTION_TRANSITION &&
			    rule_io.vr_newlabel[0] == '\0') {
				printf("WARNING: transition rule without newlabel\n");
				printf("OK (with warnings)\n");
				return (0);
			}

			printf("OK\n");
			return (0);
		}

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
		int fd;

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

		ret = extattr_set_file(argv[1], EXTATTR_NAMESPACE_SYSTEM,
		    "vlabel", converted, strlen(converted));
		free(converted);
		if (ret < 0)
			err(EX_OSERR, "extattr_set_file");

		/*
		 * Refresh the kernel's cached vnode label by re-reading
		 * from extattr. This enables live relabeling on ZFS and
		 * other filesystems that don't support MNT_MULTILABEL.
		 */
		fd = open(argv[1], O_RDONLY);
		if (fd < 0) {
			warn("warning: could not open file for refresh");
		} else {
			ret = mac_syscall(VLABEL_POLICY_NAME, VLABEL_SYS_REFRESH, &fd);
			if (ret < 0)
				warn("warning: refresh syscall failed (errno=%d)", errno);
			else
				printf("label refreshed\n");
			close(fd);
		}

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
	struct vlabel_test_arg *test_arg;
	char *buf;
	size_t subject_len, object_len, total_len;
	uint32_t op;

	if (argc < 3)
		errx(EX_USAGE, "test requires: <operation> <subject-label> <object-label>");

	/* Parse operation */
	op = parse_operation(argv[0]);
	if (op == 0)
		errx(EX_USAGE, "unknown operation: %s", argv[0]);

	/* Build test argument */
	subject_len = strlen(argv[1]) + 1;
	object_len = strlen(argv[2]) + 1;
	total_len = sizeof(struct vlabel_test_arg) + subject_len + object_len;

	buf = calloc(1, total_len);
	if (buf == NULL)
		err(EX_OSERR, "calloc");

	test_arg = (struct vlabel_test_arg *)buf;
	test_arg->vt_operation = op;
	test_arg->vt_subject_len = subject_len;
	test_arg->vt_object_len = object_len;

	memcpy(buf + sizeof(struct vlabel_test_arg), argv[1], subject_len);
	memcpy(buf + sizeof(struct vlabel_test_arg) + subject_len, argv[2], object_len);

	/* Perform test */
	if (vlabel_syscall(VLABEL_SYS_TEST, buf) < 0) {
		free(buf);
		err(EX_OSERR, "TEST");
	}

	/* Print result */
	printf("Operation:   %s\n", argv[0]);
	printf("Subject:     %s\n", argv[1]);
	printf("Object:      %s\n", argv[2]);
	printf("Result:      %s\n", test_arg->vt_result == 0 ? "ALLOW" : "DENY");

	if (test_arg->vt_rule_id != 0)
		printf("Matched:     rule %u\n", test_arg->vt_rule_id);
	else
		printf("Matched:     (default policy)\n");

	int result = (test_arg->vt_result == 0) ? 0 : 1;
	free(buf);

	/* Exit with non-zero if denied, for scripting */
	return result;
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
	else if (strcmp(argv[0], "test") == 0)
		return (cmd_test(argc - 1, argv + 1));
	else if (strcmp(argv[0], "help") == 0 || strcmp(argv[0], "-h") == 0)
		usage();
	else
		errx(EX_USAGE, "unknown command: %s", argv[0]);

	return (0);
}
