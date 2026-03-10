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
#include <sys/mac.h>

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>

#include "../kernel/mac_vlabel.h"
#include "vlabelctl.h"

/*
 * Wrapper for mac_syscall with error checking
 */
int
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
char *
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

/*
 * Helper to format an operation bitmask as a string
 */
const char *
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
	if (ops & VLABEL_OP_OPEN)
		strlcat(buf, "open,", buflen);
	if (ops & VLABEL_OP_ACCESS)
		strlcat(buf, "access,", buflen);
	if (ops & VLABEL_OP_MMAP)
		strlcat(buf, "mmap,", buflen);
	if (ops & VLABEL_OP_DEBUG)
		strlcat(buf, "debug,", buflen);
	if (ops & VLABEL_OP_SIGNAL)
		strlcat(buf, "signal,", buflen);
	if (ops & VLABEL_OP_SCHED)
		strlcat(buf, "sched,", buflen);
	if (ops & VLABEL_OP_READDIR)
		strlcat(buf, "readdir,", buflen);
	if (ops & VLABEL_OP_CREATE)
		strlcat(buf, "create,", buflen);
	if (ops & VLABEL_OP_SETEXTATTR)
		strlcat(buf, "setextattr,", buflen);
	if (ops & VLABEL_OP_GETEXTATTR)
		strlcat(buf, "getextattr,", buflen);
	if (ops & VLABEL_OP_LOOKUP)
		strlcat(buf, "lookup,", buflen);
	if (ops & VLABEL_OP_LINK)
		strlcat(buf, "link,", buflen);
	if (ops & VLABEL_OP_RENAME)
		strlcat(buf, "rename,", buflen);
	if (ops & VLABEL_OP_UNLINK)
		strlcat(buf, "unlink,", buflen);
	if (ops & VLABEL_OP_CHDIR)
		strlcat(buf, "chdir,", buflen);
	if (ops & VLABEL_OP_CONNECT)
		strlcat(buf, "connect,", buflen);
	if (ops & VLABEL_OP_BIND)
		strlcat(buf, "bind,", buflen);
	if (ops & VLABEL_OP_LISTEN)
		strlcat(buf, "listen,", buflen);
	if (ops & VLABEL_OP_ACCEPT)
		strlcat(buf, "accept,", buflen);
	if (ops & VLABEL_OP_SEND)
		strlcat(buf, "send,", buflen);
	if (ops & VLABEL_OP_RECEIVE)
		strlcat(buf, "receive,", buflen);

	/* Remove trailing comma */
	len = strlen(buf);
	if (len > 0 && buf[len - 1] == ',')
		buf[len - 1] = '\0';

	return buf[0] ? buf : "none";
}

void
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
	    "      Add a rule, prints assigned ID\n"
	    "      Format: action ops subject [ctx:...] -> object [ctx:...] [=> newlabel]\n"
	    "      Examples:\n"
	    "        vlabelctl rule add \"deny exec * -> type=untrusted\"\n"
	    "        vlabelctl rule add \"deny read * ctx:jail=any -> type=secret\"\n"
	    "        vlabelctl rule add \"deny debug * -> * ctx:sandboxed=true\"\n"
	    "\n"
	    "  rule remove <id>\n"
	    "      Remove a rule by ID\n"
	    "\n"
	    "  rule load <file>\n"
	    "      Atomic load: clear all rules, load from file\n"
	    "      On parse error, existing rules remain unchanged\n"
	    "\n"
	    "  rule append <file>\n"
	    "      Append rules from file (keeps existing rules)\n"
	    "\n"
	    "  rule list\n"
	    "      List all loaded rules with IDs\n"
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
int
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
int
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
int
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
int
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
int
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
	printf("    %-12s  0x%08x  %s\n", "open",       VLABEL_OP_OPEN,       "open file");
	printf("    %-12s  0x%08x  %s\n", "mmap",       VLABEL_OP_MMAP,       "memory map file");
	printf("    %-12s  0x%08x  %s\n", "access",     VLABEL_OP_ACCESS,     "access() check");
	printf("    %-12s  0x%08x  %s\n", "setextattr", VLABEL_OP_SETEXTATTR, "set extended attr");
	printf("    %-12s  0x%08x  %s\n", "getextattr", VLABEL_OP_GETEXTATTR, "get extended attr");
	printf("    %-12s  0x%08x  %s\n", "debug",      VLABEL_OP_DEBUG,      "ptrace/procfs debug");
	printf("    %-12s  0x%08x  %s\n", "signal",     VLABEL_OP_SIGNAL,     "send signal");
	printf("    %-12s  0x%08x  %s\n", "sched",      VLABEL_OP_SCHED,      "scheduler control");
	printf("    %-12s  0x%08x  %s\n", "link",       VLABEL_OP_LINK,       "create hard link");
	printf("    %-12s  0x%08x  %s\n", "rename",     VLABEL_OP_RENAME,     "rename file");
	printf("    %-12s  0x%08x  %s\n", "unlink",     VLABEL_OP_UNLINK,     "unlink/delete file");
	printf("    %-12s  0x%08x  %s\n", "chdir",      VLABEL_OP_CHDIR,      "change directory");
	printf("    %-12s  0x%08x  %s\n", "connect",    VLABEL_OP_CONNECT,    "socket connect");
	printf("    %-12s  0x%08x  %s\n", "bind",       VLABEL_OP_BIND,       "socket bind");
	printf("    %-12s  0x%08x  %s\n", "listen",     VLABEL_OP_LISTEN,     "socket listen");
	printf("    %-12s  0x%08x  %s\n", "accept",     VLABEL_OP_ACCEPT,     "socket accept");
	printf("    %-12s  0x%08x  %s\n", "send",       VLABEL_OP_SEND,       "socket send");
	printf("    %-12s  0x%08x  %s\n", "receive",    VLABEL_OP_RECEIVE,    "socket receive");
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
