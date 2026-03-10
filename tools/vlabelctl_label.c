/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 vLabel Project
 * All rights reserved.
 *
 * vlabelctl - Label and test command handlers
 *
 * Handles: label get|set|remove, test
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
#include <unistd.h>

#include "../kernel/mac_vlabel.h"
#include "vlabelctl.h"

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
	if (strcasecmp(opstr, "open") == 0)
		return VLABEL_OP_OPEN;
	if (strcasecmp(opstr, "mmap") == 0)
		return VLABEL_OP_MMAP;
	if (strcasecmp(opstr, "access") == 0)
		return VLABEL_OP_ACCESS;
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
	if (strcasecmp(opstr, "stat") == 0)
		return VLABEL_OP_STAT;
	if (strcasecmp(opstr, "readdir") == 0)
		return VLABEL_OP_READDIR;
	if (strcasecmp(opstr, "create") == 0)
		return VLABEL_OP_CREATE;
	if (strcasecmp(opstr, "lookup") == 0)
		return VLABEL_OP_LOOKUP;
	/* File/directory manipulation operations */
	if (strcasecmp(opstr, "link") == 0)
		return VLABEL_OP_LINK;
	if (strcasecmp(opstr, "rename") == 0)
		return VLABEL_OP_RENAME;
	if (strcasecmp(opstr, "unlink") == 0)
		return VLABEL_OP_UNLINK;
	if (strcasecmp(opstr, "chdir") == 0)
		return VLABEL_OP_CHDIR;
	/* Socket operations */
	if (strcasecmp(opstr, "connect") == 0)
		return VLABEL_OP_CONNECT;
	if (strcasecmp(opstr, "bind") == 0)
		return VLABEL_OP_BIND;
	if (strcasecmp(opstr, "listen") == 0)
		return VLABEL_OP_LISTEN;
	if (strcasecmp(opstr, "accept") == 0)
		return VLABEL_OP_ACCEPT;
	if (strcasecmp(opstr, "send") == 0)
		return VLABEL_OP_SEND;
	if (strcasecmp(opstr, "receive") == 0)
		return VLABEL_OP_RECEIVE;
	if (strcasecmp(opstr, "all") == 0)
		return VLABEL_OP_ALL;

	return 0;
}

/*
 * label get|set|remove <path>
 */
int
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
 * test <operation> <subject-label> <object-label>
 *
 * Test if an operation would be allowed without actually performing it.
 */
int
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
