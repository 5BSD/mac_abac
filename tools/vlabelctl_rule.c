/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 vLabel Project
 * All rights reserved.
 *
 * vlabelctl - Rule command handlers
 *
 * Handles: rule add|remove|clear|list|load|append|validate
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
#include "../daemon/vlabeld.h"
#include "vlabelctl.h"

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
	/* Copy subject context constraints */
	arg->vr_subj_context.vc_flags = rule_io.vr_subj_context.vc_flags;
	arg->vr_subj_context.vc_cap_sandboxed = rule_io.vr_subj_context.vc_cap_sandboxed;
	arg->vr_subj_context.vc_has_tty = rule_io.vr_subj_context.vc_has_tty;
	arg->vr_subj_context.vc_jail_check = rule_io.vr_subj_context.vc_jail_check;
	arg->vr_subj_context.vc_uid = rule_io.vr_subj_context.vc_uid;
	arg->vr_subj_context.vc_gid = rule_io.vr_subj_context.vc_gid;
	/* Copy object context constraints */
	arg->vr_obj_context.vc_flags = rule_io.vr_obj_context.vc_flags;
	arg->vr_obj_context.vc_cap_sandboxed = rule_io.vr_obj_context.vc_cap_sandboxed;
	arg->vr_obj_context.vc_has_tty = rule_io.vr_obj_context.vc_has_tty;
	arg->vr_obj_context.vc_jail_check = rule_io.vr_obj_context.vc_jail_check;
	arg->vr_obj_context.vc_uid = rule_io.vr_obj_context.vc_uid;
	arg->vr_obj_context.vc_gid = rule_io.vr_obj_context.vc_gid;
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
 * rule add|remove|clear|list|load|append|validate
 */
int
cmd_rule(int argc, char *argv[])
{
	uint32_t id;
	int ret;

	if (argc < 1)
		usage();

	if (strcmp(argv[0], "add") == 0) {
		char *buf;
		size_t len;
		struct vlabel_rule_arg *arg;

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

		arg = (struct vlabel_rule_arg *)buf;
		printf("rule %u added\n", arg->vr_id);
		free(buf);

	} else if (strcmp(argv[0], "append") == 0) {
		/*
		 * Append rules from file without clearing existing rules.
		 * Unlike 'load', this adds to existing rules.
		 */
		FILE *fp;
		char line[2048];
		char *start, *end, *comment;
		char *buf;
		size_t len;
		struct vlabel_rule_arg *arg;
		int lineno = 0;
		int added = 0;
		int errors = 0;

		if (argc < 2)
			errx(EX_USAGE, "rule append requires a file path");

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

			arg = (struct vlabel_rule_arg *)buf;
			printf("  rule %u added\n", arg->vr_id);
			free(buf);
			added++;
		}

		fclose(fp);

		printf("appended %d rules", added);
		if (errors > 0)
			printf(" (%d errors)", errors);
		printf("\n");

		return (errors > 0 ? 1 : 0);

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
		/*
		 * Atomic rule load - like PF's pfctl -f
		 *
		 * First pass: parse all rules, build packed buffer
		 * Second pass: send to kernel atomically
		 *
		 * On success: old rules are cleared, new rules loaded
		 * On failure: old rules remain unchanged
		 */
		FILE *fp;
		char line[2048];
		char *start, *end, *comment;
		char *rule_buf;
		size_t rule_len;
		int lineno = 0;
		int rule_count = 0;
		int errors = 0;

		/* Dynamic buffer for packed rules */
		char *load_buf = NULL;
		size_t load_buflen = 0;
		size_t load_bufused = 0;

		struct vlabel_rule_load_arg load_arg;

		if (argc < 2)
			errx(EX_USAGE, "rule load requires a file path");

		fp = fopen(argv[1], "r");
		if (fp == NULL)
			err(EX_NOINPUT, "open %s", argv[1]);

		/* First pass: parse all rules into buffer */
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
			ret = build_rule_arg(start, &rule_buf, &rule_len);
			if (ret < 0) {
				warnx("%s:%d: invalid rule syntax: %s",
				    argv[1], lineno, start);
				errors++;
				continue;
			}
			if (ret > 0) /* empty after parsing */
				continue;

			/* Grow buffer if needed */
			if (load_bufused + rule_len > load_buflen) {
				size_t newlen = load_buflen == 0 ? 8192 :
				    load_buflen * 2;
				while (newlen < load_bufused + rule_len)
					newlen *= 2;
				load_buf = realloc(load_buf, newlen);
				if (load_buf == NULL) {
					free(rule_buf);
					err(EX_OSERR, "realloc");
				}
				load_buflen = newlen;
			}

			/* Append rule to buffer */
			memcpy(load_buf + load_bufused, rule_buf, rule_len);
			load_bufused += rule_len;
			rule_count++;

			free(rule_buf);
		}

		fclose(fp);

		if (errors > 0) {
			warnx("aborting load due to %d parse errors", errors);
			free(load_buf);
			return (1);
		}

		if (rule_count == 0) {
			printf("no rules to load (clearing existing rules)\n");
		}

		/* Atomic load via kernel syscall */
		memset(&load_arg, 0, sizeof(load_arg));
		load_arg.vrl_count = rule_count;
		load_arg.vrl_buflen = load_bufused;
		load_arg.vrl_buf = load_buf;

		if (vlabel_syscall(VLABEL_SYS_RULE_LOAD, &load_arg) < 0) {
			free(load_buf);
			err(EX_OSERR, "RULE_LOAD");
		}

		free(load_buf);

		printf("loaded %u rules (atomic)\n", load_arg.vrl_loaded);
		return (0);

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

			/* Print subject context constraints if any */
			if (out->vr_subj_context.vc_flags != 0) {
				printf(" subj_context:");
				int first = 1;
				if (out->vr_subj_context.vc_flags & VLABEL_CTX_CAP_SANDBOXED) {
					printf("%ssandboxed=%s", first ? "" : ",",
					    out->vr_subj_context.vc_cap_sandboxed ? "true" : "false");
					first = 0;
				}
				if (out->vr_subj_context.vc_flags & VLABEL_CTX_JAIL) {
					if (out->vr_subj_context.vc_jail_check == 0)
						printf("%sjail=host", first ? "" : ",");
					else if (out->vr_subj_context.vc_jail_check == -1)
						printf("%sjail=any", first ? "" : ",");
					else
						printf("%sjail=%d", first ? "" : ",",
						    out->vr_subj_context.vc_jail_check);
					first = 0;
				}
				if (out->vr_subj_context.vc_flags & VLABEL_CTX_UID) {
					printf("%suid=%u", first ? "" : ",",
					    out->vr_subj_context.vc_uid);
					first = 0;
				}
				if (out->vr_subj_context.vc_flags & VLABEL_CTX_GID) {
					printf("%sgid=%u", first ? "" : ",",
					    out->vr_subj_context.vc_gid);
					first = 0;
				}
			}

			/* Print object context constraints if any */
			if (out->vr_obj_context.vc_flags != 0) {
				printf(" obj_context:");
				int first = 1;
				if (out->vr_obj_context.vc_flags & VLABEL_CTX_CAP_SANDBOXED) {
					printf("%ssandboxed=%s", first ? "" : ",",
					    out->vr_obj_context.vc_cap_sandboxed ? "true" : "false");
					first = 0;
				}
				if (out->vr_obj_context.vc_flags & VLABEL_CTX_JAIL) {
					if (out->vr_obj_context.vc_jail_check == 0)
						printf("%sjail=host", first ? "" : ",");
					else if (out->vr_obj_context.vc_jail_check == -1)
						printf("%sjail=any", first ? "" : ",");
					else
						printf("%sjail=%d", first ? "" : ",",
						    out->vr_obj_context.vc_jail_check);
					first = 0;
				}
				if (out->vr_obj_context.vc_flags & VLABEL_CTX_UID) {
					printf("%suid=%u", first ? "" : ",",
					    out->vr_obj_context.vc_uid);
					first = 0;
				}
				if (out->vr_obj_context.vc_flags & VLABEL_CTX_GID) {
					printf("%sgid=%u", first ? "" : ",",
					    out->vr_obj_context.vc_gid);
					first = 0;
				}
			}

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
