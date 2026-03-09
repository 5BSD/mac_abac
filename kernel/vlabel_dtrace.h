/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 vLabel Project
 * All rights reserved.
 *
 * vLabel DTrace Probe Definitions
 *
 * DTrace provider: vlabel
 *
 * Probe naming convention:
 *   vlabel:<module>:<function>:<name>
 *
 * Example usage:
 *   dtrace -n 'vlabel:::check-deny { printf("%s -> %s op=%x",
 *       stringof(arg0), stringof(arg1), arg2); }'
 *
 *   dtrace -n 'vlabel:::rule-match { @[arg0] = count(); }'
 *
 *   dtrace -n 'vlabel:::check-entry { self->ts = timestamp; }
 *              vlabel:::check-return { @["ns"] = quantize(timestamp - self->ts); }'
 */

#ifndef _VLABEL_DTRACE_H_
#define _VLABEL_DTRACE_H_

#include <sys/sdt.h>

/*
 * Provider declaration
 */
SDT_PROVIDER_DECLARE(vlabel);

/*
 * Access check probes
 *
 * check-entry: Fired at start of access check
 *   arg0: subject label string (char *)
 *   arg1: object label string (char *)
 *   arg2: operation bitmask (uint32_t)
 *
 * check-return: Fired at end of access check
 *   arg0: result (0=allow, EACCES=deny)
 *   arg1: operation bitmask (uint32_t)
 *
 * check-allow: Fired when access is allowed
 *   arg0: subject label string (char *)
 *   arg1: object label string (char *)
 *   arg2: operation bitmask (uint32_t)
 *   arg3: matching rule ID (0=default policy)
 *
 * check-deny: Fired when access is denied
 *   arg0: subject label string (char *)
 *   arg1: object label string (char *)
 *   arg2: operation bitmask (uint32_t)
 *   arg3: matching rule ID (0=default policy)
 */
SDT_PROBE_DECLARE(vlabel, rules, check, entry);
SDT_PROBE_DECLARE(vlabel, rules, check, return);
SDT_PROBE_DECLARE(vlabel, rules, check, allow);
SDT_PROBE_DECLARE(vlabel, rules, check, deny);

/*
 * Rule matching probes
 *
 * rule-match: Fired when a rule matches (before action applied)
 *   arg0: rule ID (uint32_t)
 *   arg1: action (0=allow, 1=deny, 2=transition)
 *   arg2: operation bitmask (uint32_t)
 *
 * rule-nomatch: Fired when no rule matches (default policy used)
 *   arg0: default policy (0=allow, 1=deny)
 *   arg1: operation bitmask (uint32_t)
 */
SDT_PROBE_DECLARE(vlabel, rules, rule, match);
SDT_PROBE_DECLARE(vlabel, rules, rule, nomatch);

/*
 * Label transition probes
 *
 * transition: Fired when a process label changes on exec
 *   arg0: old label string (char *)
 *   arg1: new label string (char *)
 *   arg2: executable label string (char *)
 *   arg3: pid (pid_t)
 */
SDT_PROBE_DECLARE(vlabel, cred, transition, exec);

/*
 * Label read probes
 *
 * label-read: Fired when a label is read from extattr
 *   arg0: label string (char *)
 *   arg1: vnode pointer (struct vnode *)
 *
 * label-default: Fired when a default label is assigned
 *   arg0: is_subject (1=process, 0=file)
 */
SDT_PROBE_DECLARE(vlabel, label, extattr, read);
SDT_PROBE_DECLARE(vlabel, label, extattr, default);

/*
 * Rule management probes
 *
 * rule-add: Fired when a rule is added
 *   arg0: rule ID (uint32_t)
 *   arg1: action (uint8_t)
 *   arg2: operations bitmask (uint32_t)
 *
 * rule-remove: Fired when a rule is removed
 *   arg0: rule ID (uint32_t)
 *
 * rule-clear: Fired when all rules are cleared
 *   arg0: count of rules cleared (uint32_t)
 */
SDT_PROBE_DECLARE(vlabel, rules, rule, add);
SDT_PROBE_DECLARE(vlabel, rules, rule, remove);
SDT_PROBE_DECLARE(vlabel, rules, rule, clear);

/*
 * Mode change probes
 *
 * mode-change: Fired when enforcement mode changes
 *   arg0: old mode (int)
 *   arg1: new mode (int)
 */
SDT_PROBE_DECLARE(vlabel, policy, mode, change);

#endif /* !_VLABEL_DTRACE_H_ */
