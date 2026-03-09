#!/usr/sbin/dtrace -qs
/*
 * vlabel-denials.d - Watch all access denials in real-time
 *
 * Usage: dtrace -s vlabel-denials.d
 *
 * Shows subject label, object label, operation, and matching rule for each denial.
 */

#pragma D option quiet

dtrace:::BEGIN
{
    printf("Watching vLabel access denials...\n");
    printf("%-20s %-20s %-10s %s\n", "SUBJECT", "OBJECT", "OP", "RULE");
    printf("%-20s %-20s %-10s %s\n", "-------", "------", "--", "----");
}

vlabel:::check-deny
{
    /* arg0=subject, arg1=object, arg2=op, arg3=rule_id */
    printf("%-20s %-20s 0x%-8x %u\n",
        stringof(arg0),
        stringof(arg1),
        arg2,
        arg3);
}

dtrace:::END
{
    printf("\nDone.\n");
}
