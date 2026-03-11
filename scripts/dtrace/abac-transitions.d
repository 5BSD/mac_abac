#!/usr/sbin/dtrace -qs
/*
 * abac-transitions.d - Watch label transitions on exec
 *
 * Usage: dtrace -s abac-transitions.d
 *
 * Shows when processes change labels during exec.
 * Useful for tracking privilege escalation/sandboxing.
 */

#pragma D option quiet

dtrace:::BEGIN
{
    printf("Watching ABAC transitions...\n");
    printf("%-8s %-25s %-25s %s\n", "PID", "OLD_LABEL", "NEW_LABEL", "EXEC_LABEL");
    printf("%-8s %-25s %-25s %s\n", "---", "---------", "---------", "----------");
}

abac:::transition-exec
{
    /* arg0=old_label, arg1=new_label, arg2=exec_label, arg3=pid */
    printf("%-8d %-25s %-25s %s\n",
        arg3,
        stringof(arg0),
        stringof(arg1),
        stringof(arg2));
}

dtrace:::END
{
    printf("\nDone.\n");
}
