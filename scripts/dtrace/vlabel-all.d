#!/usr/sbin/dtrace -qs
/*
 * vlabel-all.d - Real-time trace of all vLabel activity
 *
 * Usage: dtrace -s vlabel-all.d
 *
 * Shows all vLabel events as they happen.
 * Warning: Can be very verbose under load.
 */

#pragma D option quiet

dtrace:::BEGIN
{
    printf("Tracing ALL vLabel activity...\n");
    printf("Press Ctrl+C to stop.\n\n");
    printf("%-12s %-8s %s\n", "TIMESTAMP", "PROBE", "DETAILS");
    printf("%-12s %-8s %s\n", "---------", "-----", "-------");
}

vlabel:::check-entry
{
    printf("%-12d %-8s subj=%s obj=%s op=0x%x\n",
        timestamp/1000000,
        "ENTRY",
        stringof(arg0), stringof(arg1), arg2);
}

vlabel:::check-return
{
    printf("%-12d %-8s result=%d op=0x%x\n",
        timestamp/1000000,
        "RETURN",
        arg0, arg1);
}

vlabel:::check-allow
{
    printf("%-12d %-8s subj=%s obj=%s op=0x%x rule=%u\n",
        timestamp/1000000,
        "ALLOW",
        stringof(arg0), stringof(arg1), arg2, arg3);
}

vlabel:::check-deny
{
    printf("%-12d %-8s subj=%s obj=%s op=0x%x rule=%u\n",
        timestamp/1000000,
        "DENY",
        stringof(arg0), stringof(arg1), arg2, arg3);
}

vlabel:::rule-match
{
    printf("%-12d %-8s rule=%u action=%u op=0x%x\n",
        timestamp/1000000,
        "MATCH",
        arg0, arg1, arg2);
}

vlabel:::rule-nomatch
{
    printf("%-12d %-8s default_policy=%d op=0x%x\n",
        timestamp/1000000,
        "NOMATCH",
        arg0, arg1);
}

vlabel:::transition-exec
{
    printf("%-12d %-8s pid=%d old=%s new=%s exec=%s\n",
        timestamp/1000000,
        "TRANS",
        arg3, stringof(arg0), stringof(arg1), stringof(arg2));
}

vlabel:::extattr-read
{
    printf("%-12d %-8s label=%s\n",
        timestamp/1000000,
        "EXTATTR",
        stringof(arg0));
}

vlabel:::extattr-default
{
    printf("%-12d %-8s is_subject=%d\n",
        timestamp/1000000,
        "DEFAULT",
        arg0);
}

vlabel:::rule-add
{
    printf("%-12d %-8s id=%u action=%u ops=0x%x\n",
        timestamp/1000000,
        "RULE+",
        arg0, arg1, arg2);
}

vlabel:::rule-remove
{
    printf("%-12d %-8s id=%u\n",
        timestamp/1000000,
        "RULE-",
        arg0);
}

vlabel:::rule-clear
{
    printf("%-12d %-8s count=%u\n",
        timestamp/1000000,
        "CLEAR",
        arg0);
}

vlabel:::mode-change
{
    printf("%-12d %-8s old=%d new=%d\n",
        timestamp/1000000,
        "MODE",
        arg0, arg1);
}

dtrace:::END
{
    printf("\nTrace complete.\n");
}
