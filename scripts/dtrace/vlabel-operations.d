#!/usr/sbin/dtrace -qs
/*
 * vlabel-operations.d - Count operations by type
 *
 * Usage: dtrace -s vlabel-operations.d
 *
 * Shows distribution of operations (read, write, exec, etc.)
 * and whether they were allowed or denied.
 */

#pragma D option quiet

dtrace:::BEGIN
{
    /* Define operation names for readability */
    ops[0x01] = "read";
    ops[0x02] = "write";
    ops[0x04] = "exec";
    ops[0x08] = "open";
    ops[0x10] = "stat";
    ops[0x20] = "create";
    ops[0x40] = "unlink";
    ops[0x80] = "lookup";

    printf("Counting vLabel operations...\n");
    printf("Press Ctrl+C to see results.\n\n");
}

vlabel:::check-allow
{
    @allowed[arg2] = count();
    @total["Total allowed"] = count();
}

vlabel:::check-deny
{
    @denied[arg2] = count();
    @total["Total denied"] = count();
}

dtrace:::END
{
    printf("\n=== Allowed Operations ===\n");
    printf("%-10s %s\n", "OP_MASK", "COUNT");
    printa("0x%-8x %@d\n", @allowed);

    printf("\n=== Denied Operations ===\n");
    printf("%-10s %s\n", "OP_MASK", "COUNT");
    printa("0x%-8x %@d\n", @denied);

    printf("\n=== Totals ===\n");
    printa(@total);

    printf("\nOperation masks: read=0x01, write=0x02, exec=0x04, open=0x08\n");
    printf("                 stat=0x10, create=0x20, unlink=0x40, lookup=0x80\n");
}
