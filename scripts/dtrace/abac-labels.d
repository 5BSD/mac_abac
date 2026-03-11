#!/usr/sbin/dtrace -qs
/*
 * abac-labels.d - Track label reads from extended attributes
 *
 * Usage: dtrace -s abac-labels.d
 *
 * Shows labels being read from filesystems and defaults assigned.
 * Useful for understanding label propagation.
 */

#pragma D option quiet

dtrace:::BEGIN
{
    printf("Watching ABAC label operations...\n");
    printf("Press Ctrl+C to see results.\n\n");
}

abac:::extattr-read
{
    /* arg0=label, arg1=vnode */
    @read_labels[stringof(arg0)] = count();
    @total["Labels read from extattr"] = count();
    printf("READ:    %s\n", stringof(arg0));
}

abac:::extattr-default
{
    /* arg0=is_subject (1=process, 0=file) */
    @defaults[arg0 ? "subject (process)" : "object (file)"] = count();
    @total["Default labels assigned"] = count();
    printf("DEFAULT: %s\n", arg0 ? "subject (process)" : "object (file)");
}

dtrace:::END
{
    printf("\n=== Labels Read from Extattr ===\n");
    printa("  %-40s %@d\n", @read_labels);

    printf("\n=== Default Labels Assigned ===\n");
    printa("  %-40s %@d\n", @defaults);

    printf("\n=== Totals ===\n");
    printa(@total);
}
