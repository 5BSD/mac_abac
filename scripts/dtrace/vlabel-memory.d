#!/usr/sbin/dtrace -qs
/*
 * vlabel-memory.d - Track memory allocations in vlabel UMA zone
 *
 * Usage: dtrace -s vlabel-memory.d
 *
 * Uses FreeBSD's UMA zone probes to track label allocations.
 * Requires FreeBSD 13.0+ for uma probes.
 */

#pragma D option quiet

dtrace:::BEGIN
{
    printf("Tracking vLabel memory allocations...\n");
    printf("Press Ctrl+C to see results.\n\n");
    printf("Note: Uses FreeBSD UMA zone probes.\n");
    printf("If no output, UMA probes may not be available.\n\n");
}

/* UMA zone allocation for vlabel_label zone */
uma:kernel::alloc
/stringof(args[0]->uz_name) == "vlabel_label"/
{
    @allocs["vlabel_label allocations"] = count();
    @alloc_size["Bytes allocated"] = sum(args[0]->uz_size);
    printf("ALLOC: vlabel_label (%d bytes)\n", args[0]->uz_size);
}

uma:kernel::free
/stringof(args[0]->uz_name) == "vlabel_label"/
{
    @frees["vlabel_label frees"] = count();
    printf("FREE:  vlabel_label\n");
}

dtrace:::END
{
    printf("\n=== UMA Zone Statistics ===\n");
    printa(@allocs);
    printa(@frees);
    printa(@alloc_size);
}
