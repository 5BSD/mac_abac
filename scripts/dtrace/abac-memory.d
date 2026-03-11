#!/usr/sbin/dtrace -qs
/*
 * abac-memory.d - Track memory allocations in abac UMA zone
 *
 * Usage: dtrace -s abac-memory.d
 *
 * Uses FreeBSD's UMA zone probes to track label allocations.
 * Requires FreeBSD 13.0+ for uma probes.
 */

#pragma D option quiet

dtrace:::BEGIN
{
    printf("Tracking ABAC memory allocations...\n");
    printf("Press Ctrl+C to see results.\n\n");
    printf("Note: Uses FreeBSD UMA zone probes.\n");
    printf("If no output, UMA probes may not be available.\n\n");
}

/* UMA zone allocation for abac_label zone */
uma:kernel::alloc
/stringof(args[0]->uz_name) == "abac_label"/
{
    @allocs["abac_label allocations"] = count();
    @alloc_size["Bytes allocated"] = sum(args[0]->uz_size);
    printf("ALLOC: abac_label (%d bytes)\n", args[0]->uz_size);
}

uma:kernel::free
/stringof(args[0]->uz_name) == "abac_label"/
{
    @frees["abac_label frees"] = count();
    printf("FREE:  abac_label\n");
}

dtrace:::END
{
    printf("\n=== UMA Zone Statistics ===\n");
    printa(@allocs);
    printa(@frees);
    printa(@alloc_size);
}
