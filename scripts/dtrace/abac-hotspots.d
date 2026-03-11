#!/usr/sbin/dtrace -qs
/*
 * abac-hotspots.d - Find frequently accessed subject/object pairs
 *
 * Usage: dtrace -s abac-hotspots.d
 *
 * Identifies the most common access patterns.
 * Useful for rule optimization and understanding workloads.
 */

#pragma D option quiet

dtrace:::BEGIN
{
    printf("Finding ABAC access hotspots...\n");
    printf("Press Ctrl+C to see top access patterns.\n\n");
}

abac:::check-entry
{
    /* arg0=subject, arg1=object, arg2=op */
    @pairs[stringof(arg0), stringof(arg1)] = count();
    @subjects[stringof(arg0)] = count();
    @objects[stringof(arg1)] = count();
}

dtrace:::END
{
    printf("\n=== Top 20 Subject/Object Pairs ===\n");
    printf("%-25s %-25s %s\n", "SUBJECT", "OBJECT", "COUNT");
    trunc(@pairs, 20);
    printa("%-25s %-25s %@d\n", @pairs);

    printf("\n=== Top 10 Subjects (processes) ===\n");
    trunc(@subjects, 10);
    printa("  %-40s %@d\n", @subjects);

    printf("\n=== Top 10 Objects (files) ===\n");
    trunc(@objects, 10);
    printa("  %-40s %@d\n", @objects);
}
