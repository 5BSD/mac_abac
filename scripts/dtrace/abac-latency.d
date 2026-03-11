#!/usr/sbin/dtrace -qs
/*
 * abac-latency.d - Measure access check latency
 *
 * Usage: dtrace -s abac-latency.d
 *
 * Shows latency distribution of access checks in nanoseconds.
 * Useful for performance analysis.
 */

#pragma D option quiet

dtrace:::BEGIN
{
    printf("Measuring ABAC access check latency...\n");
    printf("Press Ctrl+C to see results.\n\n");
}

abac:::check-entry
{
    self->start = timestamp;
}

abac:::check-return
/self->start/
{
    @latency["All checks (ns)"] = quantize(timestamp - self->start);
    @avg["Average latency (ns)"] = avg(timestamp - self->start);
    @count["Total checks"] = count();
    self->start = 0;
}

abac:::check-allow
/self->start/
{
    @allow_latency["Allow checks (ns)"] = quantize(timestamp - self->start);
}

abac:::check-deny
/self->start/
{
    @deny_latency["Deny checks (ns)"] = quantize(timestamp - self->start);
}

dtrace:::END
{
    printf("\n=== Latency Distribution ===\n");
    printa(@latency);
    printa(@allow_latency);
    printa(@deny_latency);
    printf("\n=== Summary ===\n");
    printa(@avg);
    printa(@count);
}
