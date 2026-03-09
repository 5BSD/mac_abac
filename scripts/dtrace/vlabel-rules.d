#!/usr/sbin/dtrace -qs
/*
 * vlabel-rules.d - Analyze rule matching
 *
 * Usage: dtrace -s vlabel-rules.d
 *
 * Shows which rules are being matched most frequently.
 * Useful for policy optimization and debugging.
 */

#pragma D option quiet

dtrace:::BEGIN
{
    printf("Analyzing vLabel rule matching...\n");
    printf("Press Ctrl+C to see results.\n\n");
}

vlabel:::rule-match
{
    /* arg0=rule_id, arg1=action, arg2=op */
    @by_rule["Matches by rule ID"] = lquantize(arg0, 0, 100, 1);
    @by_action["Matches by action (0=allow,1=deny,2=trans)"] = lquantize(arg1, 0, 3, 1);
    @by_op["Matches by operation"] = lquantize(arg2, 0, 256, 8);
}

vlabel:::rule-nomatch
{
    /* arg0=default_policy, arg1=op */
    @nomatch["No-match (default policy used)"] = count();
    @nomatch_policy["Default policy applied (0=allow,1=deny)"] = lquantize(arg0, 0, 2, 1);
}

dtrace:::END
{
    printf("\n=== Rule Match Analysis ===\n");
    printa(@by_rule);
    printa(@by_action);
    printa(@by_op);
    printf("\n=== Default Policy Fallback ===\n");
    printa(@nomatch);
    printa(@nomatch_policy);
}
