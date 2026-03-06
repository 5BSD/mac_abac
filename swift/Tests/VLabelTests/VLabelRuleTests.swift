/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 vLabel Project
 * All rights reserved.
 */

import Testing
@testable import VLabel
import CVLabel

@Suite("VLabel Rule Tests")
struct VLabelRuleTests {

    @Test("Operations option set contains expected values")
    func operationsValues() {
        #expect(VLabelOperations.exec.rawValue == UInt32(VLABEL_OP_EXEC))
        #expect(VLabelOperations.read.rawValue == UInt32(VLABEL_OP_READ))
        #expect(VLabelOperations.write.rawValue == UInt32(VLABEL_OP_WRITE))
        #expect(VLabelOperations.all.rawValue == UInt32(VLABEL_OP_ALL))
    }

    @Test("Operations can be combined")
    func operationsCombine() {
        let ops: VLabelOperations = [.exec, .read, .write]
        #expect(ops.contains(.exec))
        #expect(ops.contains(.read))
        #expect(ops.contains(.write))
        #expect(!ops.contains(.mmap))
    }

    @Test("Pattern with no fields matches any")
    func patternAny() {
        let pattern = VLabelPattern.any
        let cPattern = pattern.toCPattern()
        #expect(cPattern.vp_flags == 0)
    }

    @Test("Pattern with type field sets flag")
    func patternType() {
        let pattern = VLabelPattern(type: "untrusted")
        let cPattern = pattern.toCPattern()
        #expect(cPattern.vp_flags & UInt32(VLABEL_MATCH_TYPE) != 0)
    }

    @Test("Pattern with all fields sets all flags")
    func patternAllFields() {
        let pattern = VLabelPattern(
            type: "app",
            domain: "network",
            name: "browser",
            level: "low"
        )
        let cPattern = pattern.toCPattern()

        #expect(cPattern.vp_flags & UInt32(VLABEL_MATCH_TYPE) != 0)
        #expect(cPattern.vp_flags & UInt32(VLABEL_MATCH_DOMAIN) != 0)
        #expect(cPattern.vp_flags & UInt32(VLABEL_MATCH_NAME) != 0)
        #expect(cPattern.vp_flags & UInt32(VLABEL_MATCH_LEVEL) != 0)
    }

    @Test("Pattern negation sets negate flag")
    func patternNegate() {
        let pattern = VLabelPattern(type: "system", negate: true)
        let cPattern = pattern.toCPattern()
        #expect(cPattern.vp_flags & UInt32(VLABEL_MATCH_NEGATE) != 0)
    }

    @Test("Rule converts to C structure")
    func ruleToC() {
        let rule = VLabelRule(
            id: 42,
            action: .deny,
            operations: [.exec],
            subject: .any,
            object: VLabelPattern(type: "untrusted")
        )

        let cRule = rule.toCRule()
        #expect(cRule.vr_id == 42)
        #expect(cRule.vr_action == VLABEL_ACTION_DENY)
        #expect(cRule.vr_operations == UInt32(VLABEL_OP_EXEC))
        #expect(cRule.vr_subject.vp_flags == 0)  // any
        #expect(cRule.vr_object.vp_flags & UInt32(VLABEL_MATCH_TYPE) != 0)
    }

    @Test("Action raw values match C constants")
    func actionValues() {
        #expect(VLabelAction.allow.rawValue == VLABEL_ACTION_ALLOW)
        #expect(VLabelAction.deny.rawValue == VLABEL_ACTION_DENY)
    }

    @Test("Rule IO structure has correct padding")
    func ruleIOPadding() {
        let rule = VLabelRule(
            id: 100,
            action: .allow,
            operations: .all,
            subject: .any,
            object: VLabelPattern(type: "trusted")
        )

        let cRule = rule.toCRule()
        #expect(cRule.vr_padding.0 == 0)
        #expect(cRule.vr_padding.1 == 0)
        #expect(cRule.vr_padding.2 == 0)
    }

    @Test("Complex rule with subject and object patterns")
    func complexRule() {
        let rule = VLabelRule(
            id: 200,
            action: .allow,
            operations: [.read, .write, .mmap],
            subject: VLabelPattern(type: "trusted", domain: "system"),
            object: VLabelPattern(type: "data", level: "confidential")
        )

        let cRule = rule.toCRule()

        #expect(cRule.vr_id == 200)
        #expect(cRule.vr_action == VLABEL_ACTION_ALLOW)
        #expect(cRule.vr_operations == UInt32(VLABEL_OP_READ | VLABEL_OP_WRITE | VLABEL_OP_MMAP))

        // Subject has type and domain
        #expect(cRule.vr_subject.vp_flags & UInt32(VLABEL_MATCH_TYPE) != 0)
        #expect(cRule.vr_subject.vp_flags & UInt32(VLABEL_MATCH_DOMAIN) != 0)

        // Object has type and level
        #expect(cRule.vr_object.vp_flags & UInt32(VLABEL_MATCH_TYPE) != 0)
        #expect(cRule.vr_object.vp_flags & UInt32(VLABEL_MATCH_LEVEL) != 0)
    }
}
