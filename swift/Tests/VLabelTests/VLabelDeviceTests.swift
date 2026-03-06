/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 vLabel Project
 * All rights reserved.
 */

import Testing
@testable import VLabel
import CVLabel

@Suite("VLabel Device Tests")
struct VLabelDeviceTests {

    @Test("VLabelMode has correct raw values")
    func modeValues() {
        #expect(VLabelMode.disabled.rawValue == 0)
        #expect(VLabelMode.permissive.rawValue == 1)
        #expect(VLabelMode.enforcing.rawValue == 2)
    }

    @Test("VLabelAuditLevel has correct raw values")
    func auditLevelValues() {
        #expect(VLabelAuditLevel.none.rawValue == 0)
        #expect(VLabelAuditLevel.denials.rawValue == 1)
        #expect(VLabelAuditLevel.decisions.rawValue == 2)
        #expect(VLabelAuditLevel.verbose.rawValue == 3)
    }

    @Test("VLabelError contains operation name")
    func errorDescription() {
        let error = VLabelError(operation: "testOp", errno: 13)
        #expect(error.operation == "testOp")
        #expect(error.errno == 13)
    }

    // Note: Device tests that require /dev/vlabel should be run
    // on a system with the kernel module loaded. These are marked
    // with .enabled(if:) or skipped in CI.

    @Test("Device open fails without module", .disabled("Requires kernel module"))
    func deviceOpenRequiresModule() throws {
        // This test would verify that opening /dev/vlabel fails
        // when the module isn't loaded (ENOENT)
        #expect(throws: VLabelError.self) {
            _ = try VLabelDevice()
        }
    }
}

@Suite("VLabel Stats Tests")
struct VLabelStatsTests {

    @Test("Stats initializes from C struct")
    func statsFromC() {
        var cStats = vlabel_stats()
        cStats.vs_checks = 100
        cStats.vs_allowed = 95
        cStats.vs_denied = 5
        cStats.vs_labels_read = 50
        cStats.vs_labels_default = 25
        cStats.vs_rule_count = 3

        let stats = VLabelStats(from: cStats)

        #expect(stats.checks == 100)
        #expect(stats.allowed == 95)
        #expect(stats.denied == 5)
        #expect(stats.labelsRead == 50)
        #expect(stats.labelsDefault == 25)
        #expect(stats.ruleCount == 3)
    }
}
