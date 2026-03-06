/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 vLabel Project
 * All rights reserved.
 *
 * VLabelDevice - Swift interface to /dev/vlabel
 */

import CVLabel
import Descriptors
import FreeBSDKit

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// Enforcement mode for the vLabel policy
public enum VLabelMode: Int32, Sendable {
    case disabled = 0
    case permissive = 1
    case enforcing = 2
}

/// Audit level for vLabel logging
public enum VLabelAuditLevel: Int32, Sendable {
    case none = 0
    case denials = 1
    case decisions = 2
    case verbose = 3
}

/// Statistics from the vLabel kernel module
public struct VLabelStats: Sendable {
    public let checks: UInt64
    public let allowed: UInt64
    public let denied: UInt64
    public let labelsRead: UInt64
    public let labelsDefault: UInt64
    public let ruleCount: UInt32

    init(from stats: vlabel_stats) {
        self.checks = stats.vs_checks
        self.allowed = stats.vs_allowed
        self.denied = stats.vs_denied
        self.labelsRead = stats.vs_labels_read
        self.labelsDefault = stats.vs_labels_default
        self.ruleCount = stats.vs_rule_count
    }
}

/// Error type for vLabel operations
public struct VLabelError: Error, Sendable {
    public let operation: String
    public let errno: Int32

    public var description: String {
        "VLabel \(operation) failed: \(String(cString: strerror(errno)))"
    }
}

/// Interface to the vLabel kernel module via /dev/vlabel
public struct VLabelDevice: ~Copyable, Sendable {
    private let fd: Int32

    /// Open /dev/vlabel
    /// - Throws: VLabelError if open fails (requires root)
    public init() throws {
        let fd = open("/dev/vlabel", O_RDWR | O_CLOEXEC)
        if fd < 0 {
            throw VLabelError(operation: "open", errno: errno)
        }
        self.fd = fd
    }

    deinit {
        close(fd)
    }

    /// Get the current enforcement mode
    public func getMode() throws -> VLabelMode {
        var mode: Int32 = 0
        if vlabel_ioctl_int(fd, VLABEL_IOC_GETMODE, &mode) < 0 {
            throw VLabelError(operation: "getMode", errno: errno)
        }
        return VLabelMode(rawValue: mode) ?? .disabled
    }

    /// Set the enforcement mode
    public func setMode(_ mode: VLabelMode) throws {
        var value = mode.rawValue
        if vlabel_ioctl_int(fd, VLABEL_IOC_SETMODE, &value) < 0 {
            throw VLabelError(operation: "setMode", errno: errno)
        }
    }

    /// Get statistics from the kernel module
    public func getStats() throws -> VLabelStats {
        var stats = vlabel_stats()
        if vlabel_ioctl_stats(fd, VLABEL_IOC_GETSTATS, &stats) < 0 {
            throw VLabelError(operation: "getStats", errno: errno)
        }
        return VLabelStats(from: stats)
    }

    /// Set the audit level
    public func setAuditLevel(_ level: VLabelAuditLevel) throws {
        var value = level.rawValue
        if vlabel_ioctl_int(fd, VLABEL_IOC_SETAUDIT, &value) < 0 {
            throw VLabelError(operation: "setAuditLevel", errno: errno)
        }
    }

    /// Add a rule to the kernel rule table
    public func addRule(_ rule: VLabelRule) throws {
        var cRule = rule.toCRule()
        if vlabel_ioctl_rule(fd, VLABEL_IOC_RULE_ADD, &cRule) < 0 {
            throw VLabelError(operation: "addRule", errno: errno)
        }
    }

    /// Remove a rule by ID
    public func removeRule(id: UInt32) throws {
        var ruleId = id
        if vlabel_ioctl_uint32(fd, VLABEL_IOC_RULE_REMOVE, &ruleId) < 0 {
            throw VLabelError(operation: "removeRule", errno: errno)
        }
    }

    /// Clear all rules from the kernel
    public func clearRules() throws {
        if vlabel_ioctl_void(fd, VLABEL_IOC_RULES_CLEAR) < 0 {
            throw VLabelError(operation: "clearRules", errno: errno)
        }
    }
}
