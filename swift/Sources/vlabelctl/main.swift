/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 vLabel Project
 * All rights reserved.
 *
 * vlabelctl - Control the vLabel MAC policy module
 */

import ArgumentParser
import VLabel
import Foundation

@main
struct VLabelCtl: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "vlabelctl",
        abstract: "Control the vLabel MAC policy module",
        discussion: """
            vlabelctl provides management of the vLabel MACF kernel module.

            Requires root privileges to access /dev/vlabel.
            """,
        subcommands: [
            Status.self,
            Mode.self,
            Audit.self,
            Stats.self,
            Rule.self,
        ],
        defaultSubcommand: Status.self
    )
}

// MARK: - Status Command

struct Status: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Show current mode and statistics"
    )

    func run() throws {
        let device = try VLabelDevice()
        let mode = try device.getMode()
        let stats = try device.getStats()

        print("vLabel MAC Policy Status")
        print("========================")
        print("Mode:           \(mode.description)")
        print("Rules:          \(stats.ruleCount)")
        print("Checks:         \(stats.checks)")
        print("Allowed:        \(stats.allowed)")
        print("Denied:         \(stats.denied)")
        print("Labels read:    \(stats.labelsRead)")
        print("Labels default: \(stats.labelsDefault)")
    }
}

// MARK: - Mode Command

struct Mode: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Get or set enforcement mode"
    )

    @Argument(help: "Mode to set (disabled, permissive, enforcing)")
    var newMode: String?

    func run() throws {
        let device = try VLabelDevice()

        if let modeStr = newMode {
            let mode = try parseMode(modeStr)
            try device.setMode(mode)
            print("Mode set to: \(mode.description)")
        } else {
            let mode = try device.getMode()
            print(mode.description)
        }
    }

    func parseMode(_ str: String) throws -> VLabelMode {
        switch str.lowercased() {
        case "disabled", "off", "0":
            return .disabled
        case "permissive", "perm", "1":
            return .permissive
        case "enforcing", "enforce", "2":
            return .enforcing
        default:
            throw ValidationError("Invalid mode '\(str)'. Use: disabled, permissive, enforcing")
        }
    }
}

// MARK: - Audit Command

struct Audit: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Set audit level"
    )

    @Argument(help: "Audit level (none, denials, decisions, verbose)")
    var level: String

    func run() throws {
        let device = try VLabelDevice()
        let auditLevel = try parseAuditLevel(level)
        try device.setAuditLevel(auditLevel)
        print("Audit level set to: \(auditLevel.description)")
    }

    func parseAuditLevel(_ str: String) throws -> VLabelAuditLevel {
        switch str.lowercased() {
        case "none", "off", "0":
            return .none
        case "denials", "deny", "1":
            return .denials
        case "decisions", "all", "2":
            return .decisions
        case "verbose", "debug", "3":
            return .verbose
        default:
            throw ValidationError("Invalid audit level '\(str)'. Use: none, denials, decisions, verbose")
        }
    }
}

// MARK: - Stats Command

struct Stats: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Show detailed statistics"
    )

    func run() throws {
        let device = try VLabelDevice()
        let stats = try device.getStats()

        print("vLabel Statistics")
        print("=================")
        print("Total checks:    \(stats.checks)")
        print("Allowed:         \(stats.allowed)")
        print("Denied:          \(stats.denied)")
        print("Labels read:     \(stats.labelsRead)")
        print("Labels default:  \(stats.labelsDefault)")
        print("Active rules:    \(stats.ruleCount)")

        if stats.checks > 0 {
            let denyRate = Double(stats.denied) / Double(stats.checks) * 100
            print("Denial rate:     \(String(format: "%.2f", denyRate))%")
        }
    }
}

// MARK: - Rule Command

struct Rule: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Manage access control rules",
        subcommands: [
            RuleAdd.self,
            RuleRemove.self,
            RuleClear.self,
        ]
    )
}

struct RuleAdd: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "add",
        abstract: "Add a rule to the kernel",
        discussion: """
            Pattern format: type=<value>,domain=<value>,name=<value>,level=<value>
            Use '*' for wildcard (match any).

            Operations: exec,read,write,mmap,link,rename,unlink,chdir,stat,
                       readdir,create,open,access,all

            Examples:
                vlabelctl rule add 100 deny exec type=untrusted
                vlabelctl rule add 200 allow read,write type=trusted type=public
            """
    )

    @Argument(help: "Rule ID (positive integer)")
    var id: UInt32

    @Argument(help: "Action (allow or deny)")
    var action: String

    @Argument(help: "Operations (comma-separated: exec,read,write,all,...)")
    var operations: String

    @Argument(help: "Object pattern (or '*' for any). If two patterns given, first is subject.")
    var patterns: [String]

    func run() throws {
        guard !patterns.isEmpty else {
            throw ValidationError("At least one pattern (object) is required")
        }

        let ruleAction = try parseAction(action)
        let ops = try parseOperations(operations)

        let subject: VLabelPattern
        let object: VLabelPattern

        if patterns.count == 1 {
            subject = .any
            object = try parsePattern(patterns[0])
        } else {
            subject = try parsePattern(patterns[0])
            object = try parsePattern(patterns[1])
        }

        let rule = VLabelRule(
            id: id,
            action: ruleAction,
            operations: ops,
            subject: subject,
            object: object
        )

        let device = try VLabelDevice()
        try device.addRule(rule)
        print("Rule \(id) added: \(action) \(operations)")
        print("  Subject: \(patternDescription(subject))")
        print("  Object:  \(patternDescription(object))")
    }

    func parseAction(_ str: String) throws -> VLabelAction {
        switch str.lowercased() {
        case "allow":
            return .allow
        case "deny":
            return .deny
        default:
            throw ValidationError("Invalid action '\(str)'. Use: allow, deny")
        }
    }

    func parseOperations(_ str: String) throws -> VLabelOperations {
        var ops = VLabelOperations()

        for part in str.lowercased().split(separator: ",") {
            switch part {
            case "exec":
                ops.insert(.exec)
            case "read":
                ops.insert(.read)
            case "write":
                ops.insert(.write)
            case "mmap":
                ops.insert(.mmap)
            case "link":
                ops.insert(.link)
            case "rename":
                ops.insert(.rename)
            case "unlink":
                ops.insert(.unlink)
            case "chdir":
                ops.insert(.chdir)
            case "stat":
                ops.insert(.stat)
            case "readdir":
                ops.insert(.readdir)
            case "create":
                ops.insert(.create)
            case "open":
                ops.insert(.open)
            case "access":
                ops.insert(.access)
            case "all":
                ops.insert(.all)
            default:
                throw ValidationError("Unknown operation '\(part)'")
            }
        }

        if ops.isEmpty {
            throw ValidationError("No valid operations specified")
        }

        return ops
    }

    func parsePattern(_ str: String) throws -> VLabelPattern {
        if str == "*" {
            return .any
        }

        var pattern = VLabelPattern()

        for part in str.split(separator: ",") {
            let kv = part.split(separator: "=", maxSplits: 1)
            guard kv.count == 2 else {
                throw ValidationError("Invalid pattern '\(part)'. Expected: key=value")
            }

            let key = String(kv[0]).lowercased()
            let value = String(kv[1])

            switch key {
            case "type":
                pattern.type = value
            case "domain":
                pattern.domain = value
            case "name":
                pattern.name = value
            case "level":
                pattern.level = value
            default:
                throw ValidationError("Unknown pattern key '\(key)'. Use: type, domain, name, level")
            }
        }

        return pattern
    }

    func patternDescription(_ pattern: VLabelPattern) -> String {
        var parts: [String] = []

        if let type = pattern.type {
            parts.append("type=\(type)")
        }
        if let domain = pattern.domain {
            parts.append("domain=\(domain)")
        }
        if let name = pattern.name {
            parts.append("name=\(name)")
        }
        if let level = pattern.level {
            parts.append("level=\(level)")
        }

        return parts.isEmpty ? "*" : parts.joined(separator: ",")
    }
}

struct RuleRemove: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "remove",
        abstract: "Remove a rule by ID"
    )

    @Argument(help: "Rule ID to remove")
    var id: UInt32

    func run() throws {
        let device = try VLabelDevice()
        try device.removeRule(id: id)
        print("Rule \(id) removed")
    }
}

struct RuleClear: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "clear",
        abstract: "Clear all rules"
    )

    @Flag(name: .shortAndLong, help: "Skip confirmation prompt")
    var force = false

    func run() throws {
        if !force {
            print("This will remove all rules from the kernel.")
            print("Are you sure? [y/N] ", terminator: "")
            guard let response = readLine(), response.lowercased() == "y" else {
                print("Aborted.")
                return
            }
        }

        let device = try VLabelDevice()
        try device.clearRules()
        print("All rules cleared")
    }
}

// MARK: - Extensions

extension VLabelMode: CustomStringConvertible {
    public var description: String {
        switch self {
        case .disabled:
            return "disabled"
        case .permissive:
            return "permissive (log only)"
        case .enforcing:
            return "enforcing"
        }
    }
}

extension VLabelAuditLevel: CustomStringConvertible {
    public var description: String {
        switch self {
        case .none:
            return "none"
        case .denials:
            return "denials"
        case .decisions:
            return "decisions"
        case .verbose:
            return "verbose"
        }
    }
}
