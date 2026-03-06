/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 vLabel Project
 * All rights reserved.
 *
 * VLabelRule - Rule definitions for vLabel policy
 */

import CVLabel

/// Operations that can be controlled by rules
public struct VLabelOperations: OptionSet, Sendable {
    public let rawValue: UInt32

    public init(rawValue: UInt32) {
        self.rawValue = rawValue
    }

    public static let exec = VLabelOperations(rawValue: UInt32(VLABEL_OP_EXEC))
    public static let read = VLabelOperations(rawValue: UInt32(VLABEL_OP_READ))
    public static let write = VLabelOperations(rawValue: UInt32(VLABEL_OP_WRITE))
    public static let mmap = VLabelOperations(rawValue: UInt32(VLABEL_OP_MMAP))
    public static let link = VLabelOperations(rawValue: UInt32(VLABEL_OP_LINK))
    public static let rename = VLabelOperations(rawValue: UInt32(VLABEL_OP_RENAME))
    public static let unlink = VLabelOperations(rawValue: UInt32(VLABEL_OP_UNLINK))
    public static let chdir = VLabelOperations(rawValue: UInt32(VLABEL_OP_CHDIR))
    public static let stat = VLabelOperations(rawValue: UInt32(VLABEL_OP_STAT))
    public static let readdir = VLabelOperations(rawValue: UInt32(VLABEL_OP_READDIR))
    public static let create = VLabelOperations(rawValue: UInt32(VLABEL_OP_CREATE))
    public static let setExtattr = VLabelOperations(rawValue: UInt32(VLABEL_OP_SETEXTATTR))
    public static let getExtattr = VLabelOperations(rawValue: UInt32(VLABEL_OP_GETEXTATTR))
    public static let lookup = VLabelOperations(rawValue: UInt32(VLABEL_OP_LOOKUP))
    public static let open = VLabelOperations(rawValue: UInt32(VLABEL_OP_OPEN))
    public static let access = VLabelOperations(rawValue: UInt32(VLABEL_OP_ACCESS))
    public static let all = VLabelOperations(rawValue: UInt32(VLABEL_OP_ALL))
}

/// Action to take when a rule matches
public enum VLabelAction: UInt8, Sendable {
    case allow = 0
    case deny = 1
    case transition = 2
}

/// Pattern for matching labels
public struct VLabelPattern: Sendable {
    public var type: String?
    public var domain: String?
    public var name: String?
    public var level: String?
    public var negate: Bool

    public init(
        type: String? = nil,
        domain: String? = nil,
        name: String? = nil,
        level: String? = nil,
        negate: Bool = false
    ) {
        self.type = type
        self.domain = domain
        self.name = name
        self.level = level
        self.negate = negate
    }

    /// Match any label (wildcard)
    public static let any = VLabelPattern()

    /// Convert to C structure for ioctl
    func toCPattern() -> vlabel_pattern_io {
        var pattern = vlabel_pattern_io()

        var flags: UInt32 = 0

        if let type = type {
            flags |= UInt32(VLABEL_MATCH_TYPE)
            withUnsafeMutableBytes(of: &pattern.vp_type) { buf in
                _ = type.utf8CString.withUnsafeBytes { src in
                    let count = min(src.count, buf.count - 1)
                    buf.copyMemory(from: UnsafeRawBufferPointer(rebasing: src.prefix(count)))
                }
            }
        }

        if let domain = domain {
            flags |= UInt32(VLABEL_MATCH_DOMAIN)
            withUnsafeMutableBytes(of: &pattern.vp_domain) { buf in
                _ = domain.utf8CString.withUnsafeBytes { src in
                    let count = min(src.count, buf.count - 1)
                    buf.copyMemory(from: UnsafeRawBufferPointer(rebasing: src.prefix(count)))
                }
            }
        }

        if let name = name {
            flags |= UInt32(VLABEL_MATCH_NAME)
            withUnsafeMutableBytes(of: &pattern.vp_name) { buf in
                _ = name.utf8CString.withUnsafeBytes { src in
                    let count = min(src.count, buf.count - 1)
                    buf.copyMemory(from: UnsafeRawBufferPointer(rebasing: src.prefix(count)))
                }
            }
        }

        if let level = level {
            flags |= UInt32(VLABEL_MATCH_LEVEL)
            withUnsafeMutableBytes(of: &pattern.vp_level) { buf in
                _ = level.utf8CString.withUnsafeBytes { src in
                    let count = min(src.count, buf.count - 1)
                    buf.copyMemory(from: UnsafeRawBufferPointer(rebasing: src.prefix(count)))
                }
            }
        }

        if negate {
            flags |= UInt32(VLABEL_MATCH_NEGATE)
        }

        pattern.vp_flags = flags
        return pattern
    }
}

/// Jail matching options for context constraints
public enum JailMatch: Sendable {
    case host           // Must be on host (jail 0)
    case anyJail        // Must be in any jail (not host)
    case specific(Int32) // Must be in specific jail ID
}

/// Context constraints for rule matching
public struct VLabelContext: Sendable {
    public var sandboxed: Bool?     // Capsicum capability mode
    public var hasTTY: Bool?        // Has controlling terminal
    public var jail: JailMatch?     // Jail constraint
    public var uid: UInt32?         // Effective UID
    public var gid: UInt32?         // Effective GID
    public var ruid: UInt32?        // Real UID

    public init(
        sandboxed: Bool? = nil,
        hasTTY: Bool? = nil,
        jail: JailMatch? = nil,
        uid: UInt32? = nil,
        gid: UInt32? = nil,
        ruid: UInt32? = nil
    ) {
        self.sandboxed = sandboxed
        self.hasTTY = hasTTY
        self.jail = jail
        self.uid = uid
        self.gid = gid
        self.ruid = ruid
    }

    /// No context constraints (match any context)
    public static let any = VLabelContext()

    /// Convert to C structure for ioctl
    func toCContext() -> vlabel_context_io {
        var ctx = vlabel_context_io()
        var flags: UInt32 = 0

        if let sandboxed = sandboxed {
            flags |= UInt32(VLABEL_CTX_CAP_SANDBOXED)
            ctx.vc_cap_sandboxed = sandboxed ? 1 : 0
        }

        if let hasTTY = hasTTY {
            flags |= UInt32(VLABEL_CTX_HAS_TTY)
            ctx.vc_has_tty = hasTTY ? 1 : 0
        }

        if let jail = jail {
            flags |= UInt32(VLABEL_CTX_JAIL)
            switch jail {
            case .host:
                ctx.vc_jail_check = 0
            case .anyJail:
                ctx.vc_jail_check = -1
            case .specific(let jailID):
                ctx.vc_jail_check = jailID
            }
        }

        if let uid = uid {
            flags |= UInt32(VLABEL_CTX_UID)
            ctx.vc_uid = uid
        }

        if let gid = gid {
            flags |= UInt32(VLABEL_CTX_GID)
            ctx.vc_gid = gid
        }

        if let ruid = ruid {
            flags |= UInt32(VLABEL_CTX_RUID)
            ctx.vc_uid = ruid  // Shares same field
        }

        ctx.vc_flags = flags
        return ctx
    }
}

/// A vLabel access control rule
public struct VLabelRule: Sendable {
    public var id: UInt32
    public var action: VLabelAction
    public var operations: VLabelOperations
    public var subject: VLabelPattern
    public var object: VLabelPattern
    public var context: VLabelContext
    public var newLabel: String?    // For transition rules

    public init(
        id: UInt32,
        action: VLabelAction,
        operations: VLabelOperations,
        subject: VLabelPattern = .any,
        object: VLabelPattern,
        context: VLabelContext = .any,
        newLabel: String? = nil
    ) {
        self.id = id
        self.action = action
        self.operations = operations
        self.subject = subject
        self.object = object
        self.context = context
        self.newLabel = newLabel
    }

    /// Convert to C structure for ioctl
    public func toCRule() -> vlabel_rule_io {
        var rule = vlabel_rule_io()
        rule.vr_id = id
        rule.vr_action = action.rawValue
        rule.vr_padding = (0, 0, 0)
        rule.vr_operations = operations.rawValue
        rule.vr_subject = subject.toCPattern()
        rule.vr_object = object.toCPattern()
        rule.vr_context = context.toCContext()

        // Copy new label for transition rules
        if let newLabel = newLabel {
            withUnsafeMutableBytes(of: &rule.vr_newlabel) { buf in
                _ = newLabel.utf8CString.withUnsafeBytes { src in
                    let count = min(src.count, buf.count - 1)
                    buf.copyMemory(from: UnsafeRawBufferPointer(rebasing: src.prefix(count)))
                }
            }
        }

        return rule
    }
}
