import Foundation

public struct NativeRecordingIdentity: Codable, Equatable {
    public let uid: UInt32
    public let bundleID: String
    public let pid: Int32
    public let startToken: String
    public let windowID: String?
    public init(uid: UInt32, bundleID: String, pid: Int32, startToken: String, windowID: String? = nil) {
        self.uid = uid; self.bundleID = bundleID; self.pid = pid; self.startToken = startToken; self.windowID = windowID
    }
    public func valid(for uid: UInt32) -> Bool {
        self.uid == uid && pid > 0 && !bundleID.isEmpty && bundleID.utf8.count <= 256 && bundleID.utf8.allSatisfy { (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0) || [45,46,95].contains($0) } && !startToken.isEmpty && startToken.utf8.count <= 128 && !startToken.unicodeScalars.contains { CharacterSet.controlCharacters.contains($0) } && (windowID == nil || UInt32(windowID!) != nil && UInt32(windowID!)! > 0)
    }
}

/// No title/name, AXValue, typed text or clipboard field exists in this snapshot.
/// Raw identifiers require positive classification by a trusted local provider.
public struct NativeRecordingTarget: Codable, Equatable {
    public let role: String
    public let identifier: String?
    public let identifierDigest: String?
    public let identifierQualified: Bool
    public let nameWithheld: Bool
    public init(role: String, identifier: String? = nil, identifierDigest: String? = nil, identifierQualified: Bool = false) {
        self.role = role; self.identifier = identifier; self.identifierDigest = identifierDigest; self.identifierQualified = identifierQualified; self.nameWithheld = true
    }
    public var valid: Bool {
        let roles: Set<String> = ["AXApplication", "AXWindow", "AXButton", "AXTextField", "AXTextArea", "AXStaticText", "AXComboBox", "AXPopUpButton", "AXCheckBox", "AXRadioButton", "AXMenu", "AXMenuItem", "AXMenuBar", "AXTabGroup", "AXTable", "AXRow", "AXCell", "AXOutline", "AXGroup", "AXScrollArea", "AXSlider", "AXToolbar", "AXLink", "AXUnknown"]
        guard roles.contains(role), nameWithheld else { return false }
        if let identifier {
            guard identifierQualified, !identifier.isEmpty, identifier.utf8.count <= 256, identifier.utf8.allSatisfy({ (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0) || [45,46,58,95].contains($0) }) else { return false }
        }
        if let digest = identifierDigest {
            guard digest.utf8.count == 64, digest.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }), identifier == nil else { return false }
        }
        return true
    }
}
public struct NativeRecordingLocator: Codable, Equatable {
    public let strategy: String
    public let value: String
    public let exact: Bool
}
public struct NativeRecordingEvent: Codable, Equatable {
    public let recordingId: String
    public let sequence: UInt64
    public let timestampUnixMs: Int64
    public let kind: String
    public let nativeIdentity: NativeRecordingIdentity?
    public let target: NativeRecordingTarget?
    public let locator: NativeRecordingLocator?
    public let redacted: Bool
    public let parameterRequired: Bool
    public let selectorConfidence: String
    public let lineage: String
    public let source: String
    public let trusted: Bool
    public let reason: String?
}
public struct NativeRecordingGap: Codable, Equatable {
    public let kind: String
    public let reason: String
    public let fromSequence: UInt64
    public let toSequence: UInt64
    public let lost: UInt64
    public let unknownExtent: Bool
}
public struct NativeRecordingBatch: Codable, Equatable {
    public let recordingId: String
    public let state: String
    public let leaseExpiresUnixMs: Int64
    public let events: [NativeRecordingEvent]
    public let gaps: [NativeRecordingGap]
    public let lastSequence: UInt64
    public let truncated: Bool
}

/// Bounded live journal only. Persistence and DSL compilation belong to the
/// existing generated recording service and Endly pipeline. Saturation pauses
/// capture instead of silently evicting demonstration actions.
public final class RecordingJournal {
    private let lock = NSLock()
    public let recordingID: String
    public let expectedUID: UInt32
    private let capacity: Int
    private let expires: Int64
    private let monotonicNow: () -> UInt64
    private let began: UInt64
    private let deadline: UInt64
    private var state = "recording"
    private var events: [NativeRecordingEvent] = []
    private var gaps: [NativeRecordingGap] = []
    private var sequence: UInt64 = 0
    private var truncated = false
    public init(recordingID: String, expectedUID: UInt32, capacity: Int = 4096, durationMs: Int = 60_000, now: Date = Date(), monotonicNow: @escaping () -> UInt64 = { DispatchTime.now().uptimeNanoseconds }) throws {
        guard !recordingID.isEmpty, recordingID.utf8.count <= 128, recordingID.utf8.allSatisfy({ (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0) || [45,95].contains($0) }), capacity >= 4, capacity <= 4096, durationMs >= 1000, durationMs <= 900_000, validRecordingTime(now) else { throw NativeFailure("invalidRecording", "Bounded recording identity, duration and capacity required") }
        let started = monotonicNow(), duration = UInt64(durationMs) * 1_000_000
        guard started <= UInt64.max-duration else { throw NativeFailure("invalidRecording", "Recording monotonic deadline overflow") }
        self.monotonicNow = monotonicNow; self.began = started; self.deadline = started + duration
        self.recordingID = recordingID; self.expectedUID = expectedUID; self.capacity = capacity
        expires = Int64(now.timeIntervalSince1970 * 1000) + Int64(durationMs)
        put(kind: "start", identity: nil, target: nil, trusted: false, reason: nil, now: now)
    }
    @discardableResult public func append(kind: String, identity: NativeRecordingIdentity, target: NativeRecordingTarget?, trusted: Bool = false, now: Date = Date()) throws -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard state == "recording" else { return false }
        guard ["press", "fill", "select", "app.activate"].contains(kind), identity.valid(for: expectedUID), (target == nil || target!.valid), (kind == "app.activate" || target != nil), validRecordingTime(now) else { throw NativeFailure("invalidRecordingEvent", "Exact current-user identity and redacted target required") }
        if monotonicNow() < began || monotonicNow() >= deadline || Int64(now.timeIntervalSince1970 * 1000) >= expires { pauseLocked("durationExpired", now: now); return false }
        guard events.count < capacity - 1 else { truncated = true; pauseLocked("journalCapacity", now: now); return false }
        let reason = kind == "fill" ? "valueWithheld" : (kind != "app.activate" && identity.windowID == nil ? "windowUnresolved" : (!trusted ? "sourceNotAttested" : nil))
        put(kind: kind, identity: identity, target: target, trusted: trusted, reason: reason, now: now)
        return true
    }
    /// Unsupported actions remain visible as coverage gaps while later apps can
    /// still be demonstrated. Repeated gaps coalesce rather than flooding RAM.
    public func gap(reason: String, now: Date = Date()) {
        lock.lock(); defer { lock.unlock() }
        guard state == "recording" else { return }
        if monotonicNow() < began || monotonicNow() >= deadline { pauseLocked("durationExpired", now: now); return }
        let accepted: Set<String> = ["targetUnresolved", "identityChanged", "unsupportedInput"]
        let reason = accepted.contains(reason) ? reason : "targetUnresolved"
        if let last = gaps.last, last.reason == reason, let lastEvent = events.last,
           lastEvent.kind == "gap", now.timeIntervalSince1970 * 1000 - Double(lastEvent.timestampUnixMs) < 1000 { return }
        guard events.count < capacity - 1 else { truncated = true; pauseLocked("journalCapacity", now: now); return }
        put(kind: "gap", identity: nil, target: nil, trusted: false, reason: reason, now: now)
        let gap = NativeRecordingGap(kind: "gap", reason: reason, fromSequence: sequence, toSequence: sequence, lost: 0, unknownExtent: true)
        if gaps.count < 8 { gaps.append(gap) }
        else {
            let old = gaps.removeLast()
            gaps.append(NativeRecordingGap(kind: "gap", reason: "multipleCoverageGaps", fromSequence: old.fromSequence, toSequence: sequence, lost: 0, unknownExtent: true))
        }
    }
    public func pause(reason: String, now: Date = Date()) {
        lock.lock(); defer { lock.unlock() }
        if state == "recording" { pauseLocked(reason, now: now) }
    }
    public func stop(confirmed: Bool = true, now: Date = Date()) {
        lock.lock(); defer { lock.unlock() }
        guard state != "stopped" else { return }
        if events.count < capacity { put(kind: "stop", identity: nil, target: nil, trusted: false, reason: nil, now: now) }
        state = confirmed ? "stopped" : "stopUnconfirmed"
    }
    public func poll(after: UInt64, limit: Int = 64) throws -> NativeRecordingBatch {
        lock.lock(); defer { lock.unlock() }
        if state == "recording" && (monotonicNow() < began || monotonicNow() >= deadline) { pauseLocked("durationExpired", now: Date()) }
        guard limit >= 1, limit <= 64, after <= sequence else { throw NativeFailure("invalidRecordingCursor", "Recording cursor and limit must be bounded") }
        return NativeRecordingBatch(recordingId: recordingID, state: state, leaseExpiresUnixMs: expires, events: Array(events.filter { $0.sequence > after }.prefix(limit)), gaps: gaps.filter { $0.toSequence > after }, lastSequence: sequence, truncated: truncated)
    }
    private func pauseLocked(_ requested: String, now: Date) {
        let reasons: Set<String> = ["secureInput", "secureTarget", "permissionLost", "watchdogStopped", "consentWithdrawn", "durationExpired", "journalCapacity", "producerOverflow", "producerUnavailable", "tapDisabled", "targetUnresolved", "identityChanged", "unsupportedInput", "manualPause"]
        let reason = reasons.contains(requested) ? requested : "producerUnavailable"
        if events.count < capacity { put(kind: "gap", identity: nil, target: nil, trusted: false, reason: reason, now: now) }
        if gaps.count >= 8 {
            let old = gaps.removeLast()
            gaps.append(NativeRecordingGap(kind: "gap", reason: "multipleCoverageGaps", fromSequence: old.fromSequence, toSequence: sequence, lost: 0, unknownExtent: true))
        } else { gaps.append(NativeRecordingGap(kind: "gap", reason: reason, fromSequence: sequence, toSequence: sequence, lost: 0, unknownExtent: true)) }
        state = "paused"
    }
    private func put(kind: String, identity: NativeRecordingIdentity?, target: NativeRecordingTarget?, trusted: Bool, reason: String?, now: Date) {
        sequence += 1
        var locator: NativeRecordingLocator?
        if let target {
            if let identifier = target.identifier { locator = NativeRecordingLocator(strategy: "id", value: identifier, exact: true) }
            else if let digest = target.identifierDigest { locator = NativeRecordingLocator(strategy: "idDigest", value: digest, exact: true) }
            else { locator = NativeRecordingLocator(strategy: "role", value: target.role, exact: true) }
        }
        events.append(NativeRecordingEvent(recordingId: recordingID, sequence: sequence, timestampUnixMs: validRecordingTime(now) ? Int64(now.timeIntervalSince1970 * 1000) : (events.last?.timestampUnixMs ?? 1), kind: kind, nativeIdentity: identity, target: target, locator: locator, redacted: kind == "fill" || target?.identifier == nil, parameterRequired: kind == "fill", selectorConfidence: target?.identifier != nil ? "candidate" : "unresolved", lineage: "\(recordingID):native:\(sequence)", source: "nativeAX", trusted: trusted, reason: reason))
    }
}

private func validRecordingTime(_ now: Date) -> Bool {
    now.timeIntervalSince1970.isFinite && now.timeIntervalSince1970 > 0 && now.timeIntervalSince1970 < Double(Int64.max / 1000) - 900
}
