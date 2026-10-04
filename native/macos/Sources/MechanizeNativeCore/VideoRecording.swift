import Foundation

/// Screen pixels need separate, explicit record authority; AX permission is insufficient.
public struct VideoRecordingAuthority: Equatable {
    public let namespace: String
    public let clientID: String
    public let sessionID: String
    public let grantID: String
    public let mode: String
    public init(namespace: String, clientID: String, sessionID: String, grantID: String, mode: String) {
        self.namespace = namespace; self.clientID = clientID; self.sessionID = sessionID; self.grantID = grantID; self.mode = mode
    }
    public var valid: Bool { namespace.count == 64 && namespace.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) } && [clientID, sessionID, grantID].allSatisfy { !$0.isEmpty && $0.utf8.count <= 256 } && mode == "record" }
}
public enum VideoRecordingScope: Equatable {
    case desktop
    case application(bundleID: String)
    case window(bundleID: String, windowID: UInt32)
    public var valid: Bool {
        switch self {
        case .desktop: return true
        case .application(let bundle), .window(let bundle, _):
            guard !bundle.isEmpty, bundle.utf8.count <= 256, bundle.contains("."), bundle.utf8.allSatisfy({ (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0) || [45,46].contains($0) }) else { return false }
            if case .window(_, let id) = self { return id > 0 }; return true
        }
    }
}
public struct VideoFrameStamp: Codable, Equatable {
    public let sequence: UInt64
    public let timestampUnixMs: Int64
    public let offsetNanoseconds: UInt64
    public let displayID: UInt32
    public let sizeBytes: Int
}
/// One timeline covers all displays. Pause/revoke are terminal; resumption needs a new grant.
/// No bytes, AX text or titles are retained in this state machine.
public final class VideoRecordingBudget {
    private let lock = NSLock()
    public let authority: VideoRecordingAuthority
    public let scope: VideoRecordingScope
    public let durationMs: Int
    private let maximumBytes: Int
    private let maximumFrames: Int
    private let started: UInt64
    private let wallUnixMs: Int64
    private let now: () -> UInt64
    private var frames: UInt64 = 0
    private var bytes: Int = 0
    private var status = "recording"
    private var gap: String?
    public init(authority: VideoRecordingAuthority, scope: VideoRecordingScope, durationMs: Int, maximumBytes: Int, maximumFrames: Int = 1800, wallTime: Date = Date(), now: @escaping () -> UInt64 = { DispatchTime.now().uptimeNanoseconds }) throws {
        guard authority.valid, scope.valid, durationMs >= 1000, durationMs <= 900_000, maximumBytes > 0, maximumBytes <= 256 * 1024 * 1024, maximumFrames > 0, maximumFrames <= 3600, wallTime.timeIntervalSince1970.isFinite, wallTime.timeIntervalSince1970 > 0, wallTime.timeIntervalSince1970 < Double(Int64.max / 1000) - 900 else { throw NativeFailure("invalidVideoRecording", "Explicit record owner, scope and bounded video limits required") }
        self.authority = authority; self.scope = scope; self.durationMs = durationMs; self.maximumBytes = maximumBytes; self.maximumFrames = maximumFrames; self.now = now; started = now(); wallUnixMs = Int64(wallTime.timeIntervalSince1970 * 1000)
    }
    public func accept(sizeBytes: Int, displayID: UInt32) -> VideoFrameStamp? {
        lock.lock(); defer { lock.unlock() }
        guard status == "recording" else { return nil }
        let clock = now()
        guard clock >= started, clock - started < UInt64(durationMs) * 1_000_000 else { status = "paused"; gap = "durationExpired"; return nil }
        guard sizeBytes > 0, sizeBytes <= maximumBytes - bytes, frames < maximumFrames else { status = "paused"; gap = "videoCapacity"; return nil }
        frames += 1; bytes += sizeBytes
        return VideoFrameStamp(sequence: frames, timestampUnixMs: wallUnixMs + Int64((clock-started)/1_000_000), offsetNanoseconds: clock-started, displayID: displayID, sizeBytes: sizeBytes)
    }
    public func pause(reason: String) {
        lock.lock(); defer { lock.unlock() }
        guard status == "recording" else { return }
        status = "paused"
        gap = ["durationExpired", "videoCapacity", "manualPause", "consentWithdrawn", "permissionLost", "redactionUnavailable", "sinkFailure", "producerUnavailable"].contains(reason) ? reason : "producerUnavailable"
    }
    public func stop(confirmed: Bool) { lock.lock(); defer { lock.unlock() }; status = confirmed ? "stopped" : "stopUnconfirmed" }
    public var snapshot: (state: String, reason: String?, frames: UInt64, bytes: Int) { lock.lock(); defer { lock.unlock() }; return (status, gap, frames, bytes) }
}
