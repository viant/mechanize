import Foundation

/// Shared by the serialized action lane and independent watchdog. Native posting
/// closures run under the lock; no down event can race after inhibition.
public final class InputSafety {
    private let lock = NSLock()
    private var inhibited = true
    private var cleanup: [String: () -> Bool] = [:]
    public init() {}
    public func enable() { lock.lock(); inhibited = false; lock.unlock() }
    public func press(token: String, preflight: () throws -> Void = {}, down: () -> Bool, up: @escaping () -> Bool) throws {
        lock.lock(); defer { lock.unlock() }
        guard !inhibited else { throw NativeFailure("inputInhibited", "Input authority has been revoked") }
        guard cleanup[token] == nil else { throw NativeFailure("inputAlreadyHeld", "Input is already held") }
        try preflight()
        // Retain the cleanup before the uncertain posting boundary.
        cleanup[token] = up
        guard down() else { throw NativeFailure("inputDispatchUnknown", "Input down posting failed") }
        guard up() else { throw NativeFailure("inputDispatchUnknown", "Input release posting failed") }
        cleanup.removeValue(forKey: token)
    }
    public func inhibitAndRelease() -> (released: Int, unknown: Int) {
        lock.lock(); defer { lock.unlock() }
        inhibited = true
        var released = 0; var unknown = 0
        var remaining: [String: () -> Bool] = [:]
        for (token, release) in cleanup {
            if release() { released += 1 } else { unknown += 1; remaining[token] = release }
        }
        // An unconfirmed release remains held until a later release succeeds.
        // Repeated cleanup must not manufacture proof from an emptied registry.
        cleanup = remaining
        return (released, unknown)
    }
    public func cleanupOutcome(businessOutcomeUnknown: Bool) -> InputCleanupOutcome {
        let releases = inhibitAndRelease()
        return InputCleanupOutcome(releasesDispatched: releases.released, unknownReleases: releases.unknown, businessOutcomeUnknown: businessOutcomeUnknown)
    }
}

// Application effects and physical held-input release have distinct evidence.
public struct InputCleanupOutcome {
    public let releasesDispatched: Int
    public let unknownReleases: Int
    public let businessOutcomeUnknown: Bool
}
