import Foundation

/// Only compares the result of this authorized one-shot replacement. No value,
/// digest, previous content or independently queryable comparison is returned.
public enum ReplacementProof {
    public static func permitted(role: String?, subrole: String?, subroleKnown: Bool, valueSettable: Bool?, labels: [String]) -> Bool {
        guard ["AXTextField","AXTextArea"].contains(role ?? ""), subroleKnown, subrole != "AXSecureTextField", valueSettable == true else { return false }
        let label = labels.joined(separator:" ").lowercased()
        return !["password","credential","secret","token","securetextfield","api key"].contains(where:label.contains)
    }
    public static func perform(
        expected: String, permitted: Bool,
        set: () throws -> Bool, read: () throws -> String?, revalidate: () throws -> Void,
        timeout: TimeInterval = 0.250, pollInterval: TimeInterval = 0.025, maximumReads: Int = 10,
        now: () -> TimeInterval = { ProcessInfo.processInfo.systemUptime },
        wait: (TimeInterval) throws -> Void = { Thread.sleep(forTimeInterval: $0) }
    ) throws -> Bool? {
        guard try set() else { return nil }
        return compare(expected: expected, permitted: permitted, read: read, revalidate: revalidate, timeout: timeout, pollInterval: pollInterval, maximumReads: maximumReads, now: now, wait: wait)
    }
    /// Read-only boolean comparison; no value or digest escapes this boundary.
    public static func compare(expected: String, permitted: Bool, read: () throws -> String?, revalidate: () throws -> Void,
        timeout: TimeInterval = 0.250, pollInterval: TimeInterval = 0.025, maximumReads: Int = 10,
        now: () -> TimeInterval = { ProcessInfo.processInfo.systemUptime }, wait: (TimeInterval) throws -> Void = { Thread.sleep(forTimeInterval: $0) }) -> Bool? {
        guard permitted, expected.utf8.count <= 65_536, !expected.contains("\0") else { return nil }
        guard timeout.isFinite, timeout > 0, timeout <= 0.250,
              pollInterval.isFinite, pollInterval > 0, pollInterval <= timeout,
              (1...10).contains(maximumReads) else { return nil }
        let started = now()
        guard started.isFinite else { return nil }
        let deadline = started + timeout
        var lastTime = started
        var lastResult: Bool?
        func timeRemaining() -> TimeInterval? {
            let current = now()
            guard current.isFinite, current >= lastTime, current < deadline else { return nil }
            lastTime = current
            return deadline - current
        }
        do {
            // The setter is never retried. Each settling read is independently
            // fenced before and after by the caller's process, classification,
            // lease and request-budget checks. No compared content escapes.
            for attempt in 0..<maximumReads {
                guard timeRemaining() != nil else { return lastResult }
                try revalidate()
                guard timeRemaining() != nil else { return lastResult }
                let observed = try read()
                try revalidate()
                guard timeRemaining() != nil else { return lastResult }
                if let observed = observed {
                    guard observed.utf8.count <= 65_536, !observed.contains("\0") else { return nil }
                    lastResult = observed.utf8.elementsEqual(expected.utf8)
                    if lastResult == true { return true }
                } else { lastResult = nil }
                if attempt + 1 < maximumReads {
                    guard let remaining = timeRemaining() else { return lastResult }
                    try wait(min(pollInterval, remaining))
                }
            }
            return lastResult
        } catch { return nil }
    }
}
