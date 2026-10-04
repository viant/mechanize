import Foundation

public enum FramingError: Error { case oversized, truncated, invalid }
public enum FrameCodec {
    public static let maximumBytes = 2 * 1024 * 1024
    public static let maximumWindowFramePNGBytes = 32 * 1024 * 1024
    public static let maximumWindowFrameResponseBytes = ((maximumWindowFramePNGBytes + 2) / 3) * 4 + 64 * 1024
    public static func read(_ handle: FileHandle) throws -> Data? {
        guard let header = try readExactly(handle, count: 4, allowEOF: true) else { return nil }
        let size = header.reduce(0) { ($0 << 8) | Int($1) }
        guard size > 0, size <= maximumBytes else { throw FramingError.oversized }
        return try readExactly(handle, count: size, allowEOF: false)
    }
    static func readExactly(_ handle: FileHandle, count: Int, allowEOF: Bool) throws -> Data? {
        var result = Data()
        while result.count < count {
            guard let part = try handle.read(upToCount: count - result.count), !part.isEmpty else {
                if result.isEmpty && allowEOF { return nil }
                throw FramingError.truncated
            }
            result.append(part)
        }
        return result
    }
    public static func write(_ value: [String: Any], to handle: FileHandle) throws {
        try write(value, to: handle, maximum: maximumBytes)
    }
    // The dispatch loop supplies the expected request method and authenticated
    // launch identity. Reply fields cannot opt another method into this budget.
    public static func writeResponse(_ value: [String: Any], to handle: FileHandle, requestMethod: String, brokerAuthenticated: Bool) throws {
        let capture = brokerAuthenticated && requestMethod == "windows.captureFrame" && value["error"] == nil && value["result"] is [String: Any]
        try write(value, to: handle, maximum: capture ? maximumWindowFrameResponseBytes : maximumBytes)
    }
    private static func write(_ value: [String: Any], to handle: FileHandle, maximum: Int) throws {
        // Base64 slashes must remain single bytes to satisfy the exact bounded
        // encoded-size calculation. Ordinary replies retain their old encoding.
        let options: JSONSerialization.WritingOptions = maximum == maximumBytes ? [.sortedKeys] : [.sortedKeys, .withoutEscapingSlashes]
        let data = try JSONSerialization.data(withJSONObject: value, options: options)
        guard data.count <= maximum else { throw FramingError.oversized }
        let size = UInt32(data.count)
        let header = Data([UInt8(size >> 24), UInt8((size >> 16) & 255), UInt8((size >> 8) & 255), UInt8(size & 255)])
        try handle.write(contentsOf: header + data)
    }
}

public struct NativeFailure: Error {
    public let code: String
    public let message: String
    public init(_ code: String, _ message: String) { self.code = code; self.message = message }
}

/// All budgets use a monotonic clock. UTC is reserved for evidence timestamps.
public struct Budget {
    let started: UInt64
    let duration: UInt64
    public init(milliseconds: Int) throws {
        guard milliseconds > 0, milliseconds <= 30_000 else { throw NativeFailure("invalidDeadline", "deadlineRemainingMs must be 1...30000") }
        started = DispatchTime.now().uptimeNanoseconds
        duration = UInt64(milliseconds) * 1_000_000
    }
    public func check() throws {
        guard DispatchTime.now().uptimeNanoseconds - started < duration else { throw NativeFailure("deadlineExceeded", "Native request deadline expired") }
    }
    public var remainingSeconds: Float { Float(max(0, Double(duration) - Double(DispatchTime.now().uptimeNanoseconds - started)) / 1_000_000_000) }
}

/// Dedupe is bounded to one helper epoch. Evicted mutation IDs are never replayed:
/// after saturation the helper refuses new mutations until restart/reconciliation.
public final class MutationLedger {
    private var replies: [String: [String: Any]] = [:]
    private let limit: Int
    public init(limit: Int = 4096) { self.limit = limit }
    public func reply(for id: String) -> [String: Any]? { replies[id] }
    public func reserve(_ id: String) throws {
        guard replies[id] == nil else { throw NativeFailure("duplicateRequest", "Request already dispatched") }
        guard replies.count < limit else { throw NativeFailure("dedupeCapacity", "Restart and reconcile before further mutations") }
        replies[id] = ["dispatchState": "unknown"]
    }
    public func finish(_ id: String, reply: [String: Any]) { replies[id] = reply }
}
