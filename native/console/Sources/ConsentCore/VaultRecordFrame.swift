import Foundation

public enum VaultRecordFrameError: Error, LocalizedError {
    case invalidInput, alreadyConsumed, transportUnavailable
    public var errorDescription: String? {
        switch self {
        case .invalidInput: return "Native Vault record input rejected."
        case .alreadyConsumed: return "Native Vault record is no longer available."
        case .transportUnavailable: return "Native Vault record write could not be confirmed."
        }
    }
}

/// Write-only MVLT v2 companion; never Codable, JSON, MCP, or a plaintext getter.
/// Key, field names, and values are all secrets. Inputs must originate in a
/// protected native form. Creating this value establishes NO authorization:
/// the future native transport must independently authenticate and acquire its
/// exact protection/admission lease BEFORE writeOnce, then write one frame and
/// shut down its write half. No transport or UI is registered by this type.
///
/// The initializer consumes the supplied variables even when validation fails.
/// Callers must relinquish all other aliases. Copies of this struct share one
/// owner and cannot replay the write. Owned input/frame buffers are overwritten
/// on release; Swift/Cocoa/OS copies and caller-made aliases are not guaranteed
/// erased or locked in memory. The callback must not retain the borrowed pointer
/// or copy bytes anywhere except the already admitted native transport.
public struct VaultRecordFrame: Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    private let owner: Owner

    public init(key: inout Data, fields: inout [(name: Data, value: Data)]) throws {
        owner = try Owner(key: &key, fields: &fields)
    }

    /// Exactly one synchronous write attempt, including when its callback fails.
    /// This returns no bytes. Every callback error is replaced with a fixed error.
    public func writeOnce(_ consume: (UnsafeRawBufferPointer) throws -> Void) throws {
        try owner.writeOnce(consume)
    }

    /// Cancels unused input across every copy. It cannot cancel an in-flight
    /// admitted callback, which owns its temporary frame until the callback ends.
    public func destroy() { owner.destroy() }

    public var description: String { "[native Vault record withheld]" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [Mirror.Child]()) }

    private final class Owner: @unchecked Sendable {
        private let lock = NSLock()
        private var used = false
        private var key = Data()
        private var fields: [(name: Data, value: Data)] = []
        private var frameLength = 0
        private static let maximumFrameLength = 65_536

        init(key: inout Data, fields: inout [(name: Data, value: Data)]) throws {
            swap(&self.key, &key)
            swap(&self.fields, &fields)
            do { frameLength = try validatedLength() }
            catch { used = true; wipeInputs(); throw VaultRecordFrameError.invalidInput }
        }
        deinit { wipeInputs() }

        private func validatedLength() throws -> Int {
            guard !key.isEmpty, key.count <= 1024, (1...32).contains(fields.count) else {
                throw VaultRecordFrameError.invalidInput
            }
            // Complete size includes the 12-byte header and every length word.
            var length = 12 + 4 + key.count + 4
            for index in fields.indices {
                let field = fields[index]
                guard !field.name.isEmpty, field.name.count <= 256,
                      !field.value.isEmpty, field.value.count <= Self.maximumFrameLength else {
                    throw VaultRecordFrameError.invalidInput
                }
                for previous in 0..<index where fields[previous].name == field.name {
                    throw VaultRecordFrameError.invalidInput
                }
                // Each component is bounded before addition; no untrusted
                // count can overflow Int or reach an unbounded allocation.
                length += 8 + field.name.count + field.value.count
                guard length <= Self.maximumFrameLength else { throw VaultRecordFrameError.invalidInput }
            }
            return length
        }
        private func wipeInputs() {
            key.resetBytes(in: 0..<key.count)
            key.removeAll(keepingCapacity: false)
            for index in fields.indices {
                fields[index].name.resetBytes(in: 0..<fields[index].name.count)
                fields[index].value.resetBytes(in: 0..<fields[index].value.count)
            }
            fields.removeAll(keepingCapacity: false)
            frameLength = 0
        }
        func destroy() {
            lock.lock(); defer { lock.unlock() }
            used = true; wipeInputs()
        }
        func writeOnce(_ consume: (UnsafeRawBufferPointer) throws -> Void) throws {
            lock.lock()
            guard !used else { lock.unlock(); throw VaultRecordFrameError.alreadyConsumed }
            used = true
            // One exact allocation, no append/reallocation of secret payloads.
            var frame = Data(count: frameLength)
            frame.withUnsafeMutableBytes { (raw: UnsafeMutableRawBufferPointer) in
                var offset = 0
                func byte(_ value: UInt8) { raw[offset] = value; offset += 1 }
                func word(_ value: Int) {
                    let number = UInt32(value)
                    byte(UInt8((number >> 24) & 255)); byte(UInt8((number >> 16) & 255))
                    byte(UInt8((number >> 8) & 255)); byte(UInt8(number & 255))
                }
                func bytes(_ value: Data) {
                    word(value.count)
                    value.withUnsafeBytes { source in
                        raw.baseAddress!.advanced(by: offset).copyMemory(from: source.baseAddress!, byteCount: source.count)
                    }
                    offset += value.count
                }
                for value: UInt8 in [77, 86, 76, 84, 0, 0, 0, 2] { byte(value) }
                word(frameLength - 12)
                bytes(key); word(fields.count)
                for field in fields { bytes(field.name); bytes(field.value) }
            }
            wipeInputs()
            lock.unlock()
            // The shared owner is already spent before entering caller code,
            // so reentrant/concurrent copies cannot replay or deadlock it.
            try frame.withUnsafeMutableBytes { (raw: UnsafeMutableRawBufferPointer) throws -> Void in
                defer { raw.initializeMemory(as: UInt8.self, repeating: 0) }
                do { try consume(UnsafeRawBufferPointer(raw)) }
                catch { throw VaultRecordFrameError.transportUnavailable }
            }
        }
    }
}
