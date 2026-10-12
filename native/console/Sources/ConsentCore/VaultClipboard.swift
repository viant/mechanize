import Foundation

/// Native UI only. No clipboard contents or errors cross the agent transport.
public protocol VaultClipboardSource {
    var changeCount: Int { get }
    func readUTF8() -> Data?
    func clear(ifUnchanged revision: Int)
}

public enum VaultClipboardResult: Equatable {
    case imported, unavailable, protectionUnavailable, invalidInput
}

public enum VaultClipboard {
    public static func importLocally(source: any VaultClipboardSource,
                                     secureCaptureSuppressionConfirmed: Bool,
                                     requestValid: Bool, submitting: Bool,
                                     consume: (Data) throws -> Void) -> VaultClipboardResult {
        guard secureCaptureSuppressionConfirmed, requestValid, !submitting else { return .protectionUnavailable }
        let revision = source.changeCount
        guard var bytes = source.readUTF8() else { return .unavailable }
        defer { bytes.resetBytes(in: 0..<bytes.count) }
        guard !bytes.isEmpty, bytes.count <= 65_536, !bytes.contains(0), String(data: bytes, encoding: .utf8) != nil else {
            return .invalidInput
        }
        do { try consume(bytes) } catch { return .unavailable }
        // Never erase a newer item copied by the employee while importing.
        source.clear(ifUnchanged: revision)
        return .imported
    }
}
