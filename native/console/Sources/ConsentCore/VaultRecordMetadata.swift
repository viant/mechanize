import Foundation

/// Opaque metadata only. No record key, field name or value is included.
public struct VaultRecordMetadata: Sendable, Equatable {
    public let id: String
    public let revision: String
    public init(id: String, revision: String) { self.id = id; self.revision = revision }
    var isValid: Bool { nativeVaultEntryID(id) && nativeVaultEntryID(revision) }
}
func nativeVaultSessionID(_ value: String) -> Bool {
    value.utf8.count == 48 && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
}
func nativeRecordBinding(_ value: String) -> Bool {
    if nativeVaultEntryID(value) { return true }
    guard value.hasPrefix("account-") else { return false }
    let text = String(value.dropFirst(8))
    guard let uuid = UUID(uuidString: text) else { return false }
    return uuid.uuidString.lowercased() == text
}
func parseNativeRecordMetadata(_ data: Data) throws -> VaultRecordMetadata {
    guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
          Set(object.keys) == ["reference", "revision"],
          let ref = object["reference"] as? [String: Any], Set(ref.keys) == ["id"],
          let id = ref["id"] as? String, let revision = object["revision"] as? String else {
        throw BrokerTransportError.malformedResponse
    }
    let result = VaultRecordMetadata(id: id, revision: revision)
    guard result.isValid else { throw BrokerTransportError.malformedResponse }
    return result
}
