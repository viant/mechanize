import Foundation

public enum VaultNativeChannelError: Error { case outcomeUnknown, protectionUnknown, keySetupUnknown }

func nativeVaultEntryID(_ value: String) -> Bool {
    value.utf8.count == 64 && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
}

/// No raw remote rejection messages escape this parser. Unknown result keys,
/// request-ID mismatch and non-boolean admission cannot release credential bytes.
func nativeVaultResult(_ data: Data, id: String) throws -> Data {
    guard !data.isEmpty, data.count <= BrokerFrame.maximumLength,
          let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
          Set(object.keys).isSubset(of: ["jsonrpc", "id", "result", "error"]),
          object["jsonrpc"] as? String == "2.0", object["id"] as? String == id,
          (object["result"] != nil) != (object["error"] != nil) else { throw BrokerTransportError.malformedResponse }
    guard object["error"] == nil else { throw BrokerTransportError.remoteRejected }
    return try JSONSerialization.data(withJSONObject: object["result"]!, options: [.fragmentsAllowed])
}
func nativeVaultReference(_ value: String) -> Bool {
    let prefix = "mechanize-vault://credential/"
    guard value.hasPrefix(prefix) else { return false }
    let parts = value.dropFirst(prefix.count).split(separator: "/", omittingEmptySubsequences: false)
    return parts.count == 2 && parts.allSatisfy { $0.count == 64 && $0.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) } }
}

func parseNativeVaultInventory(_ object: [String: Any]) throws -> [VaultInventoryEntry] {
    guard Set(object.keys) == ["entries"], let rows = object["entries"] as? [[String: Any]] else { throw BrokerTransportError.malformedResponse }
    var seen = Set<String>()
    return try rows.map { row in
        guard Set(row.keys) == ["origin", "accountAlias", "reference", "revision"],
              let origin = row["origin"] as? String, let alias = row["accountAlias"] as? String,
              let reference = row["reference"] as? [String: Any], Set(reference.keys) == ["resourceURL"],
              let url = reference["resourceURL"] as? String, nativeVaultReference(url), seen.insert(url).inserted,
              let revision = row["revision"] as? String, nativeVaultEntryID(revision),
              VaultEntryRequest(id: "inventory", origin: origin, accountAlias: alias, expiresAt: .distantFuture).isValid else { throw BrokerTransportError.malformedResponse }
        return VaultInventoryEntry(origin: origin, accountAlias: alias, resourceURL: url, revision: revision)
    }
}
