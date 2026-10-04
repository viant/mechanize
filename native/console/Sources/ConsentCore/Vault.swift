import Foundation

/// Metadata only. Account aliases identify a workflow account, never a username.
public struct VaultEntryRequest: Equatable, Identifiable {
    public let id: String
    public let origin: String
    public let accountAlias: String
    public let expiresAt: Date
    public init(id: String, origin: String, accountAlias: String, expiresAt: Date) {
        self.id = id; self.origin = origin; self.accountAlias = accountAlias; self.expiresAt = expiresAt
    }
    public var isValid: Bool {
        guard !id.isEmpty, !accountAlias.isEmpty, accountAlias.count <= 128,
              accountAlias.utf8.allSatisfy({ ($0 >= 65 && $0 <= 90) || ($0 >= 97 && $0 <= 122) || ($0 >= 48 && $0 <= 57) || $0 == 45 || $0 == 95 }),
              let url = URLComponents(string: origin), url.scheme == "https",
              let host = url.host, !host.isEmpty, host == host.lowercased(), !host.hasSuffix("."),
              url.user == nil, url.password == nil, url.path.isEmpty,
              url.query == nil, url.fragment == nil, url.port != 443,
              url.string == origin else { return false }
        return expiresAt > Date()
    }
}

/// This protocol is only for the signed local native-human channel. It must never
/// be exported as an MCP method or record bytes in generic RPC tracing. Values
/// are consumed synchronously by the adapter and sent only to the scoped broker.
/// Production activation additionally requires native/browser recording and
/// screenshots/video to withhold the entire secure-entry window.
public protocol VaultSecureInputAdapter {
    var secureCaptureSuppressionConfirmed: Bool { get }
    func submit(request: VaultEntryRequest, username: Data, password: Data) async throws
    func cancel(requestID: String) async throws
}

public enum VaultInputError: Error { case disconnected, expired }
