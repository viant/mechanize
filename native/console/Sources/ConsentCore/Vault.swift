import Foundation

/// Metadata only. Account aliases identify a workflow account, never a username.
public struct VaultEntryRequest: Equatable, Identifiable, Sendable {
    public let id: String
    public let origin: String
    public let accountAlias: String
    public let expiresAt: Date
    public init(id: String, origin: String, accountAlias: String, expiresAt: Date) {
        self.id = id; self.origin = origin; self.accountAlias = accountAlias; self.expiresAt = expiresAt
    }
    public var isValid: Bool {
        guard !id.isEmpty, origin.utf8.count <= 2048, !accountAlias.isEmpty, accountAlias.count <= 128,
              accountAlias.utf8.allSatisfy({ ($0 >= 65 && $0 <= 90) || ($0 >= 97 && $0 <= 122) || ($0 >= 48 && $0 <= 57) || $0 == 45 || $0 == 95 }),
              let url = URLComponents(string: origin), url.scheme == "https",
              let host = url.host, !host.isEmpty, host == host.lowercased(), !host.hasSuffix("."),
              url.user == nil, url.password == nil, url.path.isEmpty,
              url.query == nil, url.fragment == nil, url.port != 443,
              url.port == nil || (1...65535).contains(url.port!),
              url.string == origin else { return false }
        return expiresAt > Date()
    }
}

/// This protocol is only for the signed local native-human channel. It must never
/// be exported as an MCP method or record bytes in generic RPC tracing. Values
/// are consumed synchronously by the adapter and sent only to the scoped broker.
/// Production activation additionally requires native/browser recording and
/// screenshots/video to withhold the entire secure-entry window.
@MainActor public protocol VaultSecureInputAdapter {
    var secureCaptureSuppressionConfirmed: Bool { get }
    func submit(request: VaultEntryRequest, username: Data, password: Data) async throws
    func cancel(requestID: String) async throws
}

public enum VaultInputError: Error { case disconnected, expired }

/// Website input is collected only in the confirmed protected native panel.
/// Reject URL userinfo and non-origin components before any broker message.
public enum VaultOrigin {
    public static func canonical(_ input: String) -> String? {
        let text = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard var url = URLComponents(string: text), url.scheme?.lowercased() == "https",
              let host = url.host, !host.isEmpty, !host.hasSuffix("."),
              url.user == nil, url.password == nil, url.query == nil, url.fragment == nil,
              url.path.isEmpty || url.path == "/", url.port == nil || (1...65535).contains(url.port!) else { return nil }
        url.scheme = "https"; url.host = host.lowercased(); url.path = ""
        if url.port == 443 { url.port = nil }
        guard let origin = url.string,
              VaultEntryRequest(id: "validation", origin: origin, accountAlias: "validation", expiresAt: .distantFuture).isValid else { return nil }
        return origin
    }
}

/// Public routing metadata only. No credential values can be decoded here.
public struct VaultInventoryEntry: Identifiable, Equatable, Sendable {
    public let origin: String
    public let accountAlias: String
    public let resourceURL: String
    public let revision: String
    public var id: String { resourceURL }
    public init(origin: String, accountAlias: String, resourceURL: String, revision: String) {
        self.origin = origin; self.accountAlias = accountAlias; self.resourceURL = resourceURL; self.revision = revision
    }
    public func request() -> VaultEntryRequest {
        VaultEntryRequest(id: UUID().uuidString, origin: origin, accountAlias: accountAlias, expiresAt: Date().addingTimeInterval(240))
    }
}
