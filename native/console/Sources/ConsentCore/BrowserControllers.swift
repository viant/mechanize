import Foundation

public struct BrowserControllerPolicy: Codable, Equatable, Sendable {
    public let enabled: Bool
    public let origins: [String]
    public init(enabled: Bool, origins: [String]) { self.enabled = enabled; self.origins = origins }
    public static let suggestedOrigins = ["http://localhost:3000", "https://steward.agently.viantinc.com"]
    private static let localhostPatterns: Set<String> = ["localhost:*", "http://localhost:*", "https://localhost:*"]
    public static func validOrigin(_ value: String) -> Bool {
        localhostPatterns.contains(value) || exactOrigin(value)
    }
    private static func exactOrigin(_ value: String) -> Bool {
        guard value.utf8.count <= 2048, !value.contains("*"), !value.contains("\\"),
              let u = URLComponents(string: value), let host = u.host, !host.isEmpty,
              u.user == nil, u.password == nil, u.path.isEmpty, u.query == nil, u.fragment == nil,
              let scheme = u.scheme, let url = u.url, url.absoluteString == value else { return false }
        return scheme == "https" || (scheme == "http" && ["localhost", "127.0.0.1"].contains(host))
    }
    public static func allows(_ patterns: [String], origin: String) -> Bool {
        guard exactOrigin(origin), let u = URLComponents(string: origin) else { return false }
        return patterns.contains { pattern in
            if pattern == origin { return true }
            guard localhostPatterns.contains(pattern), u.host == "localhost", let scheme = u.scheme, ["http", "https"].contains(scheme) else { return false }
            if u.port == nil && origin != scheme + "://localhost" { return false }
            if let port = u.port {
                guard (1...65535).contains(port), !(scheme == "http" && port == 80), !(scheme == "https" && port == 443), origin == scheme + "://localhost:" + String(port) else { return false }
            }
            return pattern == "localhost:*" || pattern == scheme + "://localhost:*"
        }
    }
    public var isValid: Bool { origins.count <= 20 && (!enabled || !origins.isEmpty) && origins.allSatisfy(Self.validOrigin) }
}
public struct BrowserControllerSession: Decodable, Identifiable, Sendable {
    public let id: String
    public let origin: String
    public let documentId: String
    public let tabId: Int
    public let approved: Bool
    public let expiresAt: Date
    private enum CodingKeys: String, CodingKey { case id, origin, documentId, tabId, approved, expiresAt }
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(String.self, forKey: .id); origin = try c.decode(String.self, forKey: .origin)
        documentId = try c.decode(String.self, forKey: .documentId); tabId = try c.decode(Int.self, forKey: .tabId)
        approved = try c.decode(Bool.self, forKey: .approved)
        let text = try c.decode(String.self, forKey: .expiresAt)
        let formatter = ISO8601DateFormatter(); formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        guard let date = formatter.date(from: text) ?? ISO8601DateFormatter().date(from: text) else {
            throw DecodingError.dataCorruptedError(forKey: .expiresAt, in: c, debugDescription: "Invalid controller expiry")
        }
        expiresAt = date
    }
}
public struct BrowserControllerState: Decodable, Sendable {
    public let policy: BrowserControllerPolicy
    public let sessions: [BrowserControllerSession]
    public let connected: Bool
    public var isValid: Bool {
        policy.isValid && sessions.count <= 8 && Set(sessions.map(\.id)).count == sessions.count && sessions.allSatisfy {
            !$0.id.isEmpty && $0.id.utf8.count <= 128 && !$0.documentId.isEmpty && $0.tabId >= 0 && policy.enabled && BrowserControllerPolicy.allows(policy.origins, origin: $0.origin)
        }
    }
}
public enum BrowserControllerAction: String, Sendable { case status, configure, approve, revoke }
