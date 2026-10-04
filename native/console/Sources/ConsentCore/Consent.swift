import Foundation

public enum ConsentMode: String, Codable, CaseIterable { case observe, control, record }
public enum ConsentDecision: String, Codable { case allowOnce = "allow_once", allowSession = "allow_session", allowUntilRevoked = "allow_until_revoked", deny }
public enum ClientVerification: String, Codable { case verified, unverified, unknown }
public enum RevokeStatus: String, Codable { case requested, stopping, revoked, cleanupUnknown }
public enum GrantState: String, Codable { case active, revoked, expired, consumed }
public struct VerifiedClient: Codable, Equatable {
    public let id: String
    public let displayName: String
    public let verification: ClientVerification
    public init(id: String, displayName: String, verification: ClientVerification) { self.id = id; self.displayName = displayName; self.verification = verification }
}
public struct ConsentScope: Codable, Equatable {
    public enum Kind: String, Codable { case desktop, application, window, origin }
    public let kind: Kind
    public let bundleID: String?
    public let windowID: String?
    public let origin: String?
    public let displayName: String
    public init(kind: Kind, bundleID: String? = nil, windowID: String? = nil, origin: String? = nil, displayName: String = "") { self.kind = kind; self.bundleID = bundleID; self.windowID = windowID; self.origin = origin; self.displayName = displayName }
    private enum CodingKeys: String, CodingKey { case kind, bundleID, windowID, origin, displayName }
    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        kind = try values.decode(Kind.self, forKey: .kind)
        bundleID = try values.decodeIfPresent(String.self, forKey: .bundleID)
        windowID = try values.decodeIfPresent(String.self, forKey: .windowID)
        origin = try values.decodeIfPresent(String.self, forKey: .origin)
        displayName = try values.decodeIfPresent(String.self, forKey: .displayName) ?? ""
    }
    public var exactDescription: String {
        switch kind {
        case .desktop: return "All applications and connected browsers"
        case .application: return "Application: \(displayName) [\(bundleID ?? "missing identifier")]"
        case .window: return "Window: \(displayName) [\(bundleID ?? "missing application"), window \(windowID ?? "missing identifier")]"
        case .origin: return "Origin: \(origin ?? "missing origin") · \(displayName)"
        }
    }
    public var isExact: Bool {
        guard displayName.utf8.count <= 512, (bundleID ?? "").utf8.count <= 256,
              (windowID ?? "").utf8.count <= 256, (origin ?? "").utf8.count <= 2048,
              !(bundleID ?? "").contains("*"), !(bundleID ?? "").contains("?"),
              !(windowID ?? "").contains("*"), !(windowID ?? "").contains("?"), !(origin ?? "").contains("*") else { return false }
        switch kind {
        case .desktop: return (bundleID ?? "").isEmpty && (windowID ?? "").isEmpty && (origin ?? "").isEmpty
        case .application: return !(bundleID ?? "").isEmpty && (windowID ?? "").isEmpty && (origin ?? "").isEmpty
        case .window: return !(bundleID ?? "").isEmpty && !(windowID ?? "").isEmpty && (origin ?? "").isEmpty
        case .origin:
            guard let text = origin, let u = URLComponents(string: text), ["https", "http"].contains(u.scheme ?? ""), u.host != nil else { return false }
            return (bundleID ?? "").isEmpty && (windowID ?? "").isEmpty && u.user == nil && u.password == nil && u.path.isEmpty && u.query == nil && u.fragment == nil
        }
    }
}
public struct ConsentRequest: Codable, Equatable, Identifiable {
    public let id: String
    public let verifiedClient: VerifiedClient
    public let scope: ConsentScope
    public let modes: [ConsentMode]
    public let purpose: String
    public let durationSeconds: Int
    public let createdAt: Date
    public let expiresAt: Date
    public init(id: String, verifiedClient: VerifiedClient, scope: ConsentScope, modes: [ConsentMode], purpose: String, durationSeconds: Int, createdAt: Date, expiresAt: Date) { self.id = id; self.verifiedClient = verifiedClient; self.scope = scope; self.modes = modes; self.purpose = purpose; self.durationSeconds = durationSeconds; self.createdAt = createdAt; self.expiresAt = expiresAt }
    public func isValid(at now: Date) -> Bool { !verifiedClient.id.isEmpty && !verifiedClient.displayName.isEmpty && verifiedClient.verification == .verified && scope.isExact && !modes.isEmpty && Set(modes).count == modes.count && !purpose.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && durationSeconds > 0 && createdAt <= now && expiresAt > now }
}
public struct ConsentGrant: Codable, Equatable, Identifiable {
    public let id: String
    public let requestID: String
    public let clientID: String
    public let scope: ConsentScope
    public let modes: [ConsentMode]
    public let purpose: String
    public let durationSeconds: Int
    public let decision: ConsentDecision
    public let createdAt: Date
    public let expiresAt: Date
    public let state: GrantState
    public let permanent: Bool
    public init(id: String, requestID: String, clientID: String, scope: ConsentScope, modes: [ConsentMode], purpose: String, durationSeconds: Int, decision: ConsentDecision, createdAt: Date, expiresAt: Date, state: GrantState, permanent: Bool = false) { self.id = id; self.requestID = requestID; self.clientID = clientID; self.scope = scope; self.modes = modes; self.purpose = purpose; self.durationSeconds = durationSeconds; self.decision = decision; self.createdAt = createdAt; self.expiresAt = expiresAt; self.state = state; self.permanent = permanent }
    private enum CodingKeys: String, CodingKey { case id, requestID, clientID, scope, modes, purpose, durationSeconds, decision, createdAt, expiresAt, state, permanent }
    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        id = try values.decode(String.self, forKey: .id); requestID = try values.decode(String.self, forKey: .requestID); clientID = try values.decode(String.self, forKey: .clientID)
        scope = try values.decode(ConsentScope.self, forKey: .scope); modes = try values.decode([ConsentMode].self, forKey: .modes); purpose = try values.decode(String.self, forKey: .purpose)
        durationSeconds = try values.decode(Int.self, forKey: .durationSeconds); decision = try values.decode(ConsentDecision.self, forKey: .decision); createdAt = try values.decode(Date.self, forKey: .createdAt)
        expiresAt = try values.decode(Date.self, forKey: .expiresAt); state = try values.decode(GrantState.self, forKey: .state); permanent = try values.decodeIfPresent(Bool.self, forKey: .permanent) ?? false
    }
    public func isActive(at now: Date) -> Bool { state == .active && permanent == (decision == .allowUntilRevoked) && (permanent || expiresAt > now) }
}
public struct ConsentSnapshot: Codable { public let requests: [ConsentRequest]; public let grants: [ConsentGrant]; public init(requests: [ConsentRequest], grants: [ConsentGrant]) { self.requests = requests; self.grants = grants } }
public enum ConsentError: Error, LocalizedError {
    case disconnected, invalidRequest, invalidResponse
    public var errorDescription: String? { switch self { case .disconnected: return "No authenticated local broker is connected. Preview cannot issue grants."; case .invalidRequest: return "The request is incomplete, expired, or does not name a valid scope."; case .invalidResponse: return "Broker response did not match the reviewed request." } }
}
/// Host implements this with an authenticated local broker and Scy/Keychain credential resolution.
/// Credentials remain opaque; never use command-line arguments or plaintext configuration.
public protocol LocalConsentBroker {
    var authenticatedPeerDescription: String? { get }
    func snapshot() async throws -> ConsentSnapshot
    func decide(requestID: String, decision: ConsentDecision) async throws -> ConsentGrant?
    func revoke(grantID: String) async throws -> RevokeStatus
}
public struct DisconnectedBroker: LocalConsentBroker {
    public init() {}
    public var authenticatedPeerDescription: String? { nil }
    public func snapshot() async throws -> ConsentSnapshot { throw ConsentError.disconnected }
    public func decide(requestID: String, decision: ConsentDecision) async throws -> ConsentGrant? { throw ConsentError.disconnected }
    public func revoke(grantID: String) async throws -> RevokeStatus { throw ConsentError.disconnected }
}
@MainActor public final class ConsentController {
    public private(set) var requests: [ConsentRequest] = []
    public private(set) var grants: [ConsentGrant] = []
    public let broker: any LocalConsentBroker
    public var isConnected: Bool { !(broker.authenticatedPeerDescription ?? "").isEmpty }
    public init(broker: any LocalConsentBroker) { self.broker = broker }
    public func refresh() async throws {
        guard isConnected else { throw ConsentError.disconnected }
        let value = try await broker.snapshot(); requests = value.requests; grants = value.grants
    }
    public func decide(_ request: ConsentRequest, decision: ConsentDecision, now: Date = Date()) async throws {
        guard isConnected else { throw ConsentError.disconnected }
        guard requests.contains(request), request.isValid(at: now) else { throw ConsentError.invalidRequest }
        let grant = try await broker.decide(requestID: request.id, decision: decision)
        if decision == .deny { guard grant == nil else { throw ConsentError.invalidResponse } }
        else {
            guard let grant, grant.requestID == request.id, grant.clientID == request.verifiedClient.id, grant.scope == request.scope, grant.modes == request.modes, grant.purpose == request.purpose, grant.durationSeconds == request.durationSeconds, grant.decision == decision, grant.state == .active, grant.createdAt <= Date() else { throw ConsentError.invalidResponse }
            if decision == .allowUntilRevoked {
                guard grant.permanent, grant.expiresAt == Date(timeIntervalSince1970: 0) else { throw ConsentError.invalidResponse }
            } else {
                guard !grant.permanent, grant.expiresAt > Date(), grant.expiresAt <= grant.createdAt.addingTimeInterval(TimeInterval(request.durationSeconds)) else { throw ConsentError.invalidResponse }
            }
        }
        try await refresh()
    }
    public func revoke(_ grant: ConsentGrant) async throws -> RevokeStatus {
        guard isConnected else { throw ConsentError.disconnected }
        guard grants.contains(grant) else { throw ConsentError.invalidRequest }
        let status = try await broker.revoke(grantID: grant.id)
        try await refresh()
        if status == .revoked { guard !grants.contains(where: { $0.id == grant.id && $0.isActive(at: Date()) }) else { throw ConsentError.invalidResponse } }
        return status
    }
}
