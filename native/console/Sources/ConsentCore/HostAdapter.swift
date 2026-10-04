import Foundation

public enum HelperPermission: String, Codable, CaseIterable { case accessibility, screenRecording, inputMonitoring }
public enum SystemPermissionState: String, Codable { case granted, denied, unknown, unsupported }
public struct HelperPermissionStatus: Codable, Equatable {
    public let helperBundleID: String
    public let permission: HelperPermission
    public let state: SystemPermissionState
    public let detail: String
    public init(helperBundleID: String, permission: HelperPermission, state: SystemPermissionState, detail: String) { self.helperBundleID = helperBundleID; self.permission = permission; self.state = state; self.detail = detail }
}
public struct InventoryTarget: Codable, Identifiable {
    public let id: String
    public let scope: ConsentScope
    public init(id: String, scope: ConsentScope) { self.id = id; self.scope = scope }
}
/// The embedding host resolves Scy enrollment credentials backed by Keychain, authenticates
/// a private Unix socket peer, and supplies broker data. Display strings are not authentication.
/// No implementation may infer verified identity from a request's self-reported client name.
public protocol ConsentHostAdapter: LocalConsentBroker {
    func inventory() async throws -> [InventoryTarget]
    func helperPermissionDoctor() async throws -> [HelperPermissionStatus]
    func applicationAccess() async throws -> ApplicationAccessSnapshot
    func updateApplicationAccess(expectedRevision: Int, policy: ApplicationAccessPolicy) async throws -> ApplicationAccessSnapshot
    /// Called only after an explicit button click. Never issue TCC prompts during refresh.
    func openSystemPermissionSettings(_ permission: HelperPermission) async throws
}
public extension ConsentHostAdapter {
    func applicationAccess() async throws -> ApplicationAccessSnapshot { throw ConsentError.disconnected }
    func updateApplicationAccess(expectedRevision: Int, policy: ApplicationAccessPolicy) async throws -> ApplicationAccessSnapshot { throw ConsentError.disconnected }
}
public struct DisconnectedHostAdapter: ConsentHostAdapter {
    public init() {}
    public var authenticatedPeerDescription: String? { nil }
    public func snapshot() async throws -> ConsentSnapshot { throw ConsentError.disconnected }
    public func decide(requestID: String, decision: ConsentDecision) async throws -> ConsentGrant? { throw ConsentError.disconnected }
    public func revoke(grantID: String) async throws -> RevokeStatus { throw ConsentError.disconnected }
    public func inventory() async throws -> [InventoryTarget] { throw ConsentError.disconnected }
    public func helperPermissionDoctor() async throws -> [HelperPermissionStatus] { throw ConsentError.disconnected }
    public func openSystemPermissionSettings(_ permission: HelperPermission) async throws { throw ConsentError.disconnected }
}
public enum ConsentWire {
    public static func encoder() -> JSONEncoder { let encoder = JSONEncoder(); encoder.dateEncodingStrategy = .iso8601; return encoder }
    public static func decoder() -> JSONDecoder { let decoder = JSONDecoder(); decoder.dateDecodingStrategy = .iso8601; return decoder }
}
