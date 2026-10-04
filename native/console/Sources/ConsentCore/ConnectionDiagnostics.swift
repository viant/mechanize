import Foundation

public struct ConnectionDiagnosticReport: Codable, Sendable {
    public let stage: String
    public let brokerVerified: Bool
    public let credentialAvailable: Bool
    public let authenticated: Bool
    public let errorCode: String?
    public var succeeded: Bool { stage == "complete" && authenticated && errorCode == nil }
    public init(stage: String, brokerVerified: Bool = false, credentialAvailable: Bool = false, authenticated: Bool = false, errorCode: String? = nil) {
        self.stage = stage; self.brokerVerified = brokerVerified; self.credentialAvailable = credentialAvailable
        self.authenticated = authenticated; self.errorCode = errorCode
    }
    public func json() -> Data {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        return (try? encoder.encode(self)) ?? Data("{\"stage\":\"output\",\"errorCode\":\"encodingFailed\"}".utf8)
    }
}

/// Explicit owner CLI connection check only. Never invoked during UI startup.
/// The report contains scalar progress, never credentials, paths, inventories,
/// permission details, request bodies, snapshots or broker-provided strings.
public enum ConnectionDiagnostics {
    public static func run(transport: any FramedBrokerTransport, credentials: any EnrollmentCredentialProvider) async -> ConnectionDiagnosticReport {
        let state = DiagnosticState()
        return await check(transport: transport, credentials: credentials, state: state)
    }
    /// The App initializer uses this before starting SwiftUI, for an exact CLI flag.
    /// The transport's own deadlines remain in force; a whole-check deadline adds
    /// a bounded process exit even if a signed endpoint stops making progress.
    public static func runFromExplicitCLI(transport: any FramedBrokerTransport, credentials: any EnrollmentCredentialProvider) -> ConnectionDiagnosticReport {
        let state = DiagnosticState()
        let result = DiagnosticResult()
        let completed = DispatchSemaphore(value: 0)
        Task.detached {
            result.set(await check(transport: transport, credentials: credentials, state: state))
            completed.signal()
        }
        guard completed.wait(timeout: .now() + 30) == .success else {
            return state.report(errorCode: "deadlineExceeded", authenticated: false)
        }
        return result.get() ?? state.report(errorCode: "diagnosticFailed", authenticated: false)
    }
    private static func check(transport: any FramedBrokerTransport, credentials: any EnrollmentCredentialProvider, state: DiagnosticState) async -> ConnectionDiagnosticReport {
        let checkedTransport = DiagnosticTransport(base: transport, state: state)
        let checkedCredential = DiagnosticCredential(base: credentials, state: state)
        let broker = SocketConsentBroker(transport: checkedTransport, credentials: checkedCredential)
        defer { checkedTransport.close() }
        do {
            state.update(stage: "broker")
            try broker.connectFromUserAction()
            state.update(stage: "snapshot")
            _ = try await broker.snapshot()
            state.update(stage: "inventory")
            _ = try await broker.inventory()
            state.update(stage: "permissions")
            _ = try await broker.helperPermissionDoctor()
            state.update(stage: "complete")
            return state.report(errorCode: nil, authenticated: broker.authenticatedPeerDescription != nil)
        } catch {
            return state.report(errorCode: code(error), authenticated: broker.authenticatedPeerDescription != nil)
        }
    }
    private static func code(_ error: Error) -> String {
        switch error as? BrokerTransportError {
        case .unavailable: return "unavailable"
        case .unsafeEndpoint: return "unsafeEndpoint"
        case .untrustedPeer: return "untrustedPeer"
        case .malformedFrame: return "malformedFrame"
        case .malformedResponse: return "malformedResponse"
        case .remoteRejected: return "remoteRejected"
        case .missingEnrollment: return "missingEnrollment"
        case nil: return "diagnosticFailed"
        }
    }
}

private final class DiagnosticState: @unchecked Sendable {
    private let lock = NSLock()
    private var stage = "setup"
    private var verified = false
    private var credential = false
    func update(stage: String? = nil, brokerVerified: Bool? = nil, credentialAvailable: Bool? = nil) {
        lock.lock(); defer { lock.unlock() }
        if let stage { self.stage = stage }
        if let brokerVerified { verified = brokerVerified }
        if let credentialAvailable { credential = credentialAvailable }
    }
    func report(errorCode: String?, authenticated: Bool) -> ConnectionDiagnosticReport {
        lock.lock(); defer { lock.unlock() }
        return ConnectionDiagnosticReport(stage: stage, brokerVerified: verified, credentialAvailable: credential, authenticated: authenticated, errorCode: errorCode)
    }
}
private final class DiagnosticResult: @unchecked Sendable {
    private let lock = NSLock()
    private var result: ConnectionDiagnosticReport?
    func set(_ result: ConnectionDiagnosticReport) { lock.lock(); defer { lock.unlock() }; self.result = result }
    func get() -> ConnectionDiagnosticReport? { lock.lock(); defer { lock.unlock() }; return result }
}
private struct DiagnosticCredential: EnrollmentCredentialProvider {
    let base: any EnrollmentCredentialProvider
    let state: DiagnosticState
    func credential() throws -> Data {
        state.update(stage: "credential")
        let data = try base.credential()
        state.update(stage: "authentication", credentialAvailable: !data.isEmpty)
        return data
    }
}
private final class DiagnosticTransport: FramedBrokerTransport {
    private let base: any FramedBrokerTransport
    private let state: DiagnosticState
    init(base: any FramedBrokerTransport, state: DiagnosticState) { self.base = base; self.state = state }
    func connectAuthenticated() throws {
        try base.connectAuthenticated()
        state.update(brokerVerified: true)
    }
    func exchange(_ request: Data) throws -> Data {
        guard let object = try JSONSerialization.jsonObject(with: request) as? [String: Any],
              let method = object["method"] as? String,
              ["hello", "snapshot", "inventory", "helperPermissionDoctor"].contains(method) else {
            throw BrokerTransportError.malformedFrame
        }
        return try base.exchange(request)
    }
    func close() { base.close() }
}
