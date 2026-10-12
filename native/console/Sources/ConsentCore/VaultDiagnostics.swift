import Foundation

/// Fixed stages and booleans only. Readiness does not establish entry/window
/// protection, and a false result does not establish that the key is missing.
public struct VaultDiagnosticReport: Codable, Sendable {
    public let stage: String
    public let authenticated: Bool
    public let keyReady: Bool?
    public let inventoryReadable: Bool
    public let errorCode: String?
    public var succeeded: Bool { stage == "complete" && authenticated && keyReady == true && inventoryReadable && errorCode == nil }
    public init(stage: String, authenticated: Bool = false, keyReady: Bool? = nil, inventoryReadable: Bool = false, errorCode: String? = nil) {
        self.stage = stage; self.authenticated = authenticated; self.keyReady = keyReady
        self.inventoryReadable = inventoryReadable; self.errorCode = errorCode
    }
    public func json() -> Data {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        return (try? encoder.encode(self)) ?? Data("{\"stage\":\"output\",\"errorCode\":\"encodingFailed\"}".utf8)
    }
}

/// Explicit, read-only native CLI diagnostic. Never calls setup, entry begin,
/// recovery, CRUD, clipboard, AX, screenshots or generic console inventory.
/// Existing broker responses cannot distinguish missing keys from ACL/readback
/// failures, so the report deliberately labels all false readiness as keyNotReady.
public enum VaultDiagnostics {
    public static func run(transport: any FramedBrokerTransport, credentials: any EnrollmentCredentialProvider) -> VaultDiagnosticReport {
        check(transport: transport, credentials: credentials, state: VaultDiagnosticState())
    }
    public static func runFromExplicitCLI(transport: any FramedBrokerTransport, credentials: any EnrollmentCredentialProvider) -> VaultDiagnosticReport {
        let state = VaultDiagnosticState()
        let completed = DispatchSemaphore(value: 0)
        Task.detached {
            state.finish(check(transport: transport, credentials: credentials, state: state))
            completed.signal()
        }
        guard completed.wait(timeout: .now() + 20) == .success else { return state.current(errorCode: "deadlineExceeded") }
        return state.result() ?? state.current(errorCode: "diagnosticUnavailable")
    }
    private static func check(transport: any FramedBrokerTransport, credentials: any EnrollmentCredentialProvider, state: VaultDiagnosticState) -> VaultDiagnosticReport {
        let client = SocketConsentBroker(transport: transport, credentials: credentials)
        defer { transport.close() }
        state.update(stage: "connection")
        do { try client.connectFromUserAction() }
        catch { return state.current(errorCode: connectionCode(error)) }
        state.update(stage: "keyReadiness", authenticated: true)
        let ready: Bool
        do { ready = try client.nativeVaultKeyReady() }
        catch { return state.current(errorCode: "keyStatusUnavailable") }
        state.update(keyReady: ready)
        guard ready else { return state.current(errorCode: "keyNotReady") }
        state.update(stage: "inventory")
        do { _ = try client.nativeVaultInventory() }
        catch { return state.current(errorCode: "inventoryUnavailable") }
        state.update(stage: "complete", inventoryReadable: true)
        return state.current(errorCode: nil)
    }
    private static func connectionCode(_ error: Error) -> String {
        switch error as? BrokerTransportError {
        case .unavailable: return "brokerUnavailable"
        case .unsafeEndpoint: return "unsafeEndpoint"
        case .untrustedPeer: return "untrustedPeer"
        case .missingEnrollment: return "missingEnrollment"
        case .remoteRejected: return "authenticationRejected"
        case .malformedFrame, .malformedResponse: return "invalidBrokerResponse"
        case nil: return "connectionUnavailable"
        }
    }
}
private final class VaultDiagnosticState: @unchecked Sendable {
    private let lock = NSLock()
    private var stage = "setup"
    private var authenticated = false
    private var keyReady: Bool?
    private var inventoryReadable = false
    private var finished: VaultDiagnosticReport?
    func update(stage: String? = nil, authenticated: Bool? = nil, keyReady: Bool? = nil, inventoryReadable: Bool? = nil) {
        lock.lock(); defer { lock.unlock() }
        if let stage { self.stage = stage }; if let authenticated { self.authenticated = authenticated }
        if let keyReady { self.keyReady = keyReady }; if let inventoryReadable { self.inventoryReadable = inventoryReadable }
    }
    func current(errorCode: String?) -> VaultDiagnosticReport {
        lock.lock(); defer { lock.unlock() }
        return VaultDiagnosticReport(stage: stage, authenticated: authenticated, keyReady: keyReady, inventoryReadable: inventoryReadable, errorCode: errorCode)
    }
    func finish(_ report: VaultDiagnosticReport) { lock.lock(); defer { lock.unlock() }; finished = report }
    func result() -> VaultDiagnosticReport? { lock.lock(); defer { lock.unlock() }; return finished }
}
