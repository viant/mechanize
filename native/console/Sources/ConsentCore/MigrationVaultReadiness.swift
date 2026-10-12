import Foundation
import Darwin
import Security

/// Exact peer binding for the upgrade's owned launchd broker instance. The
/// requirement comes from signed bundle metadata; PID/birth are public bounded
/// launch metadata, never an approval or a source of NativeHuman authority.
final class MigrationExactBrokerPeer: BrokerPeerAuthenticator {
    private let signed: any BrokerPeerAuthenticator
    private let pid: pid_t
    private let start: String
    private let uid: uid_t
    private let inspect: (pid_t) throws -> (uid_t, String)
    private let socketPID: (Int32) throws -> pid_t
    private let lock = NSLock()
    private var verifiedSocket: Int32?
    init(requirement: String, pid: pid_t, start: String, uid: uid_t) throws {
        guard pid > 0, Self.validStart(start), MigrationAuthorizationRecord.requirement(requirement, role: "broker") else { throw MigrationConsoleError.unavailable }
        signed = try SignedBrokerPeer(designatedRequirement: requirement, expectedUID: uid)
        self.pid = pid; self.start = start; self.uid = uid
        inspect = Self.process; socketPID = Self.peerPID
    }
    init(signed: any BrokerPeerAuthenticator, pid: pid_t, start: String, uid: uid_t,
         inspect: @escaping (pid_t) throws -> (uid_t, String), socketPID: @escaping (Int32) throws -> pid_t) {
        self.signed = signed; self.pid = pid; self.start = start; self.uid = uid; self.inspect = inspect; self.socketPID = socketPID
    }
    static func validStart(_ start: String) -> Bool {
        let parts = start.split(separator: ":", omittingEmptySubsequences: false)
        return parts.count == 2 && parts.allSatisfy { !$0.isEmpty && $0.count <= 20 && $0.utf8.allSatisfy { (48...57).contains($0) } }
    }
    private static func process(_ pid: pid_t) throws -> (uid_t, String) {
        var info = proc_bsdinfo()
        guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, Int32(MemoryLayout<proc_bsdinfo>.size)) == MemoryLayout<proc_bsdinfo>.size,
              info.pbi_pid == UInt32(pid), info.pbi_status != 5 else { throw MigrationConsoleError.unavailable }
        return (info.pbi_uid, "\(info.pbi_start_tvsec):\(info.pbi_start_tvusec)")
    }
    private static func peerPID(_ socket: Int32) throws -> pid_t {
        var pid: pid_t = 0; var size = socklen_t(MemoryLayout<pid_t>.size)
        guard getsockopt(socket, SOL_LOCAL, LOCAL_PEERPID, &pid, &size) == 0, size == MemoryLayout<pid_t>.size, pid > 0 else { throw MigrationConsoleError.unavailable }
        return pid
    }
    func authenticate(socket: Int32) throws {
        let before = try inspect(pid)
        guard before.0 == uid, before.1 == start, try socketPID(socket) == pid else { throw MigrationConsoleError.unavailable }
        try signed.authenticate(socket: socket) // includes kernel audit generation
        let after = try inspect(pid)
        guard after.0 == uid, after.1 == start, try socketPID(socket) == pid else { throw MigrationConsoleError.unavailable }
        lock.lock(); verifiedSocket = socket; lock.unlock()
    }
    func revalidateConnectedPeer() throws {
        lock.lock(); let socket = verifiedSocket; lock.unlock()
        guard let socket else { throw MigrationConsoleError.unavailable }
        try authenticate(socket: socket)
    }
}

final class MigrationVerifiedCloseTransport: FramedBrokerTransport {
    private let base: any FramedBrokerTransport
    private let peer: MigrationExactBrokerPeer
    private let lock = NSLock()
    private var closed = false
    private var confirmed = false
    init(base: any FramedBrokerTransport, peer: MigrationExactBrokerPeer) { self.base = base; self.peer = peer }
    func connectAuthenticated() throws { try base.connectAuthenticated() }
    func exchange(_ request: Data) throws -> Data { try base.exchange(request) }
    func close() {
        lock.lock(); defer { lock.unlock() }
        guard !closed else { return }; closed = true
        do { try peer.revalidateConnectedPeer(); confirmed = true } catch { confirmed = false }
        base.close()
    }
    var verifiedAfterResponse: Bool { lock.lock(); defer { lock.unlock() }; return closed && confirmed }
}

/// A diagnostic-only CLI branch in the existing app, with no new window/prompt.
/// Private credentials remain in KeychainEnrollment and the signed Unix channel.
public enum MigrationVaultReadiness {
    public static func runCLI(arguments: [String], bundle: Bundle = .main) -> VaultDiagnosticReport {
        guard arguments.count == 5, arguments[0] == "--check-vault", arguments[1] == "--broker-pid", arguments[3] == "--broker-start",
              let pid = Int32(arguments[2]), pid > 0, MigrationExactBrokerPeer.validStart(arguments[4]),
              bundle.bundleIdentifier == "com.viant.mechanize.consent",
              let requirement = bundle.object(forInfoDictionaryKey: "MechanizeBrokerRequirement") as? String,
              let account = bundle.object(forInfoDictionaryKey: "MechanizeEnrollmentAccount") as? String,
              SecKeychainSetUserInteractionAllowed(false) == errSecSuccess else {
            return VaultDiagnosticReport(stage: "setup", errorCode: "invalidArguments")
        }
        do {
            let peer = try MigrationExactBrokerPeer(requirement: requirement, pid: pid, start: arguments[4], uid: getuid())
            let transport = MigrationVerifiedCloseTransport(base: UnixBrokerTransport(authenticator: peer), peer: peer)
            let credential = KeychainEnrollment(trustedBundleID: "com.viant.mechanize.consent", uid: getuid(), enrolledAccount: account)
            let report = VaultDiagnostics.runFromExplicitCLI(transport: transport, credentials: credential)
            guard !report.succeeded || transport.verifiedAfterResponse else { return VaultDiagnosticReport(stage: "connection", errorCode: "untrustedPeer") }
            return report
        } catch { return VaultDiagnosticReport(stage: "connection", errorCode: "untrustedPeer") }
    }
}
