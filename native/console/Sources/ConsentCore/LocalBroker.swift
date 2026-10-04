import Foundation
import Darwin
import Security
import LocalAuthentication
import AppKit

public enum BrokerTransportError: Error, LocalizedError {
    case unavailable, unsafeEndpoint, untrustedPeer, malformedFrame, malformedResponse, remoteRejected, missingEnrollment
    public var errorDescription: String? {
        switch self {
        case .unavailable: return "Authenticated local broker is unavailable."
        case .unsafeEndpoint: return "Broker socket ownership, permissions or path are unsafe."
        case .untrustedPeer: return "Broker process does not satisfy the trusted signing policy."
        case .malformedFrame: return "Broker frame is invalid or exceeds 256 KiB."
        case .malformedResponse: return "Broker response is malformed or mismatched."
        case .remoteRejected: return "Broker rejected the request."
        case .missingEnrollment: return "No console enrollment credential is available in Keychain."
        }
    }
}

/// Marks only an error field found in a structurally valid, ID-matched JSON-RPC response.
private struct ValidatedRemoteRejection: Error {}
public protocol EnrollmentCredentialProvider { func credential() throws -> Data }
public struct KeychainEnrollment: EnrollmentCredentialProvider {
    public static let service = "com.viant.mechanize.console.enrollment"
    private let account: String?
    private let read: (String) throws -> Data
    /// enrolledAccount comes only from the running console's signed Info.plist.
    /// An explicit invalid/missing new account never falls back to legacy items.
    public init(trustedBundleID: String, uid: uid_t, enrolledAccount: String? = nil) {
        account = Self.selectedAccount(trustedBundleID: trustedBundleID, uid: uid, enrolledAccount: enrolledAccount)
        read = Self.readCredential
    }
    // Safe fixture seam: tests inject the one-account lookup without Keychain IO.
    init(trustedBundleID: String, uid: uid_t, enrolledAccount: String?, read: @escaping (String) throws -> Data) {
        account = Self.selectedAccount(trustedBundleID: trustedBundleID, uid: uid, enrolledAccount: enrolledAccount)
        self.read = read
    }
    static func selectedAccount(trustedBundleID: String, uid: uid_t, enrolledAccount: String?) -> String? {
        guard trustedBundleID == "com.viant.mechanize.consent" else { return nil }
        let legacy = "\(trustedBundleID):\(uid)"
        guard let enrolledAccount else { return legacy }
        let prefix = legacy + ":"
        guard enrolledAccount.hasPrefix(prefix) else { return nil }
        let suffix = enrolledAccount.dropFirst(prefix.count)
        guard suffix.count == 32, suffix.allSatisfy({ "0123456789abcdef".contains($0) }) else { return nil }
        return enrolledAccount
    }
    /// Only invoke after the user's Connect button click. Never logs or exposes the credential.
    public func credential() throws -> Data {
        guard let account else { throw BrokerTransportError.missingEnrollment }
        return try read(account)
    }
    private static func readCredential(account: String) throws -> Data {
        let context = LAContext(); context.interactionNotAllowed = true
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: Self.service, kSecAttrAccount as String: account, kSecReturnData as String: true, kSecMatchLimit as String: kSecMatchLimitOne, kSecUseAuthenticationContext as String: context]
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess, let data = result as? Data, !data.isEmpty else { throw BrokerTransportError.missingEnrollment }
        return data
    }
}

public protocol BrokerPeerAuthenticator { func authenticate(socket: Int32) throws }
/// The designated requirement comes from trusted, signed native provisioning, never broker data,
/// local writable configuration, command-line arguments, or a peer's self-reported name.
public struct SignedBrokerPeer: BrokerPeerAuthenticator {
    private let requirement: SecRequirement
    private let expectedUID: uid_t
    public init(designatedRequirement: String, expectedUID: uid_t) throws {
        var value: SecRequirement?
        guard SecRequirementCreateWithString(designatedRequirement as CFString, [], &value) == errSecSuccess, let value else { throw BrokerTransportError.untrustedPeer }
        requirement = value; self.expectedUID = expectedUID
    }
    public func authenticate(socket: Int32) throws {
        var uid: uid_t = 0; var gid: gid_t = 0
        guard getpeereid(socket, &uid, &gid) == 0, uid == expectedUID else { throw BrokerTransportError.untrustedPeer }
        // The kernel audit token includes the process generation. A PID-only
        // lookup could resolve a replacement process after the peer exits.
        var token = [UInt32](repeating: 0, count: 8)
        var size = socklen_t(token.count * MemoryLayout<UInt32>.size)
        let status = token.withUnsafeMutableBytes { bytes in
            getsockopt(socket, SOL_LOCAL, LOCAL_PEERTOKEN, bytes.baseAddress, &size)
        }
        guard status == 0, size == 32 else { throw BrokerTransportError.untrustedPeer }
        let audit = token.withUnsafeBytes { Data($0) }
        var code: SecCode?
        let attributes = [kSecGuestAttributeAudit as String: audit] as CFDictionary
        guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &code) == errSecSuccess, let code, SecCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate), requirement) == errSecSuccess else { throw BrokerTransportError.untrustedPeer }
    }
}
public protocol FramedBrokerTransport {
    func connectAuthenticated() throws
    func exchange(_ request: Data) throws -> Data
    func close()
}
public enum BrokerFrame {
    public static let maximumLength = 256 * 1024
    public static func encode(_ body: Data) throws -> Data {
        guard !body.isEmpty, body.count <= maximumLength else { throw BrokerTransportError.malformedFrame }
        var size = UInt32(body.count).bigEndian
        var output = withUnsafeBytes(of: &size) { Data($0) }; output.append(body); return output
    }
    public static func decode(_ frame: Data) throws -> Data {
        guard frame.count >= 4 else { throw BrokerTransportError.malformedFrame }
        let size = frame.prefix(4).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        guard size > 0, size <= maximumLength, frame.count == Int(size) + 4 else { throw BrokerTransportError.malformedFrame }
        return frame.dropFirst(4)
    }
}
public final class UnixBrokerTransport: FramedBrokerTransport {
    private let authenticator: any BrokerPeerAuthenticator
    private var fd: Int32 = -1
    private let endpoint: String
    public init(authenticator: any BrokerPeerAuthenticator) {
        self.authenticator = authenticator
        endpoint = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/Mechanize/runtime/consent.sock").path
    }
    deinit { close() }
    public func connectAuthenticated() throws {
        close()
        // Validate the home and every component below it, avoiding symlink redirects.
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        var path = home
        for component in ["", "Library", "Application Support", "Mechanize", "runtime", "consent.sock"] {
            if !component.isEmpty { path += "/" + component }
            var info = stat()
            guard lstat(path, &info) == 0, (info.st_mode & S_IFMT) != S_IFLNK, info.st_uid == getuid(), (info.st_mode & 0o022) == 0 else { throw BrokerTransportError.unsafeEndpoint }
            if component == "consent.sock" { guard (info.st_mode & S_IFMT) == S_IFSOCK, (info.st_mode & 0o077) == 0 else { throw BrokerTransportError.unsafeEndpoint } }
            else { guard (info.st_mode & S_IFMT) == S_IFDIR else { throw BrokerTransportError.unsafeEndpoint } }
            if component == "runtime" { guard (info.st_mode & 0o077) == 0 else { throw BrokerTransportError.unsafeEndpoint } }
        }
        fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw BrokerTransportError.unavailable }
        do {
            var timeout = timeval(tv_sec: 5, tv_usec: 0)
            _ = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
            _ = setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
            var noSignal: Int32 = 1; _ = setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &noSignal, socklen_t(MemoryLayout<Int32>.size))
            var address = sockaddr_un(); address.sun_family = sa_family_t(AF_UNIX)
            let bytes = Array(endpoint.utf8CString)
            guard bytes.count <= MemoryLayout.size(ofValue: address.sun_path) else { throw BrokerTransportError.unsafeEndpoint }
            withUnsafeMutableBytes(of: &address.sun_path) { target in for (i, b) in bytes.enumerated() { target[i] = UInt8(bitPattern: b) } }
            address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
            let result = withUnsafePointer(to: &address) { p in p.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) } }
            guard result == 0 else { throw BrokerTransportError.unavailable }
            try authenticator.authenticate(socket: fd)
        } catch { close(); throw error }
    }
    public func exchange(_ request: Data) throws -> Data {
        guard fd >= 0 else { throw BrokerTransportError.unavailable }
        do {
            let frame = try BrokerFrame.encode(request)
            try frame.withUnsafeBytes { raw in
                var offset = 0
                while offset < frame.count { let n = Darwin.write(fd, raw.baseAddress!.advanced(by: offset), frame.count - offset); if n < 0 && errno == EINTR { continue }; guard n > 0 else { throw BrokerTransportError.unavailable }; offset += n }
            }
            let header = try readExactly(4)
            let size = header.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
            guard size > 0, size <= BrokerFrame.maximumLength else { throw BrokerTransportError.malformedFrame }
            return try readExactly(Int(size))
        } catch { close(); throw error }
    }
    private func readExactly(_ count: Int) throws -> Data {
        var data = Data(count: count)
        try data.withUnsafeMutableBytes { raw in
            var offset = 0
            while offset < count { let n = Darwin.read(fd, raw.baseAddress!.advanced(by: offset), count - offset); if n < 0 && errno == EINTR { continue }; guard n > 0 else { throw BrokerTransportError.malformedFrame }; offset += n }
        }
        return data
    }
    public func close() { if fd >= 0 { Darwin.close(fd); fd = -1 } }
}

/// Serialized RPC client. Caller supplies a transport that authenticates the local peer before
/// any credential is written. Production uses UnixBrokerTransport + SignedBrokerPeer.
public final class SocketConsentBroker: ConsentHostAdapter {
    private let transport: any FramedBrokerTransport
    private let credentials: any EnrollmentCredentialProvider
    private let lock = NSLock()
    private var sessionID: String?
    private var peer: String?
    public var authenticatedPeerDescription: String? { lock.lock(); defer { lock.unlock() }; return peer }
    public init(transport: any FramedBrokerTransport, credentials: any EnrollmentCredentialProvider) { self.transport = transport; self.credentials = credentials }
    deinit { transport.close() }
    /// Must be invoked only from explicit enrollment/connect UI. Missing policy/credential fails closed.
    public func connectFromUserAction() throws {
        lock.lock(); defer { lock.unlock() }
        sessionID = nil; peer = nil
        do {
            try transport.connectAuthenticated()
            let data = try credentials.credential()
            guard let credential = String(data: data, encoding: .utf8), !credential.isEmpty else { throw BrokerTransportError.missingEnrollment }
            let result = try rpc("hello", params: ["protocolVersion": 1, "credential": credential, "clientBundleID": "com.viant.mechanize.consent"])
            struct Hello: Decodable { let protocolVersion: Int; let sessionID: String; let brokerName: String }
            let hello = try ConsentWire.decoder().decode(Hello.self, from: result)
            guard hello.protocolVersion == 1, !hello.sessionID.isEmpty, !hello.brokerName.isEmpty else { throw BrokerTransportError.malformedResponse }
            sessionID = hello.sessionID; peer = hello.brokerName
        } catch { transport.close(); throw sanitize(error) }
    }
    private func sanitize(_ error: Error) -> BrokerTransportError {
        if error is ValidatedRemoteRejection { return .remoteRejected }
        return error as? BrokerTransportError ?? .malformedResponse
    }
    private func rpc(_ method: String, params: [String: Any]) throws -> Data {
        let id = UUID().uuidString
        let body = try JSONSerialization.data(withJSONObject: ["jsonrpc": "2.0", "id": id, "method": method, "params": params])
        let reply = try transport.exchange(body)
        guard reply.count <= BrokerFrame.maximumLength,
              let object = try JSONSerialization.jsonObject(with: reply) as? [String: Any],
              object["jsonrpc"] as? String == "2.0", object["id"] as? String == id,
              (object["result"] != nil) != (object["error"] != nil) else { throw BrokerTransportError.malformedResponse }
        if object["error"] != nil { throw ValidatedRemoteRejection() }
        return try JSONSerialization.data(withJSONObject: object["result"]!, options: [.fragmentsAllowed])
    }
    private func call<T: Decodable>(_ method: String, params: [String: Any] = [:], as: T.Type) throws -> T {
        lock.lock(); defer { lock.unlock() }
        guard let sessionID, peer != nil else { throw ConsentError.disconnected }
        do { var p = params; p["sessionID"] = sessionID; return try ConsentWire.decoder().decode(T.self, from: rpc(method, params: p)) }
        catch is ValidatedRemoteRejection { throw BrokerTransportError.remoteRejected }
        catch { self.sessionID = nil; peer = nil; transport.close(); throw sanitize(error) }
    }
    public func snapshot() async throws -> ConsentSnapshot { try call("snapshot", as: ConsentSnapshot.self) }
    public func decide(requestID: String, decision: ConsentDecision) async throws -> ConsentGrant? { try call("decide", params: ["requestID": requestID, "decision": decision.rawValue], as: Optional<ConsentGrant>.self) }
    public func revoke(grantID: String) async throws -> RevokeStatus {
        struct Reply: Decodable { let status: RevokeStatus }
        return try call("revoke", params: ["grantID": grantID], as: Reply.self).status
    }
    public func inventory() async throws -> [InventoryTarget] { try call("inventory", as: [InventoryTarget].self) }
    public func helperPermissionDoctor() async throws -> [HelperPermissionStatus] { try call("helperPermissionDoctor", as: [HelperPermissionStatus].self) }
    public func applicationAccess() async throws -> ApplicationAccessSnapshot { try call("applicationAccess.get", as: ApplicationAccessSnapshot.self) }
    public func updateApplicationAccess(expectedRevision: Int, policy: ApplicationAccessPolicy) async throws -> ApplicationAccessSnapshot {
        let encodedPolicy = try ConsentWire.encoder().encode(policy)
        guard let policyObject = try JSONSerialization.jsonObject(with: encodedPolicy) as? [String: Any] else { throw BrokerTransportError.malformedResponse }
        return try call("applicationAccess.set", params: ["expectedRevision": expectedRevision, "policy": policyObject], as: ApplicationAccessSnapshot.self)
    }
    public func openSystemPermissionSettings(_ permission: HelperPermission) async throws {
        guard authenticatedPeerDescription != nil else { throw ConsentError.disconnected }
        let pane: String
        switch permission {
        case .accessibility: pane = "Privacy_Accessibility"
        case .screenRecording: pane = "Privacy_ScreenCapture"
        case .inputMonitoring: pane = "Privacy_ListenEvent"
        }
        guard let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?" + pane) else { throw BrokerTransportError.unavailable }
        let opened = await MainActor.run { NSWorkspace.shared.open(url) }
        guard opened else { throw BrokerTransportError.unavailable }
    }
}
