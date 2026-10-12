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
    /// Used only by the provisioned native connection handshake. Keychain reads
    /// are noninteractive; this never logs or exposes the credential.
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
/// Dedicated native credential body after an ID-matched admission response.
/// It is not a JSON request or an agent-accessible transport operation.
public protocol NativeVaultBinaryTransport: FramedBrokerTransport {
    func sendNativeVaultFrame(username: Data, password: Data) throws -> Data
}
public protocol NativeVaultRecordBinaryTransport: FramedBrokerTransport {
    func sendNativeRecordFrame(_ frame: VaultRecordFrame) throws -> Data
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
public final class UnixBrokerTransport: NativeVaultBinaryTransport, NativeVaultRecordBinaryTransport {
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
        try Self.validateEndpoint(home: home)
        fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw BrokerTransportError.unavailable }
        do {
            try connectSocket()
        } catch {
            close()
            throw error
        }
    }
    static func validateEndpoint(home: String) throws {
        var path = home
        for component in ["", "Library", "Application Support", "Mechanize", "runtime", "consent.sock"] {
            if !component.isEmpty { path += "/" + component }
            var info = stat()
            if lstat(path, &info) != 0 {
                // A stopped broker has no endpoint. Missing parents or unsafe
                // entries still fail the path-custody checks independently.
                if component == "consent.sock", errno == ENOENT { throw BrokerTransportError.unavailable }
                throw BrokerTransportError.unsafeEndpoint
            }
            guard (info.st_mode & S_IFMT) != S_IFLNK, info.st_uid == getuid(), (info.st_mode & 0o022) == 0 else { throw BrokerTransportError.unsafeEndpoint }
            if component == "consent.sock" { guard (info.st_mode & S_IFMT) == S_IFSOCK, (info.st_mode & 0o077) == 0 else { throw BrokerTransportError.unsafeEndpoint } }
            else { guard (info.st_mode & S_IFMT) == S_IFDIR else { throw BrokerTransportError.unsafeEndpoint } }
            if component == "runtime" { guard (info.st_mode & 0o077) == 0 else { throw BrokerTransportError.unsafeEndpoint } }
        }
    }
    private func connectSocket() throws {
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
    public func sendNativeVaultFrame(username: Data, password: Data) throws -> Data {
        guard fd >= 0 else { throw BrokerTransportError.unavailable }
        defer { close() }
        do {
            try VaultCredentialFrame.withBytes(username: username, password: password) { frame in
                try frame.withUnsafeBytes { raw in
                    var offset = 0
                    while offset < frame.count {
                        let count = Darwin.write(fd, raw.baseAddress!.advanced(by: offset), frame.count - offset)
                        if count < 0 && errno == EINTR { continue }
                        guard count > 0 else { throw BrokerTransportError.unavailable }
                        offset += count
                    }
                }
            }
            guard shutdown(fd, SHUT_WR) == 0 else { throw BrokerTransportError.unavailable }
            let header = try readExactly(4)
            let count = header.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
            guard count > 0, count <= BrokerFrame.maximumLength else { throw BrokerTransportError.malformedResponse }
            return try readExactly(Int(count))
        } catch { throw BrokerTransportError.unavailable }
    }
    public func sendNativeRecordFrame(_ frame: VaultRecordFrame) throws -> Data {
        defer { frame.destroy(); close() }
        guard fd >= 0 else { throw BrokerTransportError.unavailable }
        do {
            try frame.writeOnce { raw in
                var offset = 0
                while offset < raw.count {
                    let count = Darwin.write(fd, raw.baseAddress!.advanced(by: offset), raw.count - offset)
                    if count < 0 && errno == EINTR { continue }
                    guard count > 0 else { throw BrokerTransportError.unavailable }
                    offset += count
                }
            }
            guard shutdown(fd, SHUT_WR) == 0 else { throw BrokerTransportError.unavailable }
            let header = try readExactly(4)
            let count = header.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
            guard count > 0, count <= BrokerFrame.maximumLength else { throw BrokerTransportError.malformedResponse }
            return try readExactly(Int(count))
        } catch { throw BrokerTransportError.unavailable }
    }
    public func close() { if fd >= 0 { Darwin.close(fd); fd = -1 } }
}

/// Serialized RPC client. Caller supplies a transport that authenticates the local peer before
/// any credential is written. Production uses UnixBrokerTransport + SignedBrokerPeer.
// All transport/session operations are serialized by lock. This permits native
// UI callers to perform RPC off the main thread so the broker's AX metadata
// checks can be answered by the console's main run loop.
public final class SocketConsentBroker: ConsentHostAdapter, @unchecked Sendable {
    private let transport: any FramedBrokerTransport
    private let credentials: any EnrollmentCredentialProvider
    private let lock = NSLock()
    private var sessionID: String?
    // SwiftUI reads connection status synchronously on its main actor. It must
    // never wait for the transport lock, whose RPC can itself require UI/AX work.
    private let peerStateLock = NSLock()
    private var displayedPeer: String?
    private var peer: String? {
        didSet { peerStateLock.lock(); displayedPeer = peer; peerStateLock.unlock() }
    }
    private var connectionRequested = false
    public var authenticatedPeerDescription: String? {
        peerStateLock.lock(); defer { peerStateLock.unlock() }
        return displayedPeer
    }
    public init(transport: any FramedBrokerTransport, credentials: any EnrollmentCredentialProvider) { self.transport = transport; self.credentials = credentials }
    deinit { transport.close() }
    /// Must be invoked only from explicit enrollment/connect UI. Missing policy/credential fails closed.
    public func connectFromUserAction() throws {
        lock.lock(); defer { lock.unlock() }
        connectionRequested = true
        try connectLocked()
    }
    /// Reestablish only a previously requested native connection using the same
    /// signed peer policy and saved enrollment. Never retries an application RPC.
    @discardableResult public func reconnectPreviouslyRequested() throws -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard connectionRequested else { return false }
        if sessionID != nil && peer != nil { return true }
        try connectLocked()
        return true
    }
    private func connectLocked() throws {
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
    public func pendingCredentialRequests() async throws -> [NativeCredentialRequest] {
        lock.lock(); defer { lock.unlock() }
        guard let sessionID, peer != nil else { throw ConsentError.disconnected }
        do { return try NativeCredentialRequest.decode(rpc("credential.pending", params: ["sessionID": sessionID])) }
        catch is ValidatedRemoteRejection { throw BrokerTransportError.remoteRejected }
        catch { self.sessionID = nil; peer = nil; transport.close(); throw sanitize(error) }
    }
    public func credentialRecordReferences() async throws -> [VaultRecordMetadata] { try nativeRecordInventory() }
    public func bindCredentialRequest(id: String, record: VaultRecordMetadata) async throws {
        try await nativeCredentialDecision("credential.bind", id: id, record: record)
    }
    public func cancelCredentialRequest(id: String) async throws {
        try await nativeCredentialDecision("credential.cancel", id: id, record: nil)
    }
    private func nativeCredentialDecision(_ method: String, id: String, record: VaultRecordMetadata?) async throws {
        guard nativeVaultEntryID(id), record == nil || record!.isValid else { throw BrokerTransportError.malformedResponse }
        lock.lock(); defer { lock.unlock() }
        guard let sessionID, peer != nil else { throw ConsentError.disconnected }
        var params: [String: Any] = ["sessionID": sessionID, "id": id]
        if let record { params["recordId"] = record.id; params["revision"] = record.revision }
        do {
            let body = try rpc(method, params: params)
            guard let object = try JSONSerialization.jsonObject(with: body) as? [String: Any],
                  Set(object.keys) == ["accepted"], let flag = object["accepted"] as? NSNumber,
                  CFGetTypeID(flag) == CFBooleanGetTypeID(), flag.boolValue else { throw BrokerTransportError.malformedResponse }
        } catch is ValidatedRemoteRejection { throw BrokerTransportError.remoteRejected }
        catch { self.sessionID = nil; peer = nil; transport.close(); throw sanitize(error) }
    }
    public func decide(requestID: String, decision: ConsentDecision) async throws -> ConsentGrant? { try call("decide", params: ["requestID": requestID, "decision": decision.rawValue], as: Optional<ConsentGrant>.self) }
    public func revoke(grantID: String) async throws -> RevokeStatus {
        struct Reply: Decodable { let status: RevokeStatus }
        return try call("revoke", params: ["grantID": grantID], as: Reply.self).status
    }
    // Private native-console metadata route. The fixed method cannot dispatch
    // browser input or accept caller-provided directory/storage evidence.
    func migrationBrowserSetupMetadata(profileChannel: String, browserInstance: String) throws -> Data {
        lock.lock(); defer { lock.unlock() }
        guard let sessionID, peer != nil, !profileChannel.isEmpty, profileChannel.utf8.count <= 128,
              !browserInstance.isEmpty, browserInstance.utf8.count <= 128 else { throw ConsentError.disconnected }
        do { return try rpc("browserSetupMetadata", params: ["sessionID": sessionID, "profileChannel": profileChannel, "browserInstance": browserInstance]) }
        catch { self.sessionID = nil; peer = nil; transport.close(); throw sanitize(error) }
    }
    public func manageBrowserControllers(profileChannel: String, browserInstance: String, action: BrowserControllerAction, policy: BrowserControllerPolicy? = nil, controllerSessionID: String? = nil) async throws -> BrowserControllerState {
        guard !profileChannel.isEmpty, profileChannel.utf8.count <= 128, !browserInstance.isEmpty, browserInstance.utf8.count <= 128 else { throw BrokerTransportError.malformedResponse }
        switch action {
        case .status: guard policy == nil, controllerSessionID == nil else { throw BrokerTransportError.malformedResponse }
        case .configure: guard let policy, policy.isValid, controllerSessionID == nil else { throw BrokerTransportError.malformedResponse }
        case .approve, .revoke: guard policy == nil, let controllerSessionID, !controllerSessionID.isEmpty, controllerSessionID.utf8.count <= 128 else { throw BrokerTransportError.malformedResponse }
        }
        let value = try await Task.detached { [self] in
            var params: [String: Any] = ["profileChannel": profileChannel, "browserInstance": browserInstance, "action": action.rawValue]
            if let policy { params["policy"] = ["enabled": policy.enabled, "origins": policy.origins] }
            if let controllerSessionID { params["controllerSessionID"] = controllerSessionID }
            return try self.call("browserControllers", params: params, as: BrowserControllerState.self)
        }.value
        guard value.isValid else { throw BrokerTransportError.malformedResponse }
        return value
    }
    public func browserStatus() async throws -> BrowserConnectionStatus { try call("browserStatus", as: BrowserConnectionStatus.self) }
    public func runtimeSettings() async throws -> RuntimeSettingsSnapshot {
        let value = try await Task.detached { try self.call("settings.get", as: RuntimeSettingsSnapshot.self) }.value
        guard value.isValid else { throw BrokerTransportError.malformedResponse }; return value
    }
    public func updateRuntimePort(expectedRevision: Int, port: Int) async throws -> RuntimeSettingsSnapshot {
        guard expectedRevision >= 0, (1...65535).contains(port) else { throw BrokerTransportError.malformedResponse }
        let value = try await Task.detached { try self.call("settings.port.set", params: ["expectedRevision": expectedRevision, "port": port], as: RuntimeSettingsSnapshot.self) }.value
        guard value.isValid else { throw BrokerTransportError.malformedResponse }; return value
    }

    public func nativeVaultKeyReady() throws -> Bool {
        try nativeVaultKeyFlag("vault.status")
    }
    /// An uncertain reply requires readiness inspection before another setup
    /// attempt. No key is supplied by or returned to this client.
    public func setupNativeVaultKey() throws {
        guard try nativeVaultKeyFlag("vault.setup") else { throw VaultNativeChannelError.keySetupUnknown }
    }
    private func nativeVaultKeyFlag(_ method: String) throws -> Bool {
        do {
            let result = try nativeVaultLifecycle(method, params: [:])
            guard Set(result.keys) == ["keyReady"], let flag = result["keyReady"] as? NSNumber,
                  CFGetTypeID(flag) == CFBooleanGetTypeID() else { throw BrokerTransportError.malformedResponse }
            return flag.boolValue
        } catch {
            closeNativeVaultConnection(); throw VaultNativeChannelError.keySetupUnknown
        }
    }

    /// Keep this authenticated connection alive for the whole entry window.
    /// Begin permits an EMPTY marked window. Fields require a subsequent Confirm
    /// after the broker independently sees that exact window.
    public func beginNativeVaultEntry(request: VaultEntryRequest) throws -> String {
        guard request.isValid else { throw VaultInputError.expired }
        let result = try nativeVaultLifecycle("vault.entry.begin", params: ["origin": request.origin, "accountAlias": request.accountAlias])
        guard Set(result.keys) == ["entryID"], let entryID = result["entryID"] as? String,
              nativeVaultEntryID(entryID) else {
            closeNativeVaultConnection(); throw VaultNativeChannelError.protectionUnknown
        }
        return entryID
    }
    public func nativeVaultInventory() throws -> [VaultInventoryEntry] {
        do { return try parseNativeVaultInventory(nativeVaultLifecycle("vault.inventory", params: [:])) }
        catch { closeNativeVaultConnection(); throw BrokerTransportError.malformedResponse }
    }
    public func bindNativeVaultEntry(entryID: String, origin: String) throws {
        guard nativeVaultEntryID(entryID), VaultOrigin.canonical(origin) == origin else { throw VaultInputError.expired }
        let result = try nativeVaultLifecycle("vault.entry.bind", params: ["entryID": entryID, "origin": origin])
        guard Set(result.keys) == ["entryBound"], let flag = result["entryBound"] as? NSNumber,
              CFGetTypeID(flag) == CFBooleanGetTypeID(), flag.boolValue else {
            closeNativeVaultConnection(); throw VaultNativeChannelError.protectionUnknown
        }
    }
    /// A dedicated transaction connection; delete has no credential frame.
    /// Metadata-only explicit local import. Credential bytes never enter Swift.
    public func importNativeVaultCredential(request: VaultEntryRequest, entryID: String, resourceURL: String, revision: String, inspect: Bool) throws -> VaultRecordMetadata {
        guard request.isValid, nativeVaultEntryID(entryID), nativeVaultEntryID(revision), nativeVaultReference(resourceURL) else { throw VaultInputError.expired }
        defer { closeNativeVaultConnection() }
        do {
            let result = try nativeVaultLifecycle(inspect ? "vault.record.inspectImport" : "vault.record.importCredential", params: ["entryID":entryID,"origin":request.origin,"accountAlias":request.accountAlias,"resourceURL":resourceURL,"revision":revision])
            return try parseNativeRecordMetadata(JSONSerialization.data(withJSONObject: result))
        } catch { throw VaultNativeChannelError.outcomeUnknown }
    }
    public func deleteNativeVault(request: VaultEntryRequest, entryID: String, revision: String) throws {
        guard request.isValid, nativeVaultEntryID(entryID), nativeVaultEntryID(revision) else { throw VaultInputError.expired }
        defer { closeNativeVaultConnection() }
        do {
            let result = try nativeVaultLifecycle("vault.delete", params: ["entryID": entryID, "origin": request.origin, "accountAlias": request.accountAlias, "revision": revision])
            guard Set(result.keys) == ["deleted"], let flag = result["deleted"] as? NSNumber,
                  CFGetTypeID(flag) == CFBooleanGetTypeID(), flag.boolValue else { throw BrokerTransportError.malformedResponse }
        } catch { throw VaultNativeChannelError.outcomeUnknown }
    }
    public func closeNativeVaultEntry(entryID: String) throws {
        guard nativeVaultEntryID(entryID) else { throw BrokerTransportError.malformedResponse }
        try nativeVaultEntryClosed("vault.entry.close", params: ["entryID": entryID])
    }
    public func confirmNativeVaultEntry(entryID: String) throws {
        guard nativeVaultEntryID(entryID) else { throw BrokerTransportError.malformedResponse }
        let result = try nativeVaultLifecycle("vault.entry.confirm", params: ["entryID": entryID])
        guard Set(result.keys) == ["entryProtected"], let flag = result["entryProtected"] as? NSNumber,
              CFGetTypeID(flag) == CFBooleanGetTypeID(), flag.boolValue else {
            closeNativeVaultConnection(); throw VaultNativeChannelError.protectionUnknown
        }
    }
    /// Recover a lost Begin response only after local fields have been cleared
    /// and the window closed. The broker independently checks native cleanup.
    public func recoverNativeVaultEntry() throws {
        try nativeVaultEntryClosed("vault.entry.recover", params: [:])
    }
    private func nativeVaultEntryClosed(_ method: String, params: [String: Any]) throws {
        let result = try nativeVaultLifecycle(method, params: params)
        guard Set(result.keys) == ["entryClosed"], let flag = result["entryClosed"] as? NSNumber,
              CFGetTypeID(flag) == CFBooleanGetTypeID(), flag.boolValue else {
            closeNativeVaultConnection(); throw VaultNativeChannelError.protectionUnknown
        }
    }
    private func nativeVaultLifecycle(_ method: String, params: [String: Any]) throws -> [String: Any] {
        lock.lock(); defer { lock.unlock() }
        guard let sessionID, peer != nil else { throw ConsentError.disconnected }
        let id = UUID().uuidString
        var metadata = params; metadata["sessionID"] = sessionID
        let request = try JSONSerialization.data(withJSONObject: ["jsonrpc": "2.0", "id": id, "method": method, "params": metadata])
        do {
            let body = try nativeVaultResult(transport.exchange(request), id: id)
            guard let result = try JSONSerialization.jsonObject(with: body) as? [String: Any] else { throw BrokerTransportError.malformedResponse }
            return result
        } catch {
            self.sessionID = nil; peer = nil; transport.close()
            // Any refused/uncertain lifecycle transition leaves protection
            // unconfirmed locally. Never remount fields or release on timeout.
            throw VaultNativeChannelError.protectionUnknown
        }
    }
    private func closeNativeVaultConnection() {
        lock.lock(); defer { lock.unlock() }
        sessionID = nil; peer = nil; transport.close()
    }

    /// Use a dedicated authenticated instance. The single native secret
    /// transaction closes its connection; ordinary consent UI uses another one.
    /// The secure-entry adapter must hold its qualified protection lease before
    /// mounting fields; server admission alone does not protect earlier typing.
    public func submitNativeVault(request: VaultEntryRequest, entryID: String, revision: String? = nil,
                                  username: Data, password: Data) throws -> String {
        lock.lock(); defer { lock.unlock() }
        guard request.isValid, nativeVaultEntryID(entryID), revision == nil || nativeVaultEntryID(revision!), let sessionID, peer != nil,
              let binary = transport as? any NativeVaultBinaryTransport else { throw BrokerTransportError.unavailable }
        defer { self.sessionID = nil; peer = nil; transport.close() }
        let id = UUID().uuidString
        var params: [String: Any] = ["sessionID": sessionID, "origin": request.origin, "accountAlias": request.accountAlias, "entryID": entryID]
        if let revision { params["revision"] = revision }
        let body = try JSONSerialization.data(withJSONObject: ["jsonrpc": "2.0", "id": id,
            "method": revision == nil ? "vault.create" : "vault.update", "params": params])
        // JSON contains only public routing metadata. Secret bytes are released
        // only after the signed endpoint's exact admission reply is validated.
        let ready = try nativeVaultResult(transport.exchange(body), id: id)
        guard let admission = try JSONSerialization.jsonObject(with: ready) as? [String: Any],
              Set(admission.keys) == ["nativeInputReady"],
              let flag = admission["nativeInputReady"] as? NSNumber,
              CFGetTypeID(flag) == CFBooleanGetTypeID(), flag.boolValue else { throw BrokerTransportError.malformedResponse }
        do {
            let result = try nativeVaultResult(binary.sendNativeVaultFrame(username: username, password: password), id: id)
            guard let object = try JSONSerialization.jsonObject(with: result) as? [String: Any], Set(object.keys) == ["reference"],
                  let reference = object["reference"] as? [String: Any], Set(reference.keys) == ["resourceURL"],
                  let url = reference["resourceURL"] as? String, nativeVaultReference(url) else { throw BrokerTransportError.malformedResponse }
            return url
        } catch { throw VaultNativeChannelError.outcomeUnknown }
    }
    /// Dedicated native record transaction. Only opaque routing is JSON; the
    /// protected frame is consumed after exact authenticated admission.
    public func submitNativeRecord(request: VaultEntryRequest, entryID: String,
                                   replacing: VaultRecordMetadata? = nil, frame: VaultRecordFrame) throws -> VaultRecordMetadata {
        lock.lock(); defer { lock.unlock(); frame.destroy() }
        defer { self.sessionID = nil; peer = nil; transport.close() }
        guard request.isValid, request.origin == "https://vault.mechanize.invalid",
              nativeRecordBinding(request.accountAlias), nativeVaultEntryID(entryID),
              replacing == nil || replacing!.isValid, let sessionID, nativeVaultSessionID(sessionID), peer != nil,
              let binary = transport as? any NativeVaultRecordBinaryTransport else { throw BrokerTransportError.unavailable }
        let id = UUID().uuidString
        var params: [String: Any] = ["sessionID": sessionID, "entryID": entryID, "accountAlias": request.accountAlias]
        if let replacing { params["refID"] = replacing.id; params["revision"] = replacing.revision }
        let body = try JSONSerialization.data(withJSONObject: ["jsonrpc": "2.0", "id": id,
            "method": replacing == nil ? "vault.record.create" : "vault.record.update", "params": params])
        let ready = try nativeVaultResult(transport.exchange(body), id: id)
        guard let admission = try JSONSerialization.jsonObject(with: ready) as? [String: Any],
              Set(admission.keys) == ["nativeInputReady"], let flag = admission["nativeInputReady"] as? NSNumber,
              CFGetTypeID(flag) == CFBooleanGetTypeID(), flag.boolValue else { throw BrokerTransportError.malformedResponse }
        do {
            let data = try nativeVaultResult(binary.sendNativeRecordFrame(frame), id: id)
            return try parseNativeRecordMetadata(data)
        } catch { throw VaultNativeChannelError.outcomeUnknown }
    }
    public func deleteNativeRecord(request: VaultEntryRequest, entryID: String, record: VaultRecordMetadata) throws {
        defer { closeNativeVaultConnection() }
        guard request.isValid, request.origin == "https://vault.mechanize.invalid",
              nativeRecordBinding(request.accountAlias), nativeVaultEntryID(entryID), record.isValid else {
            throw BrokerTransportError.unavailable
        }
        do {
            let result = try nativeVaultLifecycle("vault.record.delete", params: ["entryID": entryID,
                "accountAlias": request.accountAlias, "refID": record.id, "revision": record.revision])
            guard Set(result.keys) == ["deleted"], let flag = result["deleted"] as? NSNumber,
                  CFGetTypeID(flag) == CFBooleanGetTypeID(), flag.boolValue else {
                throw BrokerTransportError.malformedResponse
            }
        } catch { throw VaultNativeChannelError.outcomeUnknown }
    }
    public func nativeRecordReady() throws -> Bool {
        let result = try nativeVaultLifecycle("vault.record.status", params: [:])
        guard Set(result.keys) == ["recordReady"], let flag = result["recordReady"] as? NSNumber,
              CFGetTypeID(flag) == CFBooleanGetTypeID() else { throw BrokerTransportError.malformedResponse }
        return flag.boolValue
    }
    public func nativeRecordInventory() throws -> [VaultRecordMetadata] {
        let result = try nativeVaultLifecycle("vault.record.inventory", params: [:])
        guard Set(result.keys) == ["entries"], let entries = result["entries"] as? [[String: Any]], entries.count <= 256 else {
            throw BrokerTransportError.malformedResponse
        }
        var seen = Set<String>()
        return try entries.map { entry in
            let metadata = try parseNativeRecordMetadata(JSONSerialization.data(withJSONObject: entry))
            guard seen.insert(metadata.id).inserted else { throw BrokerTransportError.malformedResponse }
            return metadata
        }
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
