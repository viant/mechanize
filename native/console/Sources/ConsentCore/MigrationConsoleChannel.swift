import Foundation
import Darwin
import CryptoKit

public enum MigrationConsoleError: Error, LocalizedError {
    case unavailable
    public var errorDescription: String? { "The authenticated migration channel is unavailable." }
}

/// Retained by the main Mechanize window for an already-authorized exact operation.
/// Construct from trusted preparation/enrollment, never arguments, peer JSON or a
/// decoded approval boolean. This record creates no window and requests no prompt.
public final class MigrationAuthorizationRecord: CustomStringConvertible, CustomDebugStringConvertible {
    private let lock = NSLock()
    private let fields: [Int: String]
    let helperRequirement: String
    let validUntil: Date
    private var consumed = false
    public var description: String { "Private migration authorization" }
    public var debugDescription: String { description }

    public init(workerSession: String, optionsSHA256: String, helperRequirement: String,
                itemReferenceSHA256: String, transitionID: String, canonicalExecutable: String,
                oldRequirement: String, newRequirement: String, alias: String, service: String,
                account: String, transitionBinding: String, validUntil: Date, newCanonicalExecutable: String? = nil) throws {
        guard [workerSession, optionsSHA256, itemReferenceSHA256, transitionID, transitionBinding].allSatisfy(Self.digest),
              Self.requirement(helperRequirement, role: "custody-migration"),
              Self.requirement(oldRequirement, role: "broker"), Self.requirement(newRequirement, role: "broker"), oldRequirement != newRequirement,
              canonicalExecutable.hasPrefix("/"), canonicalExecutable.utf8.count <= 4096,
              !canonicalExecutable.contains("\0"), !canonicalExecutable.contains("\n"), !canonicalExecutable.contains("\r"),
              service == "com.viant.mechanize.vault", !alias.isEmpty, alias.utf8.count <= 256,
              !account.isEmpty, account.utf8.count <= 1024, !account.contains("\0"),
              validUntil > Date(), validUntil.timeIntervalSinceNow <= 240 else { throw MigrationConsoleError.unavailable }
        self.helperRequirement = helperRequirement; self.validUntil = validUntil
        var bound = [0: workerSession, 2: optionsSHA256, 3: helperRequirement, 4: itemReferenceSHA256,
                  5: transitionID, 6: canonicalExecutable, 7: oldRequirement, 8: newRequirement,
                  9: alias, 10: service, 11: account, 12: itemReferenceSHA256, 13: transitionBinding]
        if let newCanonicalExecutable {
            guard MigrationRuntimeConsoleManifest.path(newCanonicalExecutable), newCanonicalExecutable != canonicalExecutable else { throw MigrationConsoleError.unavailable }
            bound[14] = newCanonicalExecutable; bound[15] = MigrationUpgradeIntent.relocationDomain
        }
        fields = bound
    }
    static func digest(_ text: String) -> Bool { text.utf8.count == 64 && text.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) } }
    static func requirement(_ text: String, role: String) -> Bool {
        let prefix = "identifier \"com.viant.mechanize.\(role)\" and cdhash H\""
        guard text.hasPrefix(prefix), text.hasSuffix("\"") else { return false }
        let hash = text.dropFirst(prefix.count).dropLast()
        return hash.utf8.count == 40 && hash.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }
    func consume(_ challenge: MigrationApprovalChallenge, now: Date) throws {
        lock.lock(); defer { lock.unlock() }
        guard !consumed, now < validUntil, challenge.deadline > now,
              challenge.deadline <= validUntil,
              challenge.fields.count == fields.count + 1, Self.digest(challenge.fields[1]), fields.allSatisfy({ challenge.fields[$0.key] == $0.value }) else { throw MigrationConsoleError.unavailable }
        // Consume before dispatch. A failed write cannot authorize a retry.
        consumed = true
    }
}

struct MigrationApprovalChallenge: CustomStringConvertible, CustomDebugStringConvertible {
    let nonce: Data
    let deadline: Date
    let fields: [String]
    let transcript: Data
    var description: String { "Private migration challenge" }
    var debugDescription: String { description }
    static let maximumLength = 9216
    static let marker = Data([77,77,65,80,82,86,0,1])
    static func decode(_ payload: Data, now: Date = Date()) throws -> MigrationApprovalChallenge {
        let bytes = [UInt8](payload)
        guard bytes.count >= 40, bytes.count <= maximumLength else { throw MigrationConsoleError.unavailable }
        let nonce = Data(bytes[0..<32]); guard nonce.contains(where: { $0 != 0 }) else { throw MigrationConsoleError.unavailable }
        let nanos = bytes[32..<40].reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
        guard nanos <= UInt64(Int64.max) else { throw MigrationConsoleError.unavailable }
        let deadline = Date(timeIntervalSince1970: Double(nanos) / 1_000_000_000)
        guard deadline > now, deadline.timeIntervalSince(now) <= 240 else { throw MigrationConsoleError.unavailable }
        var index = 40; var fields: [String] = []
        while index < bytes.count && fields.count < 16 {
            guard index + 2 <= bytes.count else { throw MigrationConsoleError.unavailable }
            let length = Int(bytes[index]) << 8 | Int(bytes[index + 1]); index += 2
            guard length <= 4096, index + length <= bytes.count,
                  let text = String(bytes: bytes[index..<index + length], encoding: .utf8) else { throw MigrationConsoleError.unavailable }
            fields.append(text); index += length
        }
        guard index == bytes.count, fields.count == 14 || (fields.count == 16 &&
              fields[15] == MigrationUpgradeIntent.relocationDomain && MigrationRuntimeConsoleManifest.path(fields[14]) && fields[14] != fields[6]) else { throw MigrationConsoleError.unavailable }
        return MigrationApprovalChallenge(nonce: nonce, deadline: deadline, fields: fields, transcript: Data(SHA256.hash(data: payload)))
    }
    var attestation: Data {
        var result = Data([77,77,65,67,75,0,0,1,1]); result.append(nonce); result.append(transcript); return result
    }
}

protocol MigrationConsoleWire: AnyObject {
    func authenticate() throws
    func write(_ data: Data, deadline: Date) throws
    func readExactly(_ count: Int, deadline: Date) throws -> Data
    func close()
    func interrupt()
}
extension MigrationConsoleWire { func interrupt() { close() } }

/// Adopts one connected private Unix socket. Its trusted helper requirement must
/// come from the signed candidate manifest/launcher, never from this socket.
final class SignedMigrationSocket: MigrationConsoleWire {
    private let peer: SignedBrokerPeer
    private let descriptorLock = NSLock()
    private var fd: Int32
    init(socket: Int32, requirement: String, uid: uid_t) throws {
        guard socket >= 0, MigrationAuthorizationRecord.requirement(requirement, role: "custody-migration") else { throw MigrationConsoleError.unavailable }
        self.fd = socket; self.peer = try SignedBrokerPeer(designatedRequirement: requirement, expectedUID: uid)
        do {
            try authenticate()
            let flags = fcntl(fd, F_GETFL); guard flags >= 0, fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0 else { throw MigrationConsoleError.unavailable }
            var one: Int32 = 1
            guard setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size)) == 0 else { throw MigrationConsoleError.unavailable }
        } catch { close(); throw MigrationConsoleError.unavailable }
    }
    deinit { close() }
    func authenticate() throws { guard fd >= 0 else { throw MigrationConsoleError.unavailable }; try peer.authenticate(socket: fd) }
    private func ready(_ event: Int16, deadline: Date) throws {
        while true {
            let remaining = deadline.timeIntervalSinceNow
            guard fd >= 0, remaining > 0, remaining <= 240 else { throw MigrationConsoleError.unavailable }
            var descriptor = pollfd(fd: fd, events: event, revents: 0)
            let result = poll(&descriptor, 1, Int32(max(1, ceil(remaining * 1000))))
            if result < 0 && errno == EINTR { continue }
            guard result > 0, descriptor.revents & event != 0 else { throw MigrationConsoleError.unavailable }
            return
        }
    }
    func write(_ data: Data, deadline: Date) throws {
        try data.withUnsafeBytes { raw in
            var offset = 0
            while offset < raw.count {
                try ready(Int16(POLLOUT), deadline: deadline)
                let count = Darwin.write(fd, raw.baseAddress!.advanced(by: offset), raw.count - offset)
                if count < 0 && (errno == EINTR || errno == EAGAIN) { continue }
                guard count > 0 else { throw MigrationConsoleError.unavailable }; offset += count
            }
        }
    }
    func readExactly(_ count: Int, deadline: Date) throws -> Data {
        guard count > 0, count <= 16384 else { throw MigrationConsoleError.unavailable }
        var data = Data(count: count)
        try data.withUnsafeMutableBytes { raw in
            var offset = 0
            while offset < count {
                try ready(Int16(POLLIN), deadline: deadline)
                let read = Darwin.read(fd, raw.baseAddress!.advanced(by: offset), count - offset)
                if read < 0 && (errno == EINTR || errno == EAGAIN) { continue }
                guard read > 0 else { throw MigrationConsoleError.unavailable }; offset += read
            }
        }
        return data
    }
    func interrupt() { descriptorLock.lock(); defer { descriptorLock.unlock() }; if fd >= 0 { _ = shutdown(fd, SHUT_RDWR) } }
    func close() { descriptorLock.lock(); defer { descriptorLock.unlock() }; if fd >= 0 { Darwin.close(fd); fd = -1 } }
}

/// Invoked by main-window upgrade orchestration for an existing authorization.
/// No UI, JSON approval API, CLI arguments or new confirmation loop is provided.
public final class MigrationConsoleChannel: CustomStringConvertible, CustomDebugStringConvertible {
    private let lock = NSLock()
    private let wire: any MigrationConsoleWire
    private let credentials: any EnrollmentCredentialProvider
    private let authorization: MigrationAuthorizationRecord
    private var started = false
    private let observer: MigrationRuntimeObserverCollector?
    public var description: String { "Private migration console channel" }
    public var debugDescription: String { description }
    public convenience init(connectedSocket: Int32, expectedUID: uid_t, credentials: any EnrollmentCredentialProvider, authorization: MigrationAuthorizationRecord, observer: MigrationRuntimeObserverCollector? = nil) throws {
        let wire = try SignedMigrationSocket(socket: connectedSocket, requirement: authorization.helperRequirement, uid: expectedUID)
        self.init(wire: wire, credentials: credentials, authorization: authorization, observer: observer)
    }
    // Fixture seam only. Production always constructs SignedMigrationSocket.
    init(wire: any MigrationConsoleWire, credentials: any EnrollmentCredentialProvider, authorization: MigrationAuthorizationRecord, observer: MigrationRuntimeObserverCollector? = nil) {
        self.wire = wire; self.credentials = credentials; self.authorization = authorization; self.observer = observer
    }
    deinit { wire.close() }
    public func attestExistingAuthorization() throws {
        lock.lock(); defer { lock.unlock() }
        guard !started else { throw MigrationConsoleError.unavailable }; started = true
        do {
            guard authorization.validUntil > Date() else { throw MigrationConsoleError.unavailable }
            try wire.authenticate() // Must precede even the private credential lookup.
            var credential = try credentials.credential()
            defer { credential.resetBytes(in: 0..<credential.count) }
            guard !credential.isEmpty, credential.count <= 32768 else { throw MigrationConsoleError.unavailable }
            var frame = Data([77,77,65,85,84,72,0,1]); var length = UInt32(credential.count).bigEndian
            withUnsafeBytes(of: &length) { frame.append(contentsOf: $0) }; frame.append(credential)
            defer { frame.resetBytes(in: 0..<frame.count) }
            try wire.authenticate(); try wire.write(frame, deadline: authorization.validUntil)
            for _ in 0..<129 {
                try wire.authenticate()
                let header = try wire.readExactly(12, deadline: authorization.validUntil)
                try wire.authenticate()
                let count = header.suffix(4).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
                guard count > 0, count <= 16384 else { throw MigrationConsoleError.unavailable }
                let payload = try wire.readExactly(Int(count), deadline: authorization.validUntil)
                try wire.authenticate()
                if header.prefix(8) == Data([77,77,79,66,83,81,0,1]) {
                    guard let observer else { throw MigrationConsoleError.unavailable }
                    let response = try observer.response(payload, authorizationDeadline: authorization.validUntil)
                    guard response.count <= 16384 else { throw MigrationConsoleError.unavailable }
                    var frame = Data([77,77,79,66,83,82,0,1]); var length = UInt32(response.count).bigEndian
                    withUnsafeBytes(of: &length) { frame.append(contentsOf: $0) }; frame.append(response)
                    try wire.authenticate(); try wire.write(frame, deadline: authorization.validUntil); try wire.authenticate()
                } else if header.prefix(8) == MigrationApprovalChallenge.marker {
                    let challenge = try MigrationApprovalChallenge.decode(payload)
                    try authorization.consume(challenge, now: Date())
                    try wire.authenticate()
                    try wire.write(challenge.attestation, deadline: min(authorization.validUntil, challenge.deadline))
                    try wire.authenticate()
                    if observer == nil { return }
                } else { throw MigrationConsoleError.unavailable }
            }
            throw MigrationConsoleError.unavailable
        } catch { wire.close(); throw MigrationConsoleError.unavailable }
    }
    /// Call only after the owning orchestrator has received the terminal result.
    public func close() { wire.interrupt(); lock.lock(); defer { lock.unlock() }; wire.close() }
}
