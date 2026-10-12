import Foundation
import Darwin
import Security
import CryptoKit

/// Reviewed candidate metadata, created by main-window orchestration. No decoding
/// initializer accepts an approval claim or a peer-provided executable path.
public struct MigrationWorkerManifest: CustomStringConvertible, CustomDebugStringConvertible {
    public var description: String { "Reviewed migration worker manifest" }
    public var debugDescription: String { description }
    public let executable: URL
    public let requirement: String
    public let sha256: String
    public init(executable: URL, requirement: String, sha256: String) throws {
        // Foundation can rewrite an existing /private/tmp path to the /tmp
        // symlink alias. Check lexical components here; the artifact reader
        // separately pins each physical ancestor with O_NOFOLLOW.
        let path = executable.path
        let components = path.split(separator: "/", omittingEmptySubsequences: false)
        guard executable.isFileURL, path.hasPrefix("/"), components.count > 1,
              components.dropFirst().allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." }),
              !path.contains("\0"), !path.contains("\r"), !path.contains("\n"),
              MigrationAuthorizationRecord.requirement(requirement, role: "custody-migration"),
              MigrationAuthorizationRecord.digest(sha256) else { throw MigrationConsoleError.unavailable }
        self.executable = executable; self.requirement = requirement; self.sha256 = sha256
    }
}

/// The helper independently matches this metadata against its signed enrollment.
/// These values never stand in for console authentication or an approved record.
public struct MigrationWorkerBootstrap: CustomStringConvertible, CustomDebugStringConvertible {
    public var description: String { "Private migration bootstrap" }
    public var debugDescription: String { description }
    let session: String
    let reconciliation: Bool
    let value: [String: Any]
    public init(session: String, configSHA256: String, canonicalExecutable: String,
                oldRequirement: String, newRequirement: String, alias: String,
                service: String, account: String, workerRequirement: String,
                expectedIdentity: Data? = nil, newCanonicalExecutable: String? = nil) throws {
        guard MigrationAuthorizationRecord.digest(session), MigrationAuthorizationRecord.digest(configSHA256),
              MigrationAuthorizationRecord.requirement(oldRequirement, role: "broker"),
              MigrationAuthorizationRecord.requirement(newRequirement, role: "broker"), oldRequirement != newRequirement,
              MigrationAuthorizationRecord.requirement(workerRequirement, role: "custody-migration"),
              canonicalExecutable.hasPrefix("/"), canonicalExecutable.utf8.count <= 4096,
              !alias.isEmpty, alias.utf8.count <= 256, service == "com.viant.mechanize.vault",
              !account.isEmpty, account.utf8.count <= 1024,
              expectedIdentity == nil || (expectedIdentity!.count > 0 && expectedIdentity!.count <= 16384) else { throw MigrationConsoleError.unavailable }
        if let newCanonicalExecutable {
            guard MigrationRuntimeConsoleManifest.path(canonicalExecutable), MigrationRuntimeConsoleManifest.path(newCanonicalExecutable),
                  newCanonicalExecutable != canonicalExecutable else { throw MigrationConsoleError.unavailable }
        }
        self.session = session; self.reconciliation = expectedIdentity != nil
        var data: [String: Any] = ["version": 1, "op": "bootstrap", "session": session, "configSHA256": configSHA256,
            "canonicalExecutable": canonicalExecutable, "oldRequirement": oldRequirement, "newRequirement": newRequirement,
            "alias": alias, "service": service, "account": account, "workerRequirement": workerRequirement]
        if let expectedIdentity { data["expectedIdentity"] = expectedIdentity.base64EncodedString() }
        if let newCanonicalExecutable { data["version"] = 2; data["newCanonicalExecutable"] = newCanonicalExecutable }
        value = data
    }
}
public enum MigrationWorkerOperation: String { case prepare, verify, commit, inspect, close }
public struct MigrationWorkerReply: CustomStringConvertible, CustomDebugStringConvertible {
    public var debugDescription: String { description }
    public let status: String
    /// Private coordinator metadata: never display or export through agent tools.
    public let itemIdentity: Data?
    public var description: String { "Private migration worker reply" }
}

final class MigrationWorkerArtifact {
    private var descriptors: [Int32] = []
    private var links: [(Int32, String, Int32, stat)] = []
    private let file: Int32
    private let original: stat
    convenience init(_ manifest: MigrationWorkerManifest, uid: uid_t) throws {
        try self.init(executable: manifest.executable, requirement: manifest.requirement, sha256: manifest.sha256, uid: uid, consoleBundle: nil)
    }
    // Internal role-specific reuse. Public worker admission remains worker-only
    // and owned0700; the console may use signed0755 bundle interiors beneath an
    // owned0700 installation directory, with an independently sealed manifest.
    init(executable: URL, requirement expectedRequirement: String, sha256: String, uid: uid_t, consoleBundle: URL?) throws {
        let role = consoleBundle == nil ? "custody-migration" : "consent"
        guard MigrationAuthorizationRecord.requirement(expectedRequirement, role: role), MigrationAuthorizationRecord.digest(sha256) else { throw MigrationConsoleError.unavailable }
        if let consoleBundle {
            guard executable.path == consoleBundle.appendingPathComponent("Contents/MacOS/MechanizeConsent").path else { throw MigrationConsoleError.unavailable }
        }
        var opened: [Int32] = []
        var accepted = false
        defer { if !accepted { opened.forEach { Darwin.close($0) } } }
        let root = Darwin.open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard root >= 0 else { throw MigrationConsoleError.unavailable }; opened.append(root)
        var parent = root
        var currentPath = ""
        var privateConsoleRoot = false
        let parts = executable.path.split(separator: "/").map(String.init)
        guard parts.count > 1 else { throw MigrationConsoleError.unavailable }
        for part in parts.dropLast() {
            let fd = openat(parent, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            var info = stat()
            guard fd >= 0 else { throw MigrationConsoleError.unavailable }; opened.append(fd)
            guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFDIR,
                  info.st_uid == 0 || info.st_uid == uid else { throw MigrationConsoleError.unavailable }
            currentPath += "/" + part
            if let consoleBundle {
                if currentPath == consoleBundle.deletingLastPathComponent().path {
                    guard info.st_uid == uid, info.st_mode & 0o7777 == 0o700 else { throw MigrationConsoleError.unavailable }
                    privateConsoleRoot = true
                } else if privateConsoleRoot {
                    guard info.st_uid == uid, [mode_t(0o700), mode_t(0o755)].contains(info.st_mode & 0o7777) else { throw MigrationConsoleError.unavailable }
                }
            }
            links.append((parent, part, fd, info)); parent = fd
        }
        guard let directory = links.last?.3, directory.st_uid == uid,
              consoleBundle == nil ? directory.st_mode & 0o7777 == 0o700 : privateConsoleRoot else { throw MigrationConsoleError.unavailable }
        let fd = openat(parent, parts.last!, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard fd >= 0 else { throw MigrationConsoleError.unavailable }; opened.append(fd)
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFREG, info.st_uid == uid,
              (consoleBundle == nil ? info.st_mode & 0o7777 == 0o700 : [mode_t(0o700), mode_t(0o755)].contains(info.st_mode & 0o7777)), info.st_nlink == 1, info.st_size > 0, info.st_size <= 512 * 1024 * 1024 else { throw MigrationConsoleError.unavailable }
        file = fd; original = info; links.append((parent, parts.last!, fd, info))
        var total = 0
        var hasher = SHA256(); var buffer = [UInt8](repeating: 0, count: 65536)
        while true {
            let count = Darwin.read(fd, &buffer, buffer.count)
            if count < 0 && errno == EINTR { continue }
            guard count >= 0 else { throw MigrationConsoleError.unavailable }
            if count == 0 { break }; total += count
            guard total <= original.st_size else { throw MigrationConsoleError.unavailable }; hasher.update(data: Data(buffer.prefix(count)))
        }
        guard hasher.finalize().map({ String(format: "%02x", $0) }).joined() == sha256 else { throw MigrationConsoleError.unavailable }
        var requirement: SecRequirement?; var code: SecStaticCode?
        guard SecRequirementCreateWithString(expectedRequirement as CFString, [], &requirement) == errSecSuccess,
              SecStaticCodeCreateWithPath((consoleBundle ?? executable) as CFURL, [], &code) == errSecSuccess,
              let requirement, let code,
              SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate | kSecCSCheckAllArchitectures), requirement) == errSecSuccess else { throw MigrationConsoleError.unavailable }
        descriptors = opened; accepted = true
        try verify()
    }
    deinit { descriptors.forEach { Darwin.close($0) } }
    func verify() throws {
        for (parent, name, fd, before) in links {
            var current = stat(); var entry = stat()
            guard fstat(fd, &current) == 0, fstatat(parent, name, &entry, AT_SYMLINK_NOFOLLOW) == 0,
                  current.st_dev == before.st_dev, current.st_ino == before.st_ino,
                  entry.st_dev == before.st_dev, entry.st_ino == before.st_ino,
                  current.st_mode == before.st_mode, entry.st_mode == before.st_mode,
                  current.st_uid == before.st_uid, entry.st_uid == before.st_uid else { throw MigrationConsoleError.unavailable }
        }
        var now = stat()
        guard fstat(file, &now) == 0, now.st_size == original.st_size, now.st_nlink == 1,
              now.st_mtimespec.tv_sec == original.st_mtimespec.tv_sec, now.st_mtimespec.tv_nsec == original.st_mtimespec.tv_nsec,
              now.st_ctimespec.tv_sec == original.st_ctimespec.tv_sec, now.st_ctimespec.tv_nsec == original.st_ctimespec.tv_nsec else { throw MigrationConsoleError.unavailable }
    }
}

/// Main-window-owned session. It never retries a protocol operation or relaunches
/// a failed child. Killing a worker is not a claim that a dispatched commit failed.
public final class MigrationWorkerSession: CustomStringConvertible, CustomDebugStringConvertible {
    public var description: String { "Private migration worker session" }
    public var debugDescription: String { description }
    private let lock = NSLock()
    private let exchangeLock = NSLock()
    private var child: pid_t
    private var input: Int32
    private var output: Int32
    private var cancellationSocket: Int32
    private var channel: (any MigrationWorkerCredentialSession)?
    private let deadline: Date
    private var timer: DispatchSourceTimer?
    private var exitSource: DispatchSourceProcess?
    private var session: String?
    private var used: Set<String> = []
    private var terminal = false
    private var closing = false
    private var commitSent = false
    private var phase = "new"
    public var commitMayHaveDispatched: Bool { lock.lock(); defer { lock.unlock() }; return commitSent }
    init(child: pid_t, input: Int32, output: Int32, cancellationSocket: Int32, deadline: Date) {
        self.child = child; self.input = input; self.output = output; self.cancellationSocket = cancellationSocket; self.deadline = deadline
    }
    func retain(_ channel: any MigrationWorkerCredentialSession) throws {
        lock.lock(); defer { lock.unlock() }
        guard child > 0 else { channel.close(); throw MigrationConsoleError.unavailable }
        self.channel = channel
    }
    func monitor() {
        let source = DispatchSource.makeProcessSource(identifier: child, eventMask: .exit, queue: .global())
        source.setEventHandler { [weak self] in self?.reapExited() }
        let timer = DispatchSource.makeTimerSource(queue: .global())
        timer.schedule(deadline: .now() + max(0, deadline.timeIntervalSinceNow)); timer.setEventHandler { [weak self] in self?.cancel() }
        lock.lock(); exitSource = source; self.timer = timer; lock.unlock()
        source.resume(); timer.resume()
    }
    // Preserve stdout after process exit so a buffered terminal receipt can be
    // drained. Exit is not itself a protocol result or permission to replay.
    func reapExited() {
        lock.lock(); defer { lock.unlock() }
        if child > 0 {
            var status: Int32 = 0; var result: pid_t
            repeat { result = waitpid(child, &status, WNOHANG) } while result < 0 && errno == EINTR
            if result == child || (result < 0 && errno == ECHILD) { child = 0 }
        }
        if child == 0 { exitSource?.cancel(); exitSource = nil }
    }
    func attestationFailed() {
        reapExited()
        lock.lock(); let mustStop = child > 0 && !closing; lock.unlock()
        if mustStop { cancel() }
    }
    deinit { cancel() }
    public func cancel() {
        lock.lock()
        if cancellationSocket >= 0 { shutdown(cancellationSocket, SHUT_RDWR); Darwin.close(cancellationSocket); cancellationSocket = -1 }
        if input >= 0 { Darwin.close(input); input = -1 }; if output >= 0 { Darwin.close(output); output = -1 }
        if child > 0 {
            var status: Int32 = 0
            var result: pid_t
            repeat { result = waitpid(child, &status, WNOHANG) } while result < 0 && errno == EINTR
            if result == 0 {
                let owned = child
                kill(owned, SIGKILL)
                // This sole reaper owns the zombie until waitpid completes; no
                // later cancel can signal a recycled PID.
                DispatchQueue.global().async { var result: Int32 = 0; while waitpid(owned, &result, 0) < 0 && errno == EINTR {} }
                child = 0
            } else if result == child || (result < 0 && errno == ECHILD) { child = 0 }
        }
        timer?.cancel(); timer = nil
        if child == 0 { exitSource?.cancel(); exitSource = nil }
        let retainedChannel = channel
        lock.unlock()
        // shutdown wakes the in-progress attestation before its lock is acquired.
        retainedChannel?.close()
    }
    private func transfer(_ data: inout Data, writing: Bool) throws {
        var offset = 0
        while offset < data.count {
            lock.lock(); let original = writing ? input : output
            let fd = original >= 0 ? dup(original) : -1; lock.unlock()
            // A duplicate prevents concurrent cancellation from redirecting IO
            // to a recycled descriptor. Child termination still closes its peer.
            defer { if fd >= 0 { Darwin.close(fd) } }
            if writing && fd >= 0 { guard fcntl(fd, F_SETNOSIGPIPE, 1) == 0 else { throw MigrationConsoleError.unavailable } }
            let remaining = deadline.timeIntervalSinceNow
            guard fd >= 0, remaining > 0, remaining <= 240 else { throw MigrationConsoleError.unavailable }
            var poller = pollfd(fd: fd, events: Int16(writing ? POLLOUT : POLLIN), revents: 0)
            let ready = poll(&poller, 1, Int32(max(1, ceil(remaining * 1000))))
            if ready < 0 && errno == EINTR { continue }
            guard ready > 0, poller.revents & poller.events != 0 else { throw MigrationConsoleError.unavailable }
            let count = data.withUnsafeMutableBytes { raw -> Int in
                if writing { return Darwin.write(fd, raw.baseAddress!.advanced(by: offset), raw.count - offset) }
                return Darwin.read(fd, raw.baseAddress!.advanced(by: offset), raw.count - offset)
            }
            if count < 0 && (errno == EINTR || errno == EAGAIN) { continue }
            guard count > 0 else { throw MigrationConsoleError.unavailable }; offset += count
        }
    }
    static func canonical(_ object: [String: Any], order: [String]) throws -> Data {
        guard Set(object.keys).isSubset(of: Set(order)) else { throw MigrationConsoleError.unavailable }
        var fields: [String] = []
        for key in order {
            guard let value = object[key] else { continue }
            let data = try JSONSerialization.data(withJSONObject: value, options: [.fragmentsAllowed, .withoutEscapingSlashes])
            guard var encoded = String(data: data, encoding: .utf8) else { throw MigrationConsoleError.unavailable }
            encoded = encoded.replacingOccurrences(of: "&", with: "\\u0026").replacingOccurrences(of: "<", with: "\\u003c").replacingOccurrences(of: ">", with: "\\u003e").replacingOccurrences(of: "\u{2028}", with: "\\u2028").replacingOccurrences(of: "\u{2029}", with: "\\u2029")
            fields.append("\"" + key + "\":" + encoded)
        }
        return Data(("{" + fields.joined(separator: ",") + "}").utf8)
    }
    private func writeFrame(_ object: [String: Any]) throws {
        let order = object["op"] as? String == "bootstrap" ? ["version", "op", "session", "configSHA256", "canonicalExecutable", "oldRequirement", "newRequirement", "alias", "service", "account", "workerRequirement", "expectedIdentity", "newCanonicalExecutable"] : ["version", "id", "session", "op"]
        let payload = try Self.canonical(object, order: order)
        guard payload.count <= 32768 else { throw MigrationConsoleError.unavailable }
        var size = UInt32(payload.count).bigEndian; var frame = Data()
        withUnsafeBytes(of: &size) { frame.append(contentsOf: $0) }; frame.append(payload); try transfer(&frame, writing: true)
    }
    public func bootstrap(_ preparation: MigrationWorkerBootstrap) throws {
        exchangeLock.lock(); defer { exchangeLock.unlock() }
        guard session == nil, !terminal else { throw MigrationConsoleError.unavailable }
        session = preparation.session // consumed before uncertain write
        phase = preparation.reconciliation ? "unknown" : "idle"
        if preparation.reconciliation { lock.lock(); commitSent = true; lock.unlock() }
        do { try writeFrame(preparation.value) } catch { terminal = true; cancel(); throw MigrationConsoleError.unavailable }
    }
    // Private installer framing is used only by the typed installer client. The
    // signed server mode owns execute/adopt/placement; raw worker verbs cannot mix.
    func installerRoundTrip(_ payload: Data, closing closeRequested: Bool) throws -> Data {
        exchangeLock.lock(); defer { exchangeLock.unlock() }
        guard !terminal, session != nil, ["idle", "installer"].contains(phase), !payload.isEmpty, payload.count <= 32768 else { throw MigrationConsoleError.unavailable }
        phase = "installer"
        if closeRequested { lock.lock(); closing = true; lock.unlock() }
        do {
            var count = UInt32(payload.count).bigEndian; var frame = Data()
            withUnsafeBytes(of:&count) { frame.append(contentsOf:$0) }; frame.append(payload)
            try transfer(&frame, writing:true)
            var header = Data(count:4); try transfer(&header, writing:false)
            let size = header.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
            guard size > 0, size <= 32768 else { throw MigrationConsoleError.unavailable }
            var reply = Data(count:Int(size)); try transfer(&reply, writing:false)
            if closeRequested { terminal = true }
            return reply
        } catch { terminal = true; cancel(); throw MigrationConsoleError.unavailable }
    }
    // Dedicated preparation client path. It never exposes commit/verify and
    // requires the independently signed read-only server's bound evidence.
    func readOnlyPreparation(intent: MigrationUpgradeIntent, requestID: String, validUntil: Date) throws -> MigrationNativePreparation {
        exchangeLock.lock(); defer { exchangeLock.unlock() }
        guard !terminal, let session, phase == "idle", MigrationAuthorizationRecord.digest(requestID), !used.contains(requestID) else { throw MigrationConsoleError.unavailable }
        used.insert(requestID); phase = "readOnlyPrepared"
        do {
            try writeFrame(["version":1,"id":requestID,"session":session,"op":"prepare"])
            var header = Data(count:4); try transfer(&header, writing:false)
            let count = header.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
            guard count > 0, count <= 32768 else { throw MigrationConsoleError.unavailable }
            var payload = Data(count:Int(count)); try transfer(&payload, writing:false)
            return try MigrationNativePreparation.decode(payload, intent:intent, requestID:requestID, validUntil:validUntil)
        } catch { terminal = true; cancel(); throw MigrationConsoleError.unavailable }
    }
    public func exchange(_ operation: MigrationWorkerOperation, requestID: String) throws -> MigrationWorkerReply {
        exchangeLock.lock(); defer { exchangeLock.unlock() }
        guard !terminal, let session, MigrationAuthorizationRecord.digest(requestID), !used.contains(requestID), used.count < 16 else { throw MigrationConsoleError.unavailable }
        let allowed = operation == .close || (operation == .prepare && phase == "idle") || (operation == .verify && phase == "prepared") || (operation == .commit && phase == "checked") || (operation == .inspect && ["unknown", "verified"].contains(phase))
        guard allowed else { throw MigrationConsoleError.unavailable }
        used.insert(requestID)
        if operation == .close { lock.lock(); closing = true; lock.unlock() }
        if operation == .commit { lock.lock(); commitSent = true; lock.unlock() }
        do {
            try writeFrame(["version": 1, "id": requestID, "session": session, "op": operation.rawValue])
            var header = Data(count: 4); try transfer(&header, writing: false)
            let count = header.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
            guard count > 0, count <= 32768 else { throw MigrationConsoleError.unavailable }
            var payload = Data(count: Int(count)); try transfer(&payload, writing: false)
            guard let reply = try JSONSerialization.jsonObject(with: payload) as? [String: Any],
                  Set(reply.keys).isSubset(of: ["version", "id", "session", "status", "identity"]),
                  reply["version"] as? Int == 1, reply["id"] as? String == requestID, reply["session"] as? String == session,
                  let status = reply["status"] as? String, ["prepared", "checked", "verified", "closed", "unknown", "unavailable"].contains(status) else { throw MigrationConsoleError.unavailable }
            var canonical = reply; canonical["version"] = 1
            guard try Self.canonical(canonical, order: ["version", "id", "session", "status", "identity"]) == payload else { throw MigrationConsoleError.unavailable }
            let permitted: [MigrationWorkerOperation: Set<String>] = [.prepare: ["prepared", "unavailable"], .verify: ["checked", "unavailable"], .commit: ["verified", "unknown", "unavailable"], .inspect: ["verified", "unknown", "unavailable"], .close: ["closed", "unknown", "unavailable"]]
            guard permitted[operation]?.contains(status) == true else { throw MigrationConsoleError.unavailable }
            var identity: Data?
            if let encoded = reply["identity"] as? String { identity = Data(base64Encoded: encoded); guard let identity, !identity.isEmpty, identity.count <= 16384 else { throw MigrationConsoleError.unavailable } }
            guard (status == "prepared") == (identity != nil), reply["identity"] == nil || identity != nil else { throw MigrationConsoleError.unavailable }
            phase = status
            if operation == .close || status == "unavailable" { terminal = true; cancel() }
            return MigrationWorkerReply(status: status, itemIdentity: identity)
        } catch { terminal = true; cancel(); throw MigrationConsoleError.unavailable }
    }
}

public enum MigrationWorkerLauncher {
    public static func launch(manifest: MigrationWorkerManifest, credentials: any EnrollmentCredentialProvider,
                              authorization: MigrationAuthorizationRecord, observer: MigrationRuntimeObserverCollector? = nil) throws -> MigrationWorkerSession {
        guard manifest.requirement == authorization.helperRequirement, authorization.validUntil > Date() else { throw MigrationConsoleError.unavailable }
        let artifact = try MigrationWorkerArtifact(manifest, uid: getuid())
        return try launchPrivate(executable: manifest.executable.path, deadline: authorization.validUntil,
            revalidate: artifact.verify, connect: { socket in
                try MigrationConsoleChannel(connectedSocket: socket, expectedUID: getuid(), credentials: credentials, authorization: authorization, observer: observer)
            })
    }
    static func requireReady(_ descriptor: Int32, deadline: Date) throws {
        func readable() throws {
            let remaining = deadline.timeIntervalSinceNow
            guard remaining > 0, remaining <= 240 else { throw MigrationConsoleError.unavailable }
            var event = pollfd(fd: descriptor, events: Int16(POLLIN), revents: 0)
            guard poll(&event, 1, Int32(max(1, ceil(remaining * 1000)))) > 0,
                  event.revents & Int16(POLLIN | POLLHUP) != 0 else { throw MigrationConsoleError.unavailable }
        }
        try readable()
        var marker = [UInt8](repeating: 0, count: 8)
        guard Darwin.read(descriptor, &marker, 8) == 8, Data(marker) == Data("MMREADY1".utf8) else { throw MigrationConsoleError.unavailable }
        try readable()
        var extra: UInt8 = 0
        guard Darwin.read(descriptor, &extra, 1) == 0 else { throw MigrationConsoleError.unavailable }
    }
    // Internal inert-process test seam; production always verifies signed artifact and peer.
    static func launchPrivate(executable: String, deadline: Date, revalidate: () throws -> Void,
                              connect: (Int32) throws -> any MigrationWorkerCredentialSession) throws -> MigrationWorkerSession {
        guard deadline > Date(), deadline.timeIntervalSinceNow <= 240 else { throw MigrationConsoleError.unavailable }
        var descriptors: [Int32] = []
        defer { descriptors.forEach { Darwin.close($0) } }
        func pipePair() throws -> [Int32] { var p: [Int32] = [-1,-1]; guard pipe(&p) == 0 else { throw MigrationConsoleError.unavailable }; descriptors += p; return p }
        let input = try pipePair(); let output = try pipePair(); let readiness = try pipePair()
        var sockets: [Int32] = [-1,-1]; guard socketpair(AF_UNIX, SOCK_STREAM, 0, &sockets) == 0 else { throw MigrationConsoleError.unavailable }; descriptors += sockets
        let null = Darwin.open("/dev/null", O_WRONLY | O_CLOEXEC); guard null >= 0 else { throw MigrationConsoleError.unavailable }; descriptors.append(null)
        var actions: posix_spawn_file_actions_t?; var attributes: posix_spawnattr_t?
        guard posix_spawn_file_actions_init(&actions) == 0, posix_spawnattr_init(&attributes) == 0 else { throw MigrationConsoleError.unavailable }
        defer { posix_spawn_file_actions_destroy(&actions); posix_spawnattr_destroy(&attributes) }
        for (source, target) in [(input[0],Int32(0)),(output[1],Int32(1)),(null,Int32(2)),(sockets[1],Int32(3)),(readiness[1],Int32(4))] {
            guard posix_spawn_file_actions_adddup2(&actions, source, target) == 0 else { throw MigrationConsoleError.unavailable }
        }
        for descriptor in descriptors where descriptor > 4 {
            guard posix_spawn_file_actions_addclose(&actions, descriptor) == 0 else { throw MigrationConsoleError.unavailable }
        }
        guard posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_CLOEXEC_DEFAULT)) == 0 else { throw MigrationConsoleError.unavailable }
        let argv = [strdup(executable), nil]; let environment: [UnsafeMutablePointer<CChar>?] = [nil]
        defer { free(argv[0]) }
        var child: pid_t = 0
        try revalidate()
        let result = argv.withUnsafeBufferPointer { args in environment.withUnsafeBufferPointer { env in
            posix_spawn(&child, executable, &actions, &attributes, UnsafeMutablePointer(mutating: args.baseAddress!), UnsafeMutablePointer(mutating: env.baseAddress!))
        } }
        guard result == 0, child > 0 else { throw MigrationConsoleError.unavailable }
        for fd in [input[0],output[1],sockets[1],readiness[1],null] { Darwin.close(fd); descriptors.removeAll { $0 == fd } }
        for descriptor in [input[1], output[0]] {
            let flags = fcntl(descriptor, F_GETFL)
            guard flags >= 0, fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0 else {
                kill(child, SIGKILL); var status: Int32 = 0; waitpid(child, &status, 0); throw MigrationConsoleError.unavailable
            }
        }
        let cancellation = dup(sockets[0]); guard cancellation >= 0 else { kill(child,SIGKILL); var status:Int32=0;waitpid(child,&status,0);throw MigrationConsoleError.unavailable }
        let session = MigrationWorkerSession(child: child, input: input[1], output: output[0], cancellationSocket: cancellation, deadline: deadline)
        descriptors.removeAll { $0 == input[1] || $0 == output[0] }
        session.monitor()
        do {
            try revalidate()
            // Readiness is a fixed progress marker on its own pipe, never proof
            // of identity. It follows child adoption/authentication of fd 3.
            try requireReady(readiness[0], deadline: min(deadline, Date().addingTimeInterval(10)))
            Darwin.close(readiness[0]); descriptors.removeAll { $0 == readiness[0] }
            var actual: pid_t = 0; var length = socklen_t(MemoryLayout<pid_t>.size)
            guard getsockopt(sockets[0], SOL_LOCAL, LOCAL_PEERPID, &actual, &length) == 0, length == MemoryLayout<pid_t>.size, actual == child else { throw MigrationConsoleError.unavailable }
            let socket = sockets[0]; descriptors.removeAll { $0 == socket } // channel constructor adopts, including failure
            let channel = try connect(socket); try session.retain(channel)
            DispatchQueue.global().async { do { try channel.authenticateAndServe() } catch { session.attestationFailed() } }
            return session
        } catch { session.cancel(); throw MigrationConsoleError.unavailable }
    }
}
