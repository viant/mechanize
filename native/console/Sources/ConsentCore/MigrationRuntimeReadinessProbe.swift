import Foundation
import Darwin
import Security

/// Sealed by the whole reviewed Go installPlan digest already authenticated by
/// preparation. No fieldwise initializer accepts a caller-selected executable.
public struct MigrationRuntimeConsoleManifest: CustomStringConvertible, CustomDebugStringConvertible {
    let executable: URL, bundle: URL
    let requirement: String, sha256: String, brokerRequirement: String, intentBinding: String
    let fileSize: Int64, fileMode: Int
    public var description: String { "Frozen runtime console manifest" }
    public var debugDescription: String { description }
    public init(frozenPlan: Data, intent: MigrationUpgradeIntent) throws {
        guard Self.path(intent.options[0]), !frozenPlan.isEmpty, frozenPlan.count <= 1_048_576,
              MigrationUpgradeIntent.digest(frozenPlan) == intent.runtimeManifestSHA256 else { throw MigrationConsoleError.unavailable }
        try MigrationReadinessJSON.validate(frozenPlan)
        guard let root = try JSONSerialization.jsonObject(with: frozenPlan) as? [String:Any],
              let runtime = root["runtime"] as? [String:Any], Self.integer(root["version"]) == (runtime["Mode"] as? String == "unified-app-update-v3" ? 3 : intent.newCanonicalExecutable == nil ? 1 : 2),
              runtime["BrokerPath"] as? String == intent.options[0],
              runtime["OldBrokerRequirement"] as? String == intent.options[1],
              runtime["NewBrokerRequirement"] as? String == intent.options[2],
              let artifacts = runtime["Artifacts"] as? [[String:Any]], artifacts.count <= 16 else { throw MigrationConsoleError.unavailable }
        let consoles: [[String:Any]], expectedBundle: URL
        if intent.newCanonicalExecutable != nil || runtime["Mode"] as? String == "unified-app-update-v3" {
            let unified = try MigrationUnifiedAppManifest(runtime:runtime,intent:intent)
            consoles = [unified.artifact]; expectedBundle = unified.bundle
        } else {
            guard runtime["Mode"] as? String != "unified-app-v2", runtime["NewBrokerPath"] == nil, runtime["LegacyArtifacts"] == nil else { throw MigrationConsoleError.unavailable }
            consoles = artifacts.filter { $0["role"] as? String == "console" }
            expectedBundle = URL(fileURLWithPath: intent.options[0]).deletingLastPathComponent().appendingPathComponent("Mechanize Permissions.app")
        }
        guard consoles.count == 1, let console = consoles.first,
              console["target"] as? String == expectedBundle.path,
              let requirement = console["NewRequirement"] as? String,
              MigrationAuthorizationRecord.requirement(requirement, role: "consent"),
              let inventory = console["New"] as? [String:Any], inventory.count <= 4096,
              let entry = inventory["Contents/MacOS/MechanizeConsent"] as? [String:Any],
              Set(entry.keys) == Set(["kind","mode","size","sha256"]), entry["kind"] as? String == "file",
              let digest = entry["sha256"] as? String, MigrationAuthorizationRecord.digest(digest),
              let mode = Self.integer(entry["mode"]), [0o700,0o755].contains(mode),
              let size = Self.integer(entry["size"]), size > 0, size <= 512*1024*1024 else { throw MigrationConsoleError.unavailable }
        for path in [".", "Contents", "Contents/MacOS"] {
            guard let directory = inventory[path] as? [String:Any], directory["kind"] as? String == "directory",
                  let mode = Self.integer(directory["mode"]), [0o700,0o755].contains(mode) else { throw MigrationConsoleError.unavailable }
        }
        self.bundle = expectedBundle; executable = expectedBundle.appendingPathComponent("Contents/MacOS/MechanizeConsent")
        self.requirement = requirement; sha256 = digest; brokerRequirement = intent.options[2]
        intentBinding = intent.binding; fileSize = Int64(size); fileMode = mode
    }
    static func path(_ value: String) -> Bool {
        let parts = value.split(separator: "/", omittingEmptySubsequences: false)
        return value.hasPrefix("/") && value.utf8.count <= 4096 && parts.count > 1 && parts.dropFirst().allSatisfy { !$0.isEmpty && $0 != "." && $0 != ".." } && !value.contains("\0") && !value.contains("\n") && !value.contains("\r")
    }
    static func integer(_ value: Any?) -> Int? {
        guard let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID(), number.doubleValue == Double(number.int64Value), number.int64Value >= 0, number.int64Value <= Int64(Int.max) else { return nil }
        return number.intValue
    }
}

/// Reject duplicate decoded JSON keys, trailing material and excessive nesting
/// before Foundation's dictionary decoder can collapse them. Whole-plan bytes
/// are independently pinned; field order is owned by the Go plan schema.
enum MigrationReadinessJSON {
    static func validate(_ data: Data) throws {
        let bytes = Array(data); var offset = 0; var nodes = 0
        func string() throws -> String {
            guard offset < bytes.count, bytes[offset] == 34 else { throw MigrationConsoleError.unavailable }
            let start = offset; offset += 1
            while offset < bytes.count {
                let byte = bytes[offset]; offset += 1
                if byte == 92 { guard offset < bytes.count else { throw MigrationConsoleError.unavailable }; offset += 1 }
                else if byte == 34 {
                    guard let value = try JSONSerialization.jsonObject(with: Data(bytes[start..<offset]), options: .fragmentsAllowed) as? String else { throw MigrationConsoleError.unavailable }; return value
                }
            }
            throw MigrationConsoleError.unavailable
        }
        func value(_ depth: Int) throws {
            nodes += 1; guard depth <= 64, nodes <= 65536, offset < bytes.count else { throw MigrationConsoleError.unavailable }
            switch bytes[offset] {
            case 123:
                offset += 1; var keys: Set<String> = []
                if offset < bytes.count, bytes[offset] == 125 { offset += 1; return }
                while true {
                    let key = try string(); guard keys.insert(key).inserted, offset < bytes.count, bytes[offset] == 58 else { throw MigrationConsoleError.unavailable }; offset += 1
                    try value(depth+1); guard offset < bytes.count else { throw MigrationConsoleError.unavailable }
                    if bytes[offset] == 125 { offset += 1; return }
                    guard bytes[offset] == 44 else { throw MigrationConsoleError.unavailable }; offset += 1
                }
            case 91:
                offset += 1; if offset < bytes.count, bytes[offset] == 93 { offset += 1; return }
                while true { try value(depth+1); guard offset < bytes.count else { throw MigrationConsoleError.unavailable }; if bytes[offset] == 93 { offset += 1; return }; guard bytes[offset] == 44 else { throw MigrationConsoleError.unavailable }; offset += 1 }
            case 34: _ = try string()
            default:
                let start = offset
                while offset < bytes.count, ![UInt8(44),93,125].contains(bytes[offset]) { offset += 1 }
                guard offset > start else { throw MigrationConsoleError.unavailable }
                _ = try JSONSerialization.jsonObject(with: Data(bytes[start..<offset]), options: .fragmentsAllowed)
            }
        }
        try value(0); guard offset == bytes.count else { throw MigrationConsoleError.unavailable }
    }
}

struct MigrationReadinessProcessIdentity: Equatable {
    let pid: pid_t, uid: uid_t
    let seconds: UInt64, microseconds: UInt64
    var start: String { "\(seconds):\(microseconds)" }
}
final class MigrationReadinessCancellation: @unchecked Sendable {
    private let lock = NSLock()
    private var cancelled = false
    private var stopping: (() -> Void)?
    func cancel() { lock.lock(); cancelled = true; let action = stopping; lock.unlock(); action?() }
    func install(_ action: @escaping () -> Void) { lock.lock(); stopping = action; let stop = cancelled; lock.unlock(); if stop { action() } }
    func clear() { lock.lock(); stopping = nil; lock.unlock() }
    var isCancelled: Bool { lock.lock(); defer { lock.unlock() }; return cancelled }
}

final class MigrationReadinessOwnedChild: @unchecked Sendable {
    private let lock = NSLock()
    private var child: pid_t
    init(_ child: pid_t) { self.child = child }
    func stop() {
        lock.lock(); defer { lock.unlock() }
        guard child > 0 else { return }
        var status: Int32 = 0; var result: pid_t
        repeat { result = waitpid(child, &status, WNOHANG) } while result < 0 && errno == EINTR
        if result == 0 { kill(child, SIGKILL) }
        else if result == child || (result < 0 && errno == ECHILD) { child = 0 }
    }
    func exited() throws -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard child > 0 else { throw MigrationConsoleError.unavailable }
        var information = siginfo_t(); var result: Int32
        repeat { result = waitid(P_PID, id_t(child), &information, WEXITED | WNOHANG | WNOWAIT) } while result < 0 && errno == EINTR
        guard result == 0 else { if errno == ECHILD { child = 0 }; throw MigrationConsoleError.unavailable }
        if information.si_pid == 0 { return false }
        // Darwin waitid does not populate si_uid reliably. The kernel confirms
        // our exact unreaped child, whose UID/birth were pinned before resuming.
        guard information.si_pid == child, [CLD_EXITED,CLD_KILLED,CLD_DUMPED].contains(information.si_code) else { throw MigrationConsoleError.unavailable }
        return true
    }
    func reap(_ options: Int32) throws -> (Bool, Int32) {
        lock.lock(); defer { lock.unlock() }
        guard child > 0 else { throw MigrationConsoleError.unavailable }
        var status: Int32 = 0; var result: pid_t
        repeat { result = waitpid(child, &status, options) } while result < 0 && errno == EINTR
        guard result >= 0 else { if errno == ECHILD { child = 0 }; throw MigrationConsoleError.unavailable }
        if result == child { child = 0; return (true,status) }
        return (false,0)
    }
    func cleanup() {
        stop()
        let end = Date().addingTimeInterval(0.25)
        while Date() < end {
            do { if try reap(WNOHANG).0 { return } } catch { return }
            usleep(1000)
        }
        // Keep sole ownership of an unreaped child if the kernel delays exit.
        // A deadline never authorizes signalling a PID after it has been reaped.
        DispatchQueue.global().async { _ = try? self.reap(0) }
    }
}

/// Final, independent read-only check. The Go finalizer owns launchd startup;
/// only the frozen new signed console may perform its own credential/key reads.
public final class MigrationRuntimeReadinessProbe {
    private let manifest: MigrationRuntimeConsoleManifest
    public init(manifest: MigrationRuntimeConsoleManifest) { self.manifest = manifest }
    public func verify(intent: MigrationUpgradeIntent, preparation: MigrationNativePreparation, terminal: MigrationInstallerReply) async throws {
        guard manifest.intentBinding == intent.binding, preparation.preparation.intentBinding == intent.binding,
              MigrationUpgradeIntent.digest(preparation.itemIdentity) == preparation.preparation.itemReferenceSHA256,
              preparation.preparation.validUntil > Date(), terminal.status == "verified", terminal.scope == "runtime-artifacts",
              terminal.transitionID == preparation.preparation.transitionID, let runtime = terminal.runtime else { throw MigrationConsoleError.unavailable }
        let manifest = self.manifest, cancellation = MigrationReadinessCancellation()
        let deadline = min(preparation.preparation.validUntil, Date().addingTimeInterval(25))
        defer { cancellation.clear() }
        try await withTaskCancellationHandler(operation: {
            try Task.checkCancellation()
            try await Task.detached(priority: .userInitiated) {
                let artifact = try MigrationWorkerArtifact(executable: manifest.executable, requirement: manifest.requirement, sha256: manifest.sha256, uid: getuid(), consoleBundle: manifest.bundle)
                let revalidate = {
                    guard !cancellation.isCancelled, Date() < deadline else { throw MigrationConsoleError.unavailable }
                    try artifact.verify(); try Self.bundleContract(manifest)
                    try Self.verifyProcess(runtime.brokerPID, executable: intent.installedBrokerExecutable, requirement: manifest.brokerRequirement, expectedStart: runtime.brokerStartToken)
                }
                let arguments = ["--check-vault","--broker-pid",String(runtime.brokerPID),"--broker-start",runtime.brokerStartToken]
                try Self.runPrivate(executable: manifest.executable.path, arguments: arguments, deadline: deadline,
                    cancelled: { cancellation.isCancelled }, revalidate: revalidate, verifyRunning: { pid in
                        try Self.verifyProcess(pid, executable: manifest.executable.path, requirement: manifest.requirement, expectedStart: nil)
                    }, installCancellation: cancellation.install)
            }.value
            try Task.checkCancellation()
        }, onCancel: { cancellation.cancel() })
    }
    static func diagnostic(_ bytes: Data) throws {
        var expected = VaultDiagnosticReport(stage: "complete", authenticated: true, keyReady: true, inventoryReadable: true).json(); expected.append(10)
        guard bytes == expected else { throw MigrationConsoleError.unavailable }
    }
    static func bundleContract(_ manifest: MigrationRuntimeConsoleManifest) throws {
        var requirement: SecRequirement?, code: SecStaticCode?, information: CFDictionary?
        var info = stat()
        guard lstat(manifest.executable.path, &info) == 0, info.st_size == manifest.fileSize, Int(info.st_mode & 0o7777) == manifest.fileMode,
              SecRequirementCreateWithString(manifest.requirement as CFString, [], &requirement) == errSecSuccess,
              SecStaticCodeCreateWithPath(manifest.bundle as CFURL, [], &code) == errSecSuccess, let code, let requirement,
              SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate | kSecCSCheckAllArchitectures), requirement) == errSecSuccess,
              SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &information) == errSecSuccess,
              let signing = information as? [String:Any], let plist = signing[kSecCodeInfoPList as String] as? [String:Any],
              plist["CFBundleIdentifier"] as? String == "com.viant.mechanize.consent",
              plist["CFBundleExecutable"] as? String == "MechanizeConsent",
              plist["MechanizeBrokerRequirement"] as? String == manifest.brokerRequirement else { throw MigrationConsoleError.unavailable }
    }
    static func identity(_ pid: pid_t) throws -> MigrationReadinessProcessIdentity {
        var info = proc_bsdinfo()
        guard pid > 0, proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, Int32(MemoryLayout<proc_bsdinfo>.size)) == MemoryLayout<proc_bsdinfo>.size,
              info.pbi_pid == UInt32(pid), info.pbi_uid == getuid() else { throw MigrationConsoleError.unavailable }
        return MigrationReadinessProcessIdentity(pid: pid, uid: info.pbi_uid, seconds: info.pbi_start_tvsec, microseconds: info.pbi_start_tvusec)
    }
    static func verifyProcess(_ pid: pid_t, executable: String, requirement: String, expectedStart: String?) throws {
        let before = try identity(pid)
        guard expectedStart == nil || expectedStart == before.start else { throw MigrationConsoleError.unavailable }
        var path = [CChar](repeating: 0, count: 4096)
        guard proc_pidpath(pid, &path, UInt32(path.count)) > 0, String(cString: path) == executable else { throw MigrationConsoleError.unavailable }
        var rule: SecRequirement?, code: SecCode?
        guard SecRequirementCreateWithString(requirement as CFString, [], &rule) == errSecSuccess,
              SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributePid as String: NSNumber(value: pid)] as CFDictionary, [], &code) == errSecSuccess,
              let rule, let code, SecCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate), rule) == errSecSuccess,
              try identity(pid) == before else { throw MigrationConsoleError.unavailable }
    }
    // Internal inert-fixture seam. Public verify always supplies concrete signed
    // artifact/peer checks; no caller success boolean is consumed by production.
    static func runPrivate(executable: String, arguments: [String], deadline: Date, cancelled: () -> Bool,
                           revalidate: () throws -> Void, verifyRunning: (pid_t) throws -> Void,
                           inspect: (pid_t) throws -> MigrationReadinessProcessIdentity = identity,
                           installCancellation: ((@escaping () -> Void) -> Void)? = nil) throws {
        guard deadline > Date(), deadline.timeIntervalSinceNow <= 25, !cancelled() else { throw MigrationConsoleError.unavailable }
        var output: [Int32] = [-1,-1]
        guard pipe(&output) == 0 else { throw MigrationConsoleError.unavailable }
        defer { output.filter { $0 >= 0 }.forEach { Darwin.close($0) } }
        let null = Darwin.open("/dev/null", O_RDWR | O_CLOEXEC); guard null >= 0 else { throw MigrationConsoleError.unavailable }; defer { Darwin.close(null) }
        var actions: posix_spawn_file_actions_t?, attributes: posix_spawnattr_t?
        guard posix_spawn_file_actions_init(&actions) == 0, posix_spawnattr_init(&attributes) == 0 else { throw MigrationConsoleError.unavailable }
        defer { posix_spawn_file_actions_destroy(&actions); posix_spawnattr_destroy(&attributes) }
        for (source,target) in [(null,Int32(0)),(output[1],Int32(1)),(null,Int32(2))] {
            guard posix_spawn_file_actions_adddup2(&actions,source,target) == 0 else { throw MigrationConsoleError.unavailable }
        }
        guard posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_START_SUSPENDED)) == 0 else { throw MigrationConsoleError.unavailable }
        let argv = ([executable] + arguments).map { strdup($0) } + [nil]
        defer { argv.forEach { free($0) } }
        let environment: [UnsafeMutablePointer<CChar>?] = [nil]
        try revalidate(); guard !cancelled(), deadline > Date() else { throw MigrationConsoleError.unavailable }
        var child: pid_t = 0
        let launched = argv.withUnsafeBufferPointer { args in environment.withUnsafeBufferPointer { env in
            posix_spawn(&child, executable, &actions, &attributes, UnsafeMutablePointer(mutating: args.baseAddress!), UnsafeMutablePointer(mutating: env.baseAddress!))
        } }
        guard launched == 0, child > 0 else { throw MigrationConsoleError.unavailable }
        let ownership = MigrationReadinessOwnedChild(child)
        defer { ownership.cleanup() }
        let watchdog = DispatchSource.makeTimerSource(queue: .global())
        watchdog.schedule(deadline: .now() + max(0, deadline.timeIntervalSinceNow))
        watchdog.setEventHandler { ownership.stop() }
        watchdog.resume(); defer { watchdog.cancel() }
        installCancellation? { ownership.stop() }
        Darwin.close(output[1]); output[1] = -1
        let flags = fcntl(output[0], F_GETFL)
        guard flags >= 0, fcntl(output[0], F_SETFL, flags | O_NONBLOCK) == 0 else { throw MigrationConsoleError.unavailable }
        let before = try inspect(child)
        try verifyRunning(child); try revalidate()
        guard try inspect(child) == before, !cancelled(), deadline > Date(), kill(child,SIGCONT) == 0 else { throw MigrationConsoleError.unavailable }
        var bytes = Data(); defer { bytes.resetBytes(in: 0..<bytes.count) }
        var eof = false
        while !eof {
            guard !cancelled(), deadline > Date() else { throw MigrationConsoleError.unavailable }
            var poller = pollfd(fd: output[0], events: Int16(POLLIN), revents: 0)
            let ready = poll(&poller,1,Int32(max(1,min(50,ceil(deadline.timeIntervalSinceNow*1000)))))
            if ready < 0 && errno == EINTR { continue }
            guard ready >= 0 else { throw MigrationConsoleError.unavailable }
            if ready == 0 { continue }
            guard poller.revents & Int16(POLLIN | POLLHUP) != 0 else { throw MigrationConsoleError.unavailable }
            var buffer = [UInt8](repeating: 0,count: 1024)
            let count = Darwin.read(output[0],&buffer,buffer.count)
            if count < 0 && [EINTR,EAGAIN].contains(errno) { continue }
            guard count >= 0 else { throw MigrationConsoleError.unavailable }
            if count == 0 { eof = true } else { bytes.append(contentsOf: buffer.prefix(count)); guard bytes.count <= 4096 else { throw MigrationConsoleError.unavailable } }
        }
        // Darwin may stop exposing libproc metadata for an exited process. A
        // WNOWAIT receipt identifies this exact owned child without reaping it;
        // its PID remains reserved, preserving the captured birth association.
        if let after = try? inspect(child) {
            guard after == before else { throw MigrationConsoleError.unavailable }
        } else {
            guard try ownership.exited() else { throw MigrationConsoleError.unavailable }
        }
        var status: Int32 = 0
        while true {
            guard !cancelled(), deadline > Date() else { throw MigrationConsoleError.unavailable }
            let result = try ownership.reap(WNOHANG)
            if result.0 { status = result.1; break }
            usleep(1000)
        }
        guard status & 0x7f == 0, (status >> 8) & 0xff == 0, !cancelled(), deadline > Date() else { throw MigrationConsoleError.unavailable }
        try revalidate(); try diagnostic(bytes)
    }
}
