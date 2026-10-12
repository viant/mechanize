import Foundation
import AppKit
import Darwin
import Security

struct MigrationShutdownIdentity: Equatable {
    let pid: pid_t, uid: uid_t
    let birth: String, executable: String, requirement: String
}
enum MigrationShutdownPresence { case same, gone, replaced, unavailable }

/// Existing managed process lifecycle, not a new broker RPC. qualify is read-only;
/// stop submits one exact broker SIGTERM. Disappearance proves physical shutdown
/// only: the legacy broker discards Host.Close errors, so durable unknown effects
/// are preserved and never promoted to verified business cleanup.
protocol MigrationBrokerLifecycleRoute: AnyObject {
    func qualify(broker: MigrationShutdownIdentity, helperPins: [String: String], deadline: Date) throws -> [MigrationShutdownIdentity]
    func stop(deadline: Date, willDispatch: () throws -> Void) throws
    func verifyStopped(deadline: Date) throws
}
struct MigrationShutdownRuntime {
    let now: () -> Date
    let inspect: (MigrationShutdownIdentity) -> MigrationShutdownPresence
    let quitChrome: (MigrationShutdownIdentity, Date, () throws -> Void) throws -> Bool
    let wait: (TimeInterval) -> Void
    let requireStopped: ([String]) throws -> Void
    let console: () throws -> Void
    static func system(consoleRequirement: String, consoleBirth: String, canonicalChrome: String? = nil, chromePID: pid_t? = nil) -> MigrationShutdownRuntime {
        let inspect: (MigrationShutdownIdentity) -> MigrationShutdownPresence = { identity in
            let state = MigrationShutdownOS.inspect(identity)
            guard state == .same, identity.pid == chromePID, let canonicalChrome else { return state }
            do { return try MigrationObserverOS.chromeImage(identity.pid, identity.birth, canonicalChrome, identity.requirement) == identity ? .same : .replaced }
            catch { return .unavailable }
        }
        return MigrationShutdownRuntime(now: Date.init, inspect: inspect, quitChrome: { identity, deadline, dispatch in
            guard inspect(identity) == .same, identity.pid != getpid(),
                  let app = NSRunningApplication(processIdentifier: identity.pid), !app.isTerminated,
                  app.bundleIdentifier == "com.google.Chrome" else { throw MigrationUpgradeError.invalidPreparation }
            guard Date() < deadline else { throw MigrationUpgradeError.recoveryRequired }
            try dispatch()
            return app.terminate()
        }, wait: { Thread.sleep(forTimeInterval: $0) }, requireStopped: { paths in try MigrationObserverOS.requireStopped(Array(Set(paths + (canonicalChrome.map { [$0] } ?? [])))) },
        console: { try MigrationObserverOS.consoleIdentity(consoleRequirement, consoleBirth) })
    }
}

/// A single-use stage. No cleanup path resubmits a quit/stop or restarts anything.
/// Missing canonical lifecycle wiring refuses before inhibiting work or quitting.
public final class MigrationRuntimeShutdown {
    private let lock = NSLock()
    private let broker: MigrationShutdownIdentity, chrome: MigrationShutdownIdentity
    private let helperPins: [String: String]
    private let capturedAt: Date, intentBinding: String
    private let route: (any MigrationBrokerLifecycleRoute)?
    private let runtime: MigrationShutdownRuntime
    private var consumed = false, cancelled = false, changed = false
    public var mayHaveChanged: Bool { lock.lock(); defer { lock.unlock() }; return changed }
    init(intentBinding: String, broker: MigrationShutdownIdentity, chrome: MigrationShutdownIdentity,
         helperPins: [String: String], capturedAt: Date, route: (any MigrationBrokerLifecycleRoute)?, runtime: MigrationShutdownRuntime) throws {
        guard MigrationAuthorizationRecord.digest(intentBinding), broker.pid > 0, chrome.pid > 0,
              broker.pid != chrome.pid, broker.pid != getpid(), chrome.pid != getpid(), broker.uid == getuid(), chrome.uid == getuid(),
              [broker, chrome].allSatisfy({ MigrationExactBrokerPeer.validStart($0.birth) && MigrationRuntimeConsoleManifest.path($0.executable) && !$0.requirement.isEmpty }),
              !helperPins.isEmpty, helperPins.count <= 4, helperPins.keys.allSatisfy(MigrationRuntimeConsoleManifest.path),
              !helperPins.keys.contains(broker.executable), !helperPins.keys.contains(chrome.executable) else { throw MigrationUpgradeError.invalidPreparation }
        self.intentBinding=intentBinding;self.broker=broker;self.chrome=chrome;self.helperPins=helperPins
        self.capturedAt=capturedAt;self.route=route;self.runtime=runtime
    }
    public func cancel() { lock.lock(); cancelled = true; lock.unlock() }
    private func check(_ deadline: Date) throws {
        lock.lock(); let stopped = cancelled; lock.unlock()
        guard !stopped, runtime.now() < deadline, capturedAt <= runtime.now() else { throw MigrationUpgradeError.recoveryRequired }
        try runtime.console()
    }
    private func dispatched() { lock.lock(); changed = true; lock.unlock() }
    func quiesce(intentBinding: String, preparationDeadline: Date) throws {
        lock.lock()
        guard !consumed, !cancelled else { lock.unlock(); throw MigrationUpgradeError.consumedIntent }
        consumed = true; lock.unlock()
        guard self.intentBinding == intentBinding, let route else { throw MigrationUpgradeError.unavailable }
        let deadline = min(preparationDeadline, capturedAt.addingTimeInterval(30))
        try check(deadline)
        guard runtime.inspect(broker) == .same, runtime.inspect(chrome) == .same else { throw MigrationUpgradeError.invalidPreparation }
        let helpers = try route.qualify(broker: broker, helperPins: helperPins, deadline: deadline)
        var seen: Set<pid_t> = [broker.pid, chrome.pid, getpid()]
        for helper in helpers {
            guard helper.pid > 0, helper.uid == getuid(), seen.insert(helper.pid).inserted,
                  helperPins[helper.executable] == helper.requirement, runtime.inspect(helper) == .same else { throw MigrationUpgradeError.invalidPreparation }
        }
        try check(deadline)
        // SIGTERM uses the already-installed broker's signal.NotifyContext /
        // Host.Close path. Never infer business cleanup from its exit status.
        try route.stop(deadline: deadline, willDispatch: { try self.check(deadline); self.dispatched() })
        guard mayHaveChanged else { throw MigrationUpgradeError.unavailable }
        try awaitGone(broker, until: min(deadline, runtime.now().addingTimeInterval(15)))
        for helper in helpers where !MigrationAuthorizationRecord.requirement(helper.requirement, role: "chrome.nativehost") {
            try awaitGone(helper, until: deadline)
        }
        try route.verifyStopped(deadline: deadline)
        try check(deadline)
        switch runtime.inspect(chrome) {
        case .same:
            guard try runtime.quitChrome(chrome, deadline, { try self.check(deadline); self.dispatched() }) else { throw MigrationUpgradeError.recoveryRequired }
            try awaitGone(chrome, until: min(deadline, runtime.now().addingTimeInterval(5)))
        case .gone: break
        case .replaced, .unavailable: throw MigrationUpgradeError.recoveryRequired
        }
        for helper in helpers { try awaitGone(helper, until: deadline) }
        try route.verifyStopped(deadline: deadline)
        try check(deadline)
        try runtime.requireStopped(Array(Set([broker.executable, chrome.executable] + Array(helperPins.keys))).sorted())
        try check(deadline)
    }
    private func awaitGone(_ identity: MigrationShutdownIdentity, until deadline: Date) throws {
        for _ in 0..<1200 {
            try check(deadline)
            switch runtime.inspect(identity) {
            case .gone: return
            case .same: runtime.wait(max(0, min(0.025, deadline.timeIntervalSince(runtime.now()))))
            case .replaced, .unavailable: throw MigrationUpgradeError.recoveryRequired
            }
        }
        throw MigrationUpgradeError.recoveryRequired
    }
}

enum MigrationShutdownOS {
    static func inspect(_ expected: MigrationShutdownIdentity) -> MigrationShutdownPresence {
        guard expected.pid > 0, expected.pid != getpid(), expected.uid == getuid() else { return .unavailable }
        if kill(expected.pid, 0) == -1 && errno == ESRCH { return .gone }
        var info = proc_bsdinfo()
        guard proc_pidinfo(expected.pid, PROC_PIDTBSDINFO, 0, &info, Int32(MemoryLayout<proc_bsdinfo>.size)) == MemoryLayout<proc_bsdinfo>.size else { return .unavailable }
        guard info.pbi_pid == UInt32(expected.pid), info.pbi_uid == expected.uid,
              "\(info.pbi_start_tvsec):\(info.pbi_start_tvusec)" == expected.birth else { return .replaced }
        if info.pbi_status == 5 { return .gone }
        var path = [CChar](repeating: 0, count: 4096)
        guard proc_pidpath(expected.pid, &path, UInt32(path.count)) > 0, String(cString: path) == expected.executable else { return .unavailable }
        var code: SecCode?, requirement: SecRequirement?
        guard SecRequirementCreateWithString(expected.requirement as CFString, [], &requirement) == errSecSuccess, let requirement,
              SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributePid: expected.pid] as CFDictionary, [], &code) == errSecSuccess, let code,
              SecCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate), requirement) == errSecSuccess else { return .unavailable }
        var after = proc_bsdinfo()
        guard proc_pidinfo(expected.pid, PROC_PIDTBSDINFO, 0, &after, Int32(MemoryLayout<proc_bsdinfo>.size)) == MemoryLayout<proc_bsdinfo>.size,
              after.pbi_uid == info.pbi_uid, after.pbi_start_tvsec == info.pbi_start_tvsec,
              after.pbi_start_tvusec == info.pbi_start_tvusec else { return .replaced }
        return .same
    }
}
