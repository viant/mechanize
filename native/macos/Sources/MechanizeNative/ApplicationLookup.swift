import AppKit
import Darwin
import MechanizeNativeCore

struct ApplicationLookupRuntime {
    let exited: (ApplicationQuitIdentity) -> Bool?
    let entry: (pid_t) -> ApplicationInventoryEntry?
    static let system = ApplicationLookupRuntime(exited: applicationProcessExited, entry: { pid in
        guard let app = NSRunningApplication(processIdentifier: pid) else { return nil }
        return ApplicationInventoryEntry(pid: pid, bundleID: app.bundleIdentifier,
            name: app.localizedName ?? "", owner: applicationLoginUID(pid),
            launchTime: nil, startToken: applicationProcessStartToken(pid),
            active: app.isActive, terminated: app.isTerminated)
    })
}

/// A pinned process does not require a LaunchServices enumeration to rediscover
/// it. Missing Cocoa metadata is unavailable observation, not evidence of exit.
func exactApplicationInventory(_ params: [String: Any], runtime: ApplicationLookupRuntime = .system,
                               uid: uid_t = getuid()) throws -> [String: Any] {
    let identity = try ApplicationQuitIdentity(params)
    guard let exited = runtime.exited(identity) else {
        throw NativeFailure("incompleteObservation", "Exact process liveness is unavailable")
    }
    if exited { return ["apps": [], "complete": true, "scope": "exactProcess"] }
    guard let app = runtime.entry(identity.pid) else {
        throw NativeFailure("incompleteObservation", "Exact application metadata is unavailable")
    }
    if app.pid != identity.pid || app.owner.map({ $0 != uid }) == true ||
        app.bundleID.map({ !$0.isEmpty && $0 != identity.bundle }) == true ||
        app.startToken.map({ !$0.isEmpty && $0 != identity.token }) == true {
        throw NativeFailure("staleReference", "Exact application identity changed")
    }
    guard let owner = app.owner,
          let bundle = app.bundleID, !bundle.isEmpty, let token = app.startToken, !token.isEmpty,
          let birth = app.birthIdentity else {
        throw NativeFailure("incompleteObservation", "Exact application metadata is unavailable")
    }
    guard app.pid == identity.pid, owner == uid, bundle == identity.bundle,
          token == identity.token, birth == identity.launch else {
        throw NativeFailure("staleReference", "Exact application identity changed")
    }
    guard !app.terminated else {
        throw NativeFailure("incompleteObservation", "Application termination metadata disagrees with live process")
    }
    return ["apps": [["pid": app.pid, "bundleID": bundle, "name": app.name,
                       "launchTime": birth, "startToken": token, "active": app.active]],
            "complete": true, "scope": "exactProcess"]
}

/// Perform the same fresh identity proof as app.lookup within a snapshot RPC.
/// No cached metadata or mutation authority is introduced by this optimization.
func verifyPinnedSnapshotIdentity(_ params: [String: Any], runtime: ApplicationLookupRuntime = .system,
                                  uid: uid_t = getuid()) throws -> Bool {
    guard let requested = params["verifyPinnedIdentity"] else { return false }
    guard let enabled = requested as? Bool, enabled,
          let pid = params["pid"] as? Int32,
          let bundle = params["bundleID"] as? String,
          let token = params["processStartToken"] as? String else {
        throw NativeFailure("invalidScope", "Pinned snapshot requires exact process identity")
    }
    let inventory = try exactApplicationInventory(["pid": Int(pid), "expectedApp": bundle,
        "startToken": token, "launchTime": "kernel:" + token], runtime: runtime, uid: uid)
    guard let apps = inventory["apps"] as? [[String: Any]], apps.count == 1 else {
        throw NativeFailure("staleReference", "Pinned process exited before snapshot")
    }
    return true
}
