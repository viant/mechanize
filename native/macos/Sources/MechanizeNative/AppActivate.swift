import AppKit
import Foundation
import Darwin
import MechanizeNativeCore

struct ApplicationInventoryEntry {
    let pid: pid_t
    let bundleID: String?
    let name: String
    let owner: uid_t?
    // Optional Cocoa metadata is descriptive only; birthIdentity is authoritative.
    let launchTime: String?
    let startToken: String?
    let active: Bool
    let terminated: Bool
    var birthIdentity: String? { applicationKernelLaunchIdentity(startToken) }
}
struct ApplicationControlRuntime {
    let list: (String?) -> [ApplicationInventoryEntry]
    let activate: (ApplicationInventoryEntry) -> Bool
    // Read-only confirmation and wait seams; request JSON cannot provide either.
    let foreground: (ApplicationInventoryEntry, Budget) throws -> Bool
    let wait: (TimeInterval) -> Void
    init(list: @escaping (String?) -> [ApplicationInventoryEntry],
         activate: @escaping (ApplicationInventoryEntry) -> Bool,
         foreground: @escaping (ApplicationInventoryEntry, Budget) throws -> Bool = { identity, budget in
             _ = try qualifiedForeground(ForegroundIdentity(pid: identity.pid, uid: identity.owner,
                 birth: identity.startToken, bundle: identity.bundleID, active: true), budget)
             return true
         }, wait: @escaping (TimeInterval) -> Void = { Thread.sleep(forTimeInterval: $0) }) {
        self.list = list; self.activate = activate; self.foreground = foreground; self.wait = wait
    }
    static let system = ApplicationControlRuntime(list: { expected in
        let apps = expected.map { NSRunningApplication.runningApplications(withBundleIdentifier: $0) } ?? NSWorkspace.shared.runningApplications
        return apps.filter { $0.bundleIdentifier != nil }.map { app in
            let token = applicationProcessStartToken(app.processIdentifier)
            return ApplicationInventoryEntry(pid: app.processIdentifier, bundleID: app.bundleIdentifier, name: app.localizedName ?? "", owner: applicationLoginUID(app.processIdentifier), launchTime: app.launchDate.map { ISO8601DateFormatter().string(from: $0) }, startToken: token, active: app.isActive, terminated: app.isTerminated)
        }
    }, activate: { identity in
        guard let expectedBirth = identity.birthIdentity, let expectedToken = identity.startToken,
              let app = NSRunningApplication(processIdentifier: identity.pid), app.bundleIdentifier == identity.bundleID,
              applicationLoginUID(identity.pid) == getuid(), let token = applicationProcessStartToken(identity.pid), token == expectedToken,
              applicationKernelLaunchIdentity(token) == expectedBirth, !app.isTerminated else { return false }
        // LaunchServices can bring an existing app forward from an automation
        // helper. NSRunningApplication.activate alone may leave it in the
        // background on current macOS. Never request another instance, accept
        // caller paths/arguments, or treat this submission as foreground proof.
        guard let url = app.bundleURL, url.isFileURL,
              Bundle(url: url)?.bundleIdentifier == identity.bundleID else { return false }
        let configuration = NSWorkspace.OpenConfiguration()
        configuration.activates = true
        configuration.createsNewApplicationInstance = false
        configuration.addsToRecentItems = false
        configuration.promptsUserIfNeeded = false
        NSWorkspace.shared.openApplication(at: url, configuration: configuration) { _, _ in }
        return true
    })
}
func applicationInventory(_ params: [String: Any], runtime: ApplicationControlRuntime = .system, uid: uid_t = getuid()) throws -> [String: Any] {
    guard Set(params.keys).isSubset(of: ["expectedApp"]) else { throw NativeFailure("invalidApplication", "Only exact expectedApp scope is accepted") }
    let expected = params["expectedApp"] as? String
    if !params.isEmpty && (expected == nil || expected!.range(of: #"^[A-Za-z0-9][A-Za-z0-9-]*(\.[A-Za-z0-9][A-Za-z0-9-]*)+$"#, options: .regularExpression) == nil || expected!.utf8.count > 255) { throw NativeFailure("invalidApplication", "Exact bundle identifier required") }
    let inventory = runtime.list(expected)
    let complete = inventory.count <= 512 && inventory.allSatisfy { app in
        guard let owner = app.owner else { return false }
        if owner != uid { return true }
        return app.pid > 0 && app.bundleID != nil && (expected == nil || app.bundleID == expected) && app.birthIdentity != nil && app.startToken?.isEmpty == false && !app.terminated
    }
    let applications = inventory.filter { $0.owner == uid && $0.startToken?.isEmpty == false && $0.birthIdentity != nil && !$0.terminated }
    return ["apps": applications.prefix(512).map { app in ["pid": app.pid, "bundleID": app.bundleID ?? "", "name": app.name, "launchTime": app.birthIdentity ?? "", "startToken": app.startToken ?? "", "active": app.active] as [String: Any] }, "complete": complete, "scope": "currentLoginUser", "otherUsersSupported": false]
}
func activateApplication(_ params: [String: Any], _ budget: Budget, runtime: ApplicationControlRuntime = .system, uid: uid_t = getuid(), willDispatch: () throws -> Void) throws -> ApplicationLaunchReply {
    guard Set(params.keys) == Set(["expectedApp", "pid", "launchTime", "startToken"]), let bundle = params["expectedApp"] as? String,
          let pid = params["pid"] as? Int, pid > 0, pid <= Int(Int32.max), let launch = params["launchTime"] as? String,
          let token = params["startToken"] as? String, applicationKernelLaunchIdentity(token) == launch else { throw NativeFailure("invalidApplication", "Activation requires exact current application identity") }
    try budget.check()
    let listed = runtime.list(bundle)
    let inventory = try applicationInventory(["expectedApp": bundle], runtime: ApplicationControlRuntime(list: { _ in listed }, activate: runtime.activate), uid: uid)
    let entries = listed.filter { $0.owner == uid && $0.bundleID == bundle && $0.pid == pid && $0.birthIdentity == launch && $0.startToken == token && !$0.terminated }
    guard inventory["complete"] as? Bool == true, entries.count == 1, let app = entries.first,
          app.bundleID == bundle, app.pid == pid, app.birthIdentity == launch, app.startToken == token, !app.terminated else { throw NativeFailure("staleReference", "Exact existing application identity is absent or ambiguous") }
    try budget.check(); try willDispatch()
    guard runtime.activate(app) else { return ApplicationLaunchReply(dispatchState: "unknown", result: [:], failure: NativeFailure("activationOutcomeUnknown", "Activation returned without proof; reconcile before replay")) }
    let result: [String: Any] = ["bundleID": bundle, "pid": pid, "launchTime": launch,
        "startToken": token, "activationRequested": true, "businessSuccess": false]
    // Acceptance is not foreground proof. Observe for at most one second without
    // resubmitting activation or sending keyboard/pointer input. Every failure
    // after submission retains the uncertain effect, including deadline expiry.
    do {
        try budget.check()
        let confirmationBudget = try Budget(milliseconds: max(1, min(1000, Int(budget.remainingSeconds * 1000))))
        for _ in 0..<40 {
            try budget.check(); try confirmationBudget.check()
            do {
                if try runtime.foreground(app, confirmationBudget) {
                    try budget.check(); try confirmationBudget.check()
                    var confirmed = result
                    confirmed["foregroundConfirmed"] = true
                    confirmed["active"] = true
                    return ApplicationLaunchReply(dispatchState: "dispatched", result: confirmed, failure: nil)
                }
            } catch let failure as NativeFailure {
                guard ["foregroundChanged", "foregroundNotActive", "foregroundUnavailable"].contains(failure.code) else { throw failure }
            }
            try budget.check(); try confirmationBudget.check()
            runtime.wait(min(0.025, Double(min(budget.remainingSeconds, confirmationBudget.remainingSeconds))))
        }
    } catch {
        // Deliberately withhold provider details and retain post-dispatch state.
    }
    return ApplicationLaunchReply(dispatchState: "unknown", result: result,
        failure: NativeFailure("activationPostconditionUnknown", "Requested activation lacks exact foreground confirmation within its bounded observation interval; reconcile before replay"))
}
