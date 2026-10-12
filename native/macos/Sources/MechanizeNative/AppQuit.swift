import AppKit
import Darwin
import MechanizeNativeCore

struct ApplicationQuitIdentity {
    let bundle: String
    let pid: pid_t
    let launch: String
    let token: String
    init(_ params: [String: Any]) throws {
        guard Set(params.keys) == Set(["expectedApp", "pid", "launchTime", "startToken"]),
              let bundle = params["expectedApp"] as? String, bundle.utf8.count <= 255,
              bundle.range(of: #"^[A-Za-z0-9][A-Za-z0-9-]*(\.[A-Za-z0-9][A-Za-z0-9-]*)+$"#, options: .regularExpression) != nil,
              let rawPID = params["pid"], CFGetTypeID(rawPID as CFTypeRef) != CFBooleanGetTypeID(),
              let pid = rawPID as? Int, pid > 0, pid <= Int(Int32.max),
              let launch = params["launchTime"] as? String, let token = params["startToken"] as? String,
              applicationKernelLaunchIdentity(token) == launch else {
            throw NativeFailure("invalidApplication", "Quit requires exact existing application identity")
        }
        self.bundle = bundle; self.pid = pid_t(pid); self.launch = launch; self.token = token
    }
    var metadata: [String: Any] { ["bundleID": bundle, "pid": pid, "launchTime": launch, "startToken": token] }
}

// nil means unavailable, never evidence of exit. Signal zero only probes liveness;
// it delivers no signal. A newly born process with a reused PID proves the old
// identity is gone without authorizing any action against the new process.
func applicationProcessExited(_ identity: ApplicationQuitIdentity) -> Bool? {
    if kill(identity.pid, 0) == -1 && errno == ESRCH { return true }
    guard let token = applicationProcessStartToken(identity.pid) else { return nil }
    return token != identity.token
}

struct ApplicationQuitRuntime {
    let list: (String?) -> [ApplicationInventoryEntry]
    let terminate: (ApplicationQuitIdentity, () throws -> Void) throws -> Bool
    let exited: (ApplicationQuitIdentity) -> Bool?
    let wait: (TimeInterval) -> Void
    static let system = ApplicationQuitRuntime(list: ApplicationControlRuntime.system.list, terminate: { identity, willDispatch in
        guard let app = NSRunningApplication(processIdentifier: identity.pid), !app.isTerminated,
              app.bundleIdentifier == identity.bundle, applicationLoginUID(identity.pid) == getuid(),
              applicationProcessStartToken(identity.pid) == identity.token else {
            throw NativeFailure("staleReference", "Quit process identity changed before dispatch")
        }
        try willDispatch()
        return app.terminate()
    }, exited: applicationProcessExited, wait: { Thread.sleep(forTimeInterval: $0) })
}

func applicationExitStatus(_ params: [String: Any], exited: (ApplicationQuitIdentity) -> Bool? = applicationProcessExited) throws -> [String: Any] {
    let identity = try ApplicationQuitIdentity(params)
    var result = identity.metadata
    let status = exited(identity)
    result["exitConfirmed"] = status == true
    result["observationAvailable"] = status != nil
    return result
}

func quitApplication(_ params: [String: Any], _ budget: Budget, runtime: ApplicationQuitRuntime = .system,
                     uid: uid_t = getuid(), willDispatch: () throws -> Void) throws -> ApplicationLaunchReply {
    let identity = try ApplicationQuitIdentity(params)
    try budget.check()
    let listed = runtime.list(identity.bundle)
    let inventory = try applicationInventory(["expectedApp": identity.bundle], runtime: ApplicationControlRuntime(list: { _ in listed }, activate: { _ in false }), uid: uid)
    let matches = listed.filter { $0.owner == uid && $0.bundleID == identity.bundle && $0.pid == identity.pid && $0.startToken == identity.token && $0.birthIdentity == identity.launch && !$0.terminated }
    guard inventory["complete"] as? Bool == true, matches.count == 1 else {
        throw NativeFailure("staleReference", "Exact existing quit target is absent or ambiguous")
    }
    var attempted = false
    var result = identity.metadata
    result["businessSuccess"] = false
    do {
        let accepted = try runtime.terminate(identity) {
            try budget.check(); try willDispatch(); attempted = true
        }
        guard attempted else { throw NativeFailure("quitNotDispatched", "Quit was not submitted") }
        result["quitRequested"] = true
        result["requestAccepted"] = accepted
        // terminate() acceptance alone is not exit proof. Unsaved-document
        // dialogs and rejection remain uncertain; never resubmit or force quit.
        let confirmation = try Budget(milliseconds: max(1, min(5000, Int(budget.remainingSeconds * 1000))))
        for _ in 0..<200 {
            try budget.check(); try confirmation.check()
            if runtime.exited(identity) == true {
                try budget.check(); try confirmation.check()
                result["exitConfirmed"] = true
                return ApplicationLaunchReply(dispatchState: "dispatched", result: result, failure: nil)
            }
            runtime.wait(max(0, min(0.025, Double(min(budget.remainingSeconds, confirmation.remainingSeconds)))))
        }
    } catch {
        if !attempted { throw error }
    }
    result["quitRequested"] = true
    result["exitConfirmed"] = false
    return ApplicationLaunchReply(dispatchState: "unknown", result: result,
        failure: NativeFailure("quitPostconditionUnknown", "Normal quit submitted without confirmed process exit; reconcile before replay"))
}
