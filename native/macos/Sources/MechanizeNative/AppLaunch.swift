import AppKit
import Foundation
import Darwin
import MechanizeNativeCore

struct ApplicationLaunchReply {
    let dispatchState: String
    let result: [String: Any]
    let failure: NativeFailure?
}

/// A timeout is an observation boundary, never a cancellation/replay promise:
/// LaunchServices can finish an already submitted launch after this helper exits.
private final class ApplicationLaunchCompletion {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<ApplicationLaunchReply, Never>?
    init(_ continuation: CheckedContinuation<ApplicationLaunchReply, Never>) { self.continuation = continuation }
    func finish(_ reply: ApplicationLaunchReply) {
        lock.lock()
        let pending = continuation
        continuation = nil
        lock.unlock()
        pending?.resume(returning: reply)
    }
}

struct ApplicationLaunchIdentity {
    let bundleID: String?
    let applicationURL: URL?
    let pid: pid_t
    let launchDate: Date?
    let startToken: String?
    let active: Bool
    let terminated: Bool
}

// This seam is internal to the signed helper. Request JSON cannot choose paths,
// providers, callbacks or launch options; fixtures can exercise the real boundary
// without starting an application on the employee's desktop.
struct ApplicationLaunchRuntime {
    let resolve: (String) -> URL?
    let bundleIdentifier: (URL) -> String?
    let open: (URL, NSWorkspace.OpenConfiguration, @escaping (ApplicationLaunchIdentity?, Error?) -> Void) -> Void
    static let system = ApplicationLaunchRuntime(
        resolve: { NSWorkspace.shared.urlForApplication(withBundleIdentifier: $0) },
        bundleIdentifier: { Bundle(url: $0)?.bundleIdentifier },
        open: { url, configuration, callback in
            NSWorkspace.shared.openApplication(at: url, configuration: configuration) { app, error in
                let identity = app.map { ApplicationLaunchIdentity(bundleID: $0.bundleIdentifier, applicationURL: $0.bundleURL, pid: $0.processIdentifier, launchDate: $0.launchDate, startToken: applicationProcessStartToken($0.processIdentifier), active: $0.isActive, terminated: $0.isTerminated) }
                callback(identity, error)
            }
        }
    )
}

func launchApplication(_ params: [String: Any], _ budget: Budget, runtime: ApplicationLaunchRuntime = .system, willDispatch: () throws -> Void) async throws -> ApplicationLaunchReply {
    guard Set(params.keys) == Set(["expectedApp"]), let bundleID = params["expectedApp"] as? String,
          bundleID.utf8.count <= 255, bundleID.range(of: #"^[A-Za-z0-9][A-Za-z0-9-]*(\.[A-Za-z0-9][A-Za-z0-9-]*)+$"#, options: .regularExpression) != nil else {
        throw NativeFailure("invalidApplication", "Launch accepts only an exact enrolled bundle identifier")
    }
    try budget.check()
    guard let applicationURL = runtime.resolve(bundleID), applicationURL.isFileURL,
          runtime.bundleIdentifier(applicationURL) == bundleID else {
        throw NativeFailure("applicationNotFound", "Installed application with the exact bundle identifier is unavailable")
    }
    let configuration = NSWorkspace.OpenConfiguration()
    // Lifecycle-only authority can launch an app without taking focus, posting
    // input, supplying documents/arguments or requesting another app instance.
    configuration.activates = false
    configuration.createsNewApplicationInstance = false
    configuration.addsToRecentItems = false
    configuration.promptsUserIfNeeded = false
    try budget.check()
    try willDispatch()
    return await withCheckedContinuation { continuation in
        let completion = ApplicationLaunchCompletion(continuation)
        let timeout = DispatchWorkItem {
            completion.finish(ApplicationLaunchReply(dispatchState: "unknown", result: [:], failure: NativeFailure("launchOutcomeUnknown", "Application launch deadline expired after submission; reconcile before replay")))
        }
        DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + Double(budget.remainingSeconds), execute: timeout)
        runtime.open(applicationURL, configuration) { app, error in
            timeout.cancel()
            guard error == nil, let app, !app.terminated, app.bundleID == bundleID,
                  app.applicationURL?.resolvingSymlinksInPath() == applicationURL.resolvingSymlinksInPath(),
                  app.pid > 0, let startToken = app.startToken, let launchIdentity = applicationKernelLaunchIdentity(startToken) else {
                completion.finish(ApplicationLaunchReply(dispatchState: "unknown", result: [:], failure: NativeFailure("launchOutcomeUnknown", "LaunchServices did not return the exact running application identity; reconcile before replay")))
                return
            }
            let result: [String: Any] = ["bundleID": bundleID, "pid": app.pid, "launchTime": launchIdentity, "startToken": startToken, "active": app.active, "activationRequested": false, "businessSuccess": false]
            completion.finish(ApplicationLaunchReply(dispatchState: "dispatched", result: result, failure: nil))
        }
    }
}

// Public libproc process identity supplements the NSRunningApplication metadata;
// PID reuse cannot satisfy an app-running postcondition with an old receipt.
func applicationProcessStartToken(_ pid: pid_t) -> String? {
    guard pid > 0 else { return nil }
    var info = proc_bsdinfo()
    let size = Int32(MemoryLayout<proc_bsdinfo>.size)
    guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size) == size,
          info.pbi_pid == UInt32(pid), info.pbi_uid == getuid(), info.pbi_status != 5,
          info.pbi_start_tvsec > 0 else { return nil }
    return "\(info.pbi_start_tvsec):\(info.pbi_start_tvusec)"
}

// Canonical, bounded public libproc fingerprint (seconds:microseconds).
func validApplicationProcessStartToken(_ token: String) -> Bool {
    token.utf8.count <= 27 && token.range(of: #"\A[1-9][0-9]{0,19}:(0|[1-9][0-9]{0,5})\z"#, options: .regularExpression) != nil && UInt64(token.split(separator: ":")[0]) != nil
}

// Cocoa launchDate is optional for legitimate directly launched applications.
// Kernel birth identity is canonical and never changes when Cocoa metadata appears.
func applicationKernelLaunchIdentity(_ startToken: String?) -> String? {
    guard let token = startToken, validApplicationProcessStartToken(token) else { return nil }
    return "kernel:\(token)"
}
