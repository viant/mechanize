import AppKit
import Carbon
import ApplicationServices
import MechanizeNativeCore

struct SessionKeyWindow {
    let id: UInt32
    let pid: pid_t
    let layer: Int
    let visible: Bool
    let alpha: Double
    let bounds: CGRect
}
struct SessionKeyForegroundSample {
    let pid: pid_t
    let bundle: String?
    let active: Bool
}
struct WindowSessionKeyRuntime {
    let process: (pid_t) -> (uid_t, String, String)?
    let foreground: () -> pid_t?
    let windows: () -> [SessionKeyWindow]?
    let session: () -> Bool
    let secure: () -> Bool
    var refresh: () throws -> Void = {}
    var foregroundSample: (() -> SessionKeyForegroundSample?)? = nil
    static let system = WindowSessionKeyRuntime(process: { pid in
        guard let uid = applicationLoginUID(pid), let birth = applicationProcessStartToken(pid), let bundle = NSRunningApplication(processIdentifier: pid)?.bundleIdentifier else { return nil }
        return (uid, birth, bundle)
    }, foreground: { guard let app = NSWorkspace.shared.frontmostApplication, app.isActive else { return nil }; return app.processIdentifier }, windows: {
        guard let raw = CGWindowListCopyWindowInfo([.optionOnScreenOnly, .excludeDesktopElements], kCGNullWindowID) as? [[String: Any]], raw.count <= 1000 else { return nil }
        var result: [SessionKeyWindow] = []
        for row in raw {
            guard let id = row[kCGWindowNumber as String] as? UInt32, let pid = row[kCGWindowOwnerPID as String] as? Int32,
                  let layer = row[kCGWindowLayer as String] as? Int, let visible = row[kCGWindowIsOnscreen as String] as? Bool,
                  let alpha = row[kCGWindowAlpha as String] as? Double, let rawBounds = row[kCGWindowBounds as String], CFGetTypeID(rawBounds as CFTypeRef) == CFDictionaryGetTypeID() else { return nil }
            var bounds = CGRect.zero
            guard CGRectMakeWithDictionaryRepresentation(rawBounds as! CFDictionary, &bounds) else { return nil }
            result.append(SessionKeyWindow(id: id, pid: pid, layer: layer, visible: visible, alpha: alpha, bounds: bounds))
        }
        return result
    }, session: sessionKeyReleaseAllowed, secure: IsSecureEventInputEnabled, refresh: {
        // Cocoa foreground properties update through its run loop. This
        // bounded read-only refresh does not activate an app. The caller's
        // original deadline is checked again before any input can be posted.
        try refreshForegroundNotifications(Budget(milliseconds: 50))
    }, foregroundSample: {
        guard let app = NSWorkspace.shared.frontmostApplication else { return nil }
        return SessionKeyForegroundSample(pid: app.processIdentifier, bundle: app.bundleIdentifier, active: app.isActive)
    })
}
func supportedSessionInputWindowLayer(_ layer: Int) -> Bool {
    [NSWindow.Level.normal.rawValue, NSWindow.Level.floating.rawValue, NSWindow.Level.modalPanel.rawValue].contains(layer)
}

func qualifyWindowSessionKey(pid: pid_t, uid: uid_t, birth: String, bundle: String, windowID: UInt32, check: () throws -> Void,
                             runtime: WindowSessionKeyRuntime = .system) throws {
    try qualifySessionWindow(pid: pid, uid: uid, birth: birth, bundle: bundle, windowID: windowID,
                             requireForeground: true, check: check, runtime: runtime)
}

// Pointer delivery is qualified separately by the exact mouse-down recipient.
// A background window can receive a normal click; keyboard delivery cannot.
func qualifyWindowFrameTarget(pid: pid_t, uid: uid_t, birth: String, bundle: String, windowID: UInt32,
                             check: () throws -> Void, runtime: WindowSessionKeyRuntime = .system) throws {
    try qualifySessionWindow(pid: pid, uid: uid, birth: birth, bundle: bundle, windowID: windowID,
                             requireForeground: false, check: check, runtime: runtime)
}

private func qualifySessionWindow(pid: pid_t, uid: uid_t, birth: String, bundle: String, windowID: UInt32,
                                  requireForeground: Bool, check: () throws -> Void, runtime: WindowSessionKeyRuntime) throws {
    try check()
    guard pid > 0, windowID > 0, let identity = runtime.process(pid), identity.0 == uid, identity.1 == birth, identity.2 == bundle else { throw NativeFailure("staleReference", "Exact window process identity changed") }
    guard runtime.session(), !runtime.secure() else { throw NativeFailure("sessionUnqualified", "Current console event permission and nonsecure session required") }
    try runtime.refresh(); try check()
    if requireForeground { try requireSessionKeyForeground(pid: pid, phase: "initial", runtime: runtime) }
    guard let windows = runtime.windows() else { throw NativeFailure("windowKeyboardUnqualified", "Visible window inventory is unavailable or contains incomplete metadata") }
    guard windows.count <= 1000 else { throw NativeFailure("windowKeyboardUnqualified", "Visible window inventory exceeds the bounded inspection limit") }
    // The highest owned visible window governs session-key routing. Frame capture
    // selects its exact requested window; pointer posting independently proves the
    // actual mouse-down recipient, including overlays and modal interception.
    let owned = windows.filter { $0.pid == pid && $0.visible && $0.alpha != 0 }
    let requestedLayer = windows.first(where: { $0.id == windowID })?.layer ?? -1
    let topID = owned.first?.id ?? 0
    let candidate = requireForeground ? owned.first : owned.first(where: { $0.id == windowID })
    let higherOwnedInputWindow = owned.prefix(while: { $0.id != windowID }).contains(where: { supportedSessionInputWindowLayer($0.layer) })
    guard (requireForeground || !higherOwnedInputWindow), owned.allSatisfy({ $0.alpha.isFinite && $0.alpha > 0 && $0.alpha <= 1 }), let first = candidate, first.id == windowID, supportedSessionInputWindowLayer(first.layer), windows.filter({ $0.id == windowID }).count == 1,
          first.bounds.minX.isFinite, first.bounds.minY.isFinite, first.bounds.maxX.isFinite, first.bounds.maxY.isFinite,
          first.bounds.width > 0, first.bounds.height > 0 else { throw NativeFailure("windowKeyboardUnqualified", "Requested window is not a supported top owned window (requestedLayer=\(requestedLayer), topWindowId=\(topID))") }
    try runtime.refresh(); try check()
    guard let after = runtime.process(pid), after.0 == uid, after.1 == birth, after.2 == bundle else { throw NativeFailure("windowKeyboardUnqualified", "Window keyboard qualification changed") }
    if requireForeground { try requireSessionKeyForeground(pid: pid, phase: "final", runtime: runtime) }
    guard runtime.session(), !runtime.secure() else { throw NativeFailure("windowKeyboardUnqualified", "Window keyboard qualification changed") }
    try check()
}

// The same sample decides admission and describes refusal. Diagnostic inventory
// never substitutes for foreground authority or changes the requested target.
private func requireSessionKeyForeground(pid: pid_t, phase: String, runtime: WindowSessionKeyRuntime) throws {
    let sample: SessionKeyForegroundSample?
    if let read = runtime.foregroundSample { sample = read() }
    else if let observed = runtime.foreground() {
        sample = SessionKeyForegroundSample(pid: observed, bundle: nil, active: true)
    } else { sample = nil }
    if let sample, sample.active && sample.pid == pid { return }
    let reason = sample == nil ? "unavailable" : (sample!.active ? "mismatch" : "inactive")
    let rawBundle = sample?.bundle ?? ""
    let bundle = rawBundle.utf8.count <= 255 && rawBundle.range(of: #"^[A-Za-z0-9][A-Za-z0-9-]*(\.[A-Za-z0-9][A-Za-z0-9-]*)+$"#, options: .regularExpression) != nil ? rawBundle : "unavailable"
    let rows = runtime.windows()
    let layers = [NSWindow.Level.normal.rawValue, NSWindow.Level.floating.rawValue, NSWindow.Level.modalPanel.rawValue]
    let top = (rows?.count ?? 1001) <= 1000 ? rows?.first(where: {
        $0.id > 0 && $0.pid > 0 && $0.visible && $0.alpha.isFinite && $0.alpha > 0 && $0.alpha <= 1 && layers.contains($0.layer) &&
        $0.bounds.minX.isFinite && $0.bounds.minY.isFinite && $0.bounds.maxX.isFinite && $0.bounds.maxY.isFinite && $0.bounds.width > 0 && $0.bounds.height > 0
    }) : nil
    throw NativeFailure("windowKeyboardUnqualified", "Foreground qualification failed (phase=\(phase), reason=\(reason), foregroundPid=\(max(0, sample?.pid ?? 0)), foregroundBundle=\(bundle), foregroundActive=\(sample.map { $0.active ? "true" : "false" } ?? "unavailable"), frontWindowId=\(top?.id ?? 0), frontWindowPid=\(top?.pid ?? 0))")
}
