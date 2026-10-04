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
struct WindowSessionKeyRuntime {
    let process: (pid_t) -> (uid_t, String, String)?
    let foreground: () -> pid_t?
    let windows: () -> [SessionKeyWindow]?
    let session: () -> Bool
    let secure: () -> Bool
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
    }, session: sessionKeyReleaseAllowed, secure: IsSecureEventInputEnabled)
}
func qualifyWindowSessionKey(pid: pid_t, uid: uid_t, birth: String, bundle: String, windowID: UInt32, check: () throws -> Void,
                             runtime: WindowSessionKeyRuntime = .system) throws {
    try check()
    guard pid > 0, windowID > 0, let identity = runtime.process(pid), identity.0 == uid, identity.1 == birth, identity.2 == bundle else { throw NativeFailure("staleReference", "Exact window process identity changed") }
    guard runtime.session(), !runtime.secure() else { throw NativeFailure("sessionUnqualified", "Current console event permission and nonsecure session required") }
    guard runtime.foreground() == pid, let windows = runtime.windows(), windows.count <= 1000 else { throw NativeFailure("windowKeyboardUnqualified", "Exact foreground and bounded visible window inventory required") }
    // The highest owned visible window governs session-key routing. Never
    // discard a modal/menu first and accidentally target the document beneath it.
    let owned = windows.filter { $0.pid == pid && $0.visible && $0.alpha != 0 }
    let supportedLayers = [NSWindow.Level.normal.rawValue, NSWindow.Level.floating.rawValue, NSWindow.Level.modalPanel.rawValue]
    let requestedLayer = windows.first(where: { $0.id == windowID })?.layer ?? -1
    let topID = owned.first?.id ?? 0
    guard owned.allSatisfy({ $0.alpha.isFinite && $0.alpha > 0 && $0.alpha <= 1 }), let first = owned.first, first.id == windowID, supportedLayers.contains(first.layer), windows.filter({ $0.id == windowID }).count == 1,
          first.bounds.minX.isFinite, first.bounds.minY.isFinite, first.bounds.maxX.isFinite, first.bounds.maxY.isFinite,
          first.bounds.width > 0, first.bounds.height > 0 else { throw NativeFailure("windowKeyboardUnqualified", "Requested window is not a supported top owned window (requestedLayer=\(requestedLayer), topWindowId=\(topID))") }
    try check()
    guard let after = runtime.process(pid), after.0 == uid, after.1 == birth, after.2 == bundle, runtime.foreground() == pid, runtime.session(), !runtime.secure() else { throw NativeFailure("windowKeyboardUnqualified", "Window keyboard qualification changed") }
    try check()
}
