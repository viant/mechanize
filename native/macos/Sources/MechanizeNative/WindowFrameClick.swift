import AppKit
import Carbon
import ApplicationServices
import MechanizeNativeCore

struct WindowFrameClickRuntime {
    let window: WindowSessionKeyRuntime
    let display: (UInt32) -> CGRect?
    static let system = WindowFrameClickRuntime(window: .system, display: { id in
        guard CGDisplayIsActive(id) != 0 else { return nil }; return CGDisplayBounds(id)
    })
}

// The point must hit the requested window before every down. Unlike keyboard
// routing, windows from any process may occlude a global pointer location.
func qualifyWindowFramePoint(_ permit: WindowFramePermit, point: CGPoint, uid: uid_t, check: () throws -> Void,
                             runtime: WindowFrameClickRuntime = .system) throws {
    try qualifyWindowSessionKey(pid: permit.pid, uid: uid, birth: permit.processStartToken, bundle: permit.bundleId,
                                windowID: permit.windowId, check: check, runtime: runtime.window)
    guard let display = runtime.display(permit.displayId), display.contains(permit.bounds), permit.bounds.contains(point),
          let rows = runtime.window.windows(), rows.count <= 1000 else { throw NativeFailure("windowClickUnqualified", "Current captured window/display mapping unavailable") }
    // Malformed metadata anywhere in the visible inventory could conceal an
    // occluder. Even a fully transparent on-screen foreign window blocks:
    // CG metadata does not attest its mouse hit-testing policy.
    guard rows.filter({ $0.visible }).allSatisfy({ $0.alpha.isFinite && $0.alpha >= 0 && $0.alpha <= 1 && $0.bounds.width > 0 && $0.bounds.height > 0 &&
        [$0.bounds.minX, $0.bounds.minY, $0.bounds.width, $0.bounds.height, $0.bounds.maxX, $0.bounds.maxY].allSatisfy { $0.isFinite } }) else {
        throw NativeFailure("windowClickUnqualified", "Visible window inventory has uncertain point ownership")
    }
    let relevant = rows.filter { $0.visible && $0.bounds.contains(point) }
    guard let first = relevant.first, first.id == permit.windowId, first.pid == permit.pid, first.alpha == 1, first.bounds == permit.bounds,
          rows.filter({ $0.id == permit.windowId }).count == 1 else { throw NativeFailure("windowClickOccluded", "Captured point is occluded or window geometry changed") }
    try check()
    guard let after = runtime.window.process(permit.pid), after.0 == uid, after.1 == permit.processStartToken,
          after.2 == permit.bundleId, runtime.window.foreground() == permit.pid, runtime.window.session(), !runtime.window.secure() else {
        throw NativeFailure("windowClickUnqualified", "Pointer qualification changed before posting")
    }
}

func postWindowFrameClick(inputs: InputSafety, point: CGPoint, preflight: () throws -> Void, willPost: () -> Void,
                          down: (() -> Bool)? = nil, up: (() -> Bool)? = nil) throws {
    let marker: Int64 = 0x4d454348
    let postDown: () -> Bool
    let postUp: () -> Bool
    if let down, let up { postDown = down; postUp = up }
    else {
        guard let down = CGEvent(mouseEventSource: nil, mouseType: .leftMouseDown, mouseCursorPosition: point, mouseButton: .left),
              let up = CGEvent(mouseEventSource: nil, mouseType: .leftMouseUp, mouseCursorPosition: point, mouseButton: .left) else {
            throw NativeFailure("eventUnavailable", "Window click events unavailable")
        }
        down.setIntegerValueField(.eventSourceUserData, value: marker); up.setIntegerValueField(.eventSourceUserData, value: marker)
        postDown = { down.post(tap: .cgSessionEventTap); return true }
        // Release does not re-target/retry a down if the click destroys a dialog.
        postUp = { guard sessionKeyReleaseAllowed() else { return false }; up.post(tap: .cgSessionEventTap); return true }
    }
    try inputs.press(token: "mouse:left", preflight: preflight, down: { willPost(); return postDown() }, up: postUp)
}
