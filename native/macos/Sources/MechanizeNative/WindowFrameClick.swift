import AppKit
import Carbon
import ApplicationServices
import MechanizeNativeCore

struct WindowFrameClickRuntime {
    let window: WindowSessionKeyRuntime
    let display: (UInt32) -> CGRect?
    var diagnostic: (WindowFramePermit, CGPoint) -> String = { _, _ in "" }
    var mouseDownWindow: ((CGPoint) throws -> UInt32?)?
    static let system = WindowFrameClickRuntime(window: .system, display: { id in
        guard CGDisplayIsActive(id) != 0 else { return nil }; return CGDisplayBounds(id)
    }, diagnostic: windowPointDiagnostic, mouseDownWindow: mouseDownWindowAtPoint)
}

// Capture selects an exact window, not a desktop point. An unrelated overlay
// at its center does not invalidate pixels elsewhere. No click authority is
// inferred here: qualifyWindowFramePoint still runs for the requested point.
func qualifyWindowFrameCapture(_ permit: WindowFramePermit, uid: uid_t, check: () throws -> Void,
                               runtime: WindowFrameClickRuntime = .system) throws {
    try qualifyWindowFrameTarget(pid: permit.pid, uid: uid, birth: permit.processStartToken, bundle: permit.bundleId,
                                windowID: permit.windowId, check: check, runtime: runtime.window)
    guard let display = runtime.display(permit.displayId), display.contains(permit.bounds),
          let rows = runtime.window.windows(), rows.count <= 1000 else {
        throw NativeFailure("windowCaptureUnqualified", "Exact captured window/display mapping unavailable")
    }
    let matches = rows.filter { $0.id == permit.windowId }
    guard matches.count == 1, let target = matches.first, target.pid == permit.pid,
          target.visible, target.alpha == 1, target.bounds == permit.bounds else {
        throw NativeFailure("staleCapture", "Captured window identity or geometry changed")
    }
    try check()
}

// The point must hit the requested window before every down. Unlike keyboard
// routing, windows from any process may occlude a global pointer location.
func qualifyWindowFramePoint(_ permit: WindowFramePermit, point: CGPoint, uid: uid_t, check: () throws -> Void,
                             runtime: WindowFrameClickRuntime = .system) throws {
    try qualifyWindowFrameTarget(pid: permit.pid, uid: uid, birth: permit.processStartToken, bundle: permit.bundleId,
                                windowID: permit.windowId, check: check, runtime: runtime.window)
    guard let display = runtime.display(permit.displayId), display.contains(permit.bounds), permit.bounds.contains(point),
          let rows = runtime.window.windows(), rows.count <= 1000 else { throw NativeFailure("windowClickUnqualified", "Current captured window/display mapping unavailable") }
    // Malformed metadata could conceal an occluder. Pixels and window alpha do
    // not establish hit-testing policy; the public mouse-down query below does.
    guard rows.filter({ $0.visible }).allSatisfy({ $0.alpha.isFinite && $0.alpha >= 0 && $0.alpha <= 1 && $0.bounds.width > 0 && $0.bounds.height > 0 &&
        [$0.bounds.minX, $0.bounds.minY, $0.bounds.width, $0.bounds.height, $0.bounds.maxX, $0.bounds.maxY].allSatisfy { $0.isFinite } }) else {
        throw NativeFailure("windowClickUnqualified", "Visible window inventory has uncertain point ownership")
    }
    let relevant = rows.filter { $0.visible && $0.bounds.contains(point) }
    let targets = rows.filter { $0.id == permit.windowId }
    let owned = targets.count == 1 && targets[0].visible && targets[0].pid == permit.pid && targets[0].alpha == 1 && targets[0].bounds == permit.bounds
    let hitMatches: Bool
    let recipient: UInt32?
    if let mouseDownWindow = runtime.mouseDownWindow {
        try check()
        guard let hit = try mouseDownWindow(point) else {
            throw NativeFailure("windowHitTestUnavailable", "Mouse-down recipient window unavailable")
        }
        try check()
        recipient = hit
        hitMatches = hit == permit.windowId
    } else {
        // Conservative injected-runtime path. Production always supplies the
        // public query; neither caller JSON nor diagnostics can disable it.
        recipient = relevant.first?.id
        hitMatches = recipient == permit.windowId
    }
    guard owned, hitMatches else {
        // IDs and geometry only: no titles, document text or credentials. Use
        // this same inventory rather than a second query that could describe
        // a different stacking order. Diagnostics never authorize input.
        let blocker = relevant.first.map {
            "boundingBoxFrontWindowId=\($0.id); boundingBoxFrontOwnerPid=\($0.pid); boundingBoxFrontLayer=\($0.layer); boundingBoxFrontAlpha=\($0.alpha); boundingBoxFrontBounds=\($0.bounds)"
        } ?? "boundingBoxFrontWindow=unavailable"
        let recipientRows = rows.filter { $0.id == recipient }
        let recipientInfo = recipientRows.count == 1 ? "mouseDownOwnerPid=\(recipientRows[0].pid); mouseDownLayer=\(recipientRows[0].layer)" : "mouseDownOwner=unavailable"
        let queried = "mouseDownWindowId=\(recipient ?? 0); \(recipientInfo); ownedMatches=\(owned); hitMatches=\(hitMatches); clickPoint=\(point); capturedWindowId=\(permit.windowId)"
        let diagnostic = queried + "; " + blocker + "; " + runtime.diagnostic(permit, point)
        try check()
        throw NativeFailure("windowClickOccluded", "Captured point is occluded or window geometry changed" +
                            (diagnostic.isEmpty ? "" : "; " + diagnostic))
    }
    try check()
    guard let after = runtime.window.process(permit.pid), after.0 == uid, after.1 == permit.processStartToken,
          after.2 == permit.bundleId, runtime.window.session(), !runtime.window.secure() else {
        throw NativeFailure("windowClickUnqualified", "Pointer qualification changed before posting")
    }
}

func postWindowFrameClick(inputs: InputSafety, point: CGPoint, preflight: @escaping () throws -> Void, willPost: @escaping () -> Void,
                          down: (() -> Bool)? = nil, up: (() -> Bool)? = nil, move: (() throws -> Void)? = nil) throws {
    let postDown: () -> Bool
    let postUp: () -> Bool
    let qualifiedPreflight: () throws -> Void
    if let down, let up {
        qualifiedPreflight = {
            try preflight()
            if let move { try move(); try preflight() }
        }
        postDown = { willPost(); return down() }
        postUp = up
    } else {
        // Movement and refreshed recipient checks stay under InputSafety's lock,
        // before registering an uncertain held-button release. A timeout here
        // cannot claim mouse-down dispatch or leave a held button behind.
        qualifiedPreflight = {
            try preflight()
            try RobotGoPointer.move(to: point)
            try preflight()
        }
        postDown = { willPost(); return RobotGoPointer.down(at: point) }
        // Release never re-targets/retries a down after a click destroys a dialog.
        postUp = { guard sessionKeyReleaseAllowed() else { return false }; return RobotGoPointer.up() }
    }
    try inputs.press(token: "mouse:left", preflight: qualifiedPreflight, down: postDown, up: postUp)
}
