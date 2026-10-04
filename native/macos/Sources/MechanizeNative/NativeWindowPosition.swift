import AppKit
import ApplicationServices
import MechanizeNativeCore

struct NativeWindowPositionRuntime {
    let attribute: (AXUIElement, String) -> (AXError, CFTypeRef?)
    let owner: (AXUIElement) -> AXElementOwner
    let settable: (AXUIElement) -> (AXError, Bool)
    let set: (AXUIElement, CGPoint) -> AXError
    static let system = NativeWindowPositionRuntime(attribute: { element, name in
        var value: CFTypeRef?
        let status = AXUIElementCopyAttributeValue(element, name as CFString, &value)
        return (status, value)
    }, owner: { inspectAXElementOwner($0) }, settable: { element in
        var settable: DarwinBoolean = false
        let status = AXUIElementIsAttributeSettable(element, kAXPositionAttribute as CFString, &settable)
        return (status, settable.boolValue)
    }, set: { element, requested in
        var point = requested
        guard let value = AXValueCreate(.cgPoint, &point) else { return .failure }
        return AXUIElementSetAttributeValue(element, kAXPositionAttribute as CFString, value)
    })
}
struct NativeWindowPositionOutcome {
    let dispatchState: String
    let verified: Bool
    let actual: CGPoint?
    let nativeCode: Int32
    let failure: NativeFailure?
    func positionFields(requested: NativeWindowPosition) -> [String: Any]? {
        guard let actual else { return nil }
        if verified, requested.matches(x: Double(actual.x), y: Double(actual.y)) {
            // Exact independent readback already proved these integral values;
            // encode integers for the closed Go wire type, never round a mismatch.
            return ["x": requested.x, "y": requested.y]
        }
        return ["x": Double(actual.x), "y": Double(actual.y)]
    }
}

func positionExactNativeWindow(_ element: AXUIElement, application: AXUIElement, pid: pid_t, uid: uid_t, birth: String, bundle: String,
                              position: NativeWindowPosition, revalidate: () throws -> Void, willSet: () throws -> Void,
                              runtime: NativeWindowPositionRuntime = .system) throws -> NativeWindowPositionOutcome {
    func validateWindow(requireSettable: Bool) throws {
        try revalidate()
        let (roleStatus, role) = runtime.attribute(element, kAXRoleAttribute)
        guard roleStatus == .success, role as? String == kAXWindowRole else { throw NativeFailure("windowScopeRequired", "Exact AXWindow reference required") }
        let owner = runtime.owner(element)
        guard owner.status == AXError.success.rawValue, owner.pid == pid, owner.uid == uid, owner.birth == birth, owner.bundle == bundle else {
            throw NativeFailure("windowOwnerMismatch", "Window owner must remain the exact enrolled application process")
        }
        let (windowsStatus, windowsValue) = runtime.attribute(application, kAXWindowsAttribute)
        guard windowsStatus == .success, let windowsValue, CFGetTypeID(windowsValue) == CFArrayGetTypeID(),
              let windows = windowsValue as? [Any], windows.count <= 1000,
              windows.allSatisfy({ CFGetTypeID($0 as CFTypeRef) == AXUIElementGetTypeID() }),
              windows.filter({ CFEqual($0 as CFTypeRef, element) }).count == 1 else {
            throw NativeFailure("staleReference", "Exact window is absent or ambiguous in the application window list")
        }
        if requireSettable {
            let (status, settable) = runtime.settable(element)
            guard status == .success, settable else { throw NativeFailure("windowPositionUnsupported", "Window AXPosition is not independently settable") }
        }
        try revalidate()
    }
    try validateWindow(requireSettable: true)
    try willSet()
    // Setter is called once. Any failure after this boundary remains unknown,
    // even if a read returns old coordinates or the app clamps the request.
    let code = runtime.set(element, CGPoint(x: position.x, y: position.y))
    var actual: CGPoint?
    do {
        try validateWindow(requireSettable: false)
        let (status, value) = runtime.attribute(element, kAXPositionAttribute)
        if status == .success, let value, CFGetTypeID(value) == AXValueGetTypeID() {
            let ax = value as! AXValue
            var point = CGPoint.zero
            if AXValueGetType(ax) == .cgPoint, AXValueGetValue(ax, .cgPoint, &point), point.x.isFinite, point.y.isFinite { actual = point }
        }
        try validateWindow(requireSettable: false)
        if code == .success, let actual, position.matches(x: Double(actual.x), y: Double(actual.y)) {
            return NativeWindowPositionOutcome(dispatchState: "dispatched", verified: true, actual: actual, nativeCode: code.rawValue, failure: nil)
        }
    } catch { /* A post-write failure cannot prove absence or authorize replay. */ }
    return NativeWindowPositionOutcome(dispatchState: "unknown", verified: false, actual: actual, nativeCode: code.rawValue,
                                       failure: NativeFailure("windowPositionUnconfirmed", "Window position write lacks fresh exact readback; reconcile before another move"))
}
