import AppKit
import ApplicationServices
import MechanizeNativeCore

struct ScopedNativeRootRuntime {
    let attribute: (AXUIElement, String) -> (AXError, CFTypeRef?)
    let owner: (AXUIElement) -> AXElementOwner
    static let system = ScopedNativeRootRuntime(attribute: { element, name in
        var value: CFTypeRef?
        let status = AXUIElementCopyAttributeValue(element, name as CFString, &value)
        return (status, value)
    }, owner: { inspectAXElementOwner($0) })
}

/// Every descendant reference retains the exact app-scoped root, independently
/// of AXFocused on that descendant. No system-wide lookup or root fallback.
struct ScopedNativeRoot {
    let scope: NativeRootScope?
    let windowScope: NativeWindowScope?
    let element: AXUIElement
    let application: AXUIElement
    let pid: pid_t
    let uid: uid_t
    let birth: String
    let bundle: String

    private static func attributeName(_ scope: NativeRootScope) -> String {
        scope == .menuBar ? kAXMenuBarAttribute : kAXFocusedUIElementAttribute
    }
    static func resolve(_ scope: NativeRootScope, application: AXUIElement, pid: pid_t, uid: uid_t, birth: String, bundle: String,
                        check: () throws -> Void, runtime: ScopedNativeRootRuntime = .system) throws -> ScopedNativeRoot {
        try check()
        let (status, value) = runtime.attribute(application, attributeName(scope))
        try check()
        guard status == .success, let value, CFGetTypeID(value) == AXUIElementGetTypeID() else {
            throw NativeFailure("rootUnavailable", "Requested application native root is unavailable")
        }
        let element = value as! AXUIElement
        AXUIElementSetMessagingTimeout(element, 0.1)
        try validateOwner(element, pid: pid, uid: uid, birth: birth, bundle: bundle, check: check, runtime: runtime)
        if scope == .menuBar {
            let (roleStatus, role) = runtime.attribute(element, kAXRoleAttribute)
            try check()
            guard roleStatus == .success, role as? String == kAXMenuBarRole else {
                throw NativeFailure("rootUnavailable", "Requested application root is not an AXMenuBar")
            }
        }
        return ScopedNativeRoot(scope: scope, windowScope: nil, element: element, application: application, pid: pid, uid: uid, birth: birth, bundle: bundle)
    }
    static func resolveWindow(_ requested: NativeWindowScope, application: AXUIElement, pid: pid_t, uid: uid_t, birth: String, bundle: String,
                              check: () throws -> Void, runtime: ScopedNativeRootRuntime = .system) throws -> ScopedNativeRoot {
        let candidates = try OwnedAXWindows.enumerate(application: application, pid: pid, uid: uid, birth: birth, bundle: bundle, check: check, runtime: runtime)
        var match: AXUIElement?
        for candidate in candidates {
            let (titleStatus, title) = runtime.attribute(candidate, kAXTitleAttribute)
            try check()
            let name: String
            if titleStatus == .noValue || titleStatus == .attributeUnsupported { name = "" }
            else { guard titleStatus == .success, let text = title as? String else { throw NativeFailure("incompleteObservation", "Window title is unavailable") }; name = text }
            if name != requested.title { continue }
            guard match == nil else { throw NativeFailure("ambiguousTarget", "Exact title matches multiple windows") }
            match = candidate
        }
        guard let element = match else { throw NativeFailure("targetNotFound", "Exact window title was not found") }
        return ScopedNativeRoot(scope: nil, windowScope: requested, element: element, application: application, pid: pid, uid: uid, birth: birth, bundle: bundle)
    }
    private func resolveCurrent(check: () throws -> Void, runtime: ScopedNativeRootRuntime) throws -> ScopedNativeRoot {
        if let windowScope { return try Self.resolveWindow(windowScope, application: application, pid: pid, uid: uid, birth: birth, bundle: bundle, check: check, runtime: runtime) }
        guard let scope else { throw NativeFailure("invalidScope", "Native scope unavailable") }
        return try Self.resolve(scope, application: application, pid: pid, uid: uid, birth: birth, bundle: bundle, check: check, runtime: runtime)
    }
    private static func validateOwner(_ element: AXUIElement, pid: pid_t, uid: uid_t, birth: String, bundle: String,
                                      check: () throws -> Void, runtime: ScopedNativeRootRuntime) throws {
        try check()
        let owner = runtime.owner(element)
        try check()
        guard owner.status == AXError.success.rawValue, owner.pid == pid, owner.uid == uid, owner.birth == birth, owner.bundle == bundle else {
            throw NativeFailure("rootOwnerMismatch", "Native root does not belong to the exact enrolled application process")
        }
    }
    private func validateContainment(_ target: AXUIElement, check: () throws -> Void, runtime: ScopedNativeRootRuntime) throws {
        try Self.validateOwner(target, pid: pid, uid: uid, birth: birth, bundle: bundle, check: check, runtime: runtime)
        if CFEqual(target, element) { return }
        var current = target
        var visited = [target]
        // Match the snapshot's depth-20 boundary. Every edge is read fresh;
        // ownership alone never proves membership in this selected subtree.
        for _ in 0..<20 {
            try check()
            AXUIElementSetMessagingTimeout(current, 0.1)
            let (status, value) = runtime.attribute(current, kAXParentAttribute)
            try check()
            guard status == .success, let value, CFGetTypeID(value) == AXUIElementGetTypeID() else {
                throw NativeFailure("staleReference", "Scoped target ancestry is unavailable")
            }
            let parent = value as! AXUIElement
            guard !visited.contains(where: { CFEqual($0, parent) }) else {
                throw NativeFailure("staleReference", "Scoped target ancestry contains a cycle")
            }
            try Self.validateOwner(parent, pid: pid, uid: uid, birth: birth, bundle: bundle, check: check, runtime: runtime)
            if CFEqual(parent, element) { return }
            guard !CFEqual(parent, application) else {
                throw NativeFailure("staleReference", "Target is no longer contained in the selected native root")
            }
            visited.append(parent)
            current = parent
        }
        throw NativeFailure("staleReference", "Scoped target ancestry exceeds the snapshot depth boundary")
    }
    func validate(referenceElement: AXUIElement? = nil, check: () throws -> Void, runtime: ScopedNativeRootRuntime = .system) throws {
        let fresh: ScopedNativeRoot
        do { fresh = try resolveCurrent(check: check, runtime: runtime) }
        catch let failure as NativeFailure {
            guard ["rootUnavailable", "rootOwnerMismatch"].contains(failure.code) else { throw failure }
            throw NativeFailure(scope == .focusedElement ? "staleFocus" : "staleReference", "Application native root is no longer qualified")
        }
        guard CFEqual(element, fresh.element) else {
            throw NativeFailure(scope == .focusedElement ? "staleFocus" : "staleReference", "Application native root changed since the scoped snapshot")
        }
        if let referenceElement {
            try validateContainment(referenceElement, check: check, runtime: runtime)
            // Ancestry reads must not silently adopt a focus/root transition.
            let after = try resolveCurrent(check: check, runtime: runtime)
            guard CFEqual(element, after.element) else {
                throw NativeFailure(scope == .focusedElement ? "staleFocus" : "staleReference", "Application native root changed during containment qualification")
            }
        }
    }
}
