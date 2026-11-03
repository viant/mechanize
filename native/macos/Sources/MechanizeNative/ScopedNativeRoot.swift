import AppKit
import ApplicationServices
import MechanizeNativeCore

struct ScopedNativeRootRuntime {
    let attribute: (AXUIElement, String) -> (AXError, CFTypeRef?)
    let owner: (AXUIElement) -> AXElementOwner
    let children: (AXUIElement, () throws -> Void) throws -> BoundedSnapshotChildRead
    init(attribute: @escaping (AXUIElement, String) -> (AXError, CFTypeRef?),
         owner: @escaping (AXUIElement) -> AXElementOwner,
         children: @escaping (AXUIElement, () throws -> Void) throws -> BoundedSnapshotChildRead = { element, check in
             try boundedSnapshotChildren(element, check: check)
         }) {
        self.attribute = attribute; self.owner = owner; self.children = children
    }
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
    let nativeMenu:String?
    let element: AXUIElement
    let application: AXUIElement
    let pid: pid_t
    let uid: uid_t
    let birth: String
    let bundle: String

    private static func attributeName(_ scope: NativeRootScope) -> String {
        scope == .menuBar ? kAXMenuBarAttribute : kAXFocusedUIElementAttribute
    }
    static func resolve(_ scope: NativeRootScope, application: AXUIElement, pid: pid_t, uid: uid_t, birth: String, bundle: String, nativeMenu:String?=nil,
                        check: () throws -> Void, runtime: ScopedNativeRootRuntime = .system) throws -> ScopedNativeRoot {
        try check()
        let (status, value) = runtime.attribute(application, attributeName(scope))
        try check()
        guard status == .success, let value, CFGetTypeID(value) == AXUIElementGetTypeID() else {
            throw NativeFailure("rootUnavailable", "Requested application native root is unavailable")
        }
        var element = value as! AXUIElement
        AXUIElementSetMessagingTimeout(element, 0.1)
        try validateOwner(element, pid: pid, uid: uid, birth: birth, bundle: bundle, check: check, runtime: runtime)
        if scope == .menuBar {
            let (roleStatus, role) = runtime.attribute(element, kAXRoleAttribute)
            try check()
            guard roleStatus == .success, role as? String == kAXMenuBarRole else {
                throw NativeFailure("rootUnavailable", "Requested application root is not an AXMenuBar")
            }
        }
        if let name=nativeMenu {
            guard scope == .menuBar,!name.trimmingCharacters(in:.whitespacesAndNewlines).isEmpty,name.utf8.count<=256,name.rangeOfCharacter(from:.controlCharacters)==nil else{throw NativeFailure("invalidScope","Exact named menu requires menuBar")}
            let (status,children)=runtime.attribute(element,kAXChildrenAttribute);try check()
            guard status == .success,let candidates=children as? [AXUIElement],candidates.count<=128 else{throw NativeFailure("incompleteObservation","Complete bounded top-level menu census required")}
            var match:AXUIElement?,seen:[AXUIElement]=[]
            for candidate in candidates {
                try check();guard !seen.contains(where:{CFEqual($0,candidate)}) else{throw NativeFailure("incompleteObservation","Duplicate top-level menu identity")};seen.append(candidate)
                AXUIElementSetMessagingTimeout(candidate,0.1)
                try validateOwner(candidate,pid:pid,uid:uid,birth:birth,bundle:bundle,check:check,runtime:runtime)
                let (roleStatus,role)=runtime.attribute(candidate,kAXRoleAttribute);try check()
                let (titleStatus,title)=runtime.attribute(candidate,kAXTitleAttribute);try check()
                guard roleStatus == .success,role as? String==kAXMenuBarItemRole,titleStatus == .success,let title=title as? String,title.utf8.count<=256 else{throw NativeFailure("incompleteObservation","Top-level menu identity unavailable")}
                if title==name {guard match==nil else{throw NativeFailure("ambiguousTarget","Named top-level menu is not unique")};match=candidate}
            }
            guard let match else{throw NativeFailure("targetNotFound","Named top-level menu unavailable")};element=match
        }
        return ScopedNativeRoot(scope: scope, windowScope: nil, nativeMenu:nativeMenu, element: element, application: application, pid: pid, uid: uid, birth: birth, bundle: bundle)
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
        return ScopedNativeRoot(scope: nil, windowScope: requested, nativeMenu:nil, element: element, application: application, pid: pid, uid: uid, birth: birth, bundle: bundle)
    }
    private func resolveCurrent(check: () throws -> Void, runtime: ScopedNativeRootRuntime) throws -> ScopedNativeRoot {
        if let windowScope { return try Self.resolveWindow(windowScope, application: application, pid: pid, uid: uid, birth: birth, bundle: bundle, check: check, runtime: runtime) }
        guard let scope else { throw NativeFailure("invalidScope", "Native scope unavailable") }
        return try Self.resolve(scope, application: application, pid: pid, uid: uid, birth: birth, bundle: bundle, nativeMenu:nativeMenu, check: check, runtime: runtime)
    }
    private static func validateOwner(_ element: AXUIElement, pid: pid_t, uid: uid_t, birth: String, bundle: String,
                                      check: () throws -> Void, runtime: ScopedNativeRootRuntime, stage: String = "root") throws {
        try check()
        let owner = runtime.owner(element)
        try check()
        guard owner.status == AXError.success.rawValue, owner.pid == pid, owner.uid == uid, owner.birth == birth, owner.bundle == bundle else {
            // Closed phase, numeric PIDs/status and equality bits only: never
            // expose accessibility content, titles, paths or credential values.
            let observedPID = owner.pid.map { String($0) } ?? "unavailable"
            throw NativeFailure("rootOwnerMismatch", "Native ownership mismatch (stage=\(stage), expectedPID=\(pid), observedPID=\(observedPID), axStatus=\(owner.status), uidMatch=\(owner.uid == uid), birthMatch=\(owner.birth == birth), bundleMatch=\(owner.bundle == bundle))")
        }
    }
    private func validateContainment(_ target: AXUIElement, check: () throws -> Void, runtime: ScopedNativeRootRuntime) throws {
        try Self.validateOwner(target, pid: pid, uid: uid, birth: birth, bundle: bundle, check: check, runtime: runtime, stage: "target")
        if CFEqual(target, element) { return }
        var current = target
        var visited = [target]
        // Match the snapshot's depth-20 boundary. Every edge is read fresh;
        // ownership alone never proves membership in this selected subtree.
        for depth in 0..<20 {
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
            let parentOwner = runtime.owner(parent)
            if windowScope != nil, parentOwner.status == AXError.success.rawValue,
               let helperPID = parentOwner.pid, helperPID > 0, helperPID != pid, parentOwner.uid == uid,
               parentOwner.birth?.isEmpty == false,
               parentOwner.bundle == "com.apple.appkit.xpc.openAndSavePanelService" {
                // AppKit panels can expose same-app controls through AXChildren
                // while their reverse AXParent crosses the save-panel service.
                // Prove membership using fresh same-app child edges instead;
                // never traverse or authorize input in the helper process.
                _ = try verifiedAttachedSheetPath(target, check: check, runtime: runtime)
                return
            }
            try Self.validateOwner(parent, pid: pid, uid: uid, birth: birth, bundle: bundle, check: check, runtime: runtime, stage: "ancestor-\(depth)")
            if CFEqual(parent, element) { return }
            guard !CFEqual(parent, application) else {
                throw NativeFailure("staleReference", "Target is no longer contained in the selected native root")
            }
            visited.append(parent)
            current = parent
        }
        throw NativeFailure("staleReference", "Scoped target ancestry exceeds the snapshot depth boundary")
    }
    func verifiedAttachedSheetPath(_ target: AXUIElement, check: () throws -> Void, runtime: ScopedNativeRootRuntime) throws -> [AXUIElement] {
        var queue: [(AXUIElement, [AXUIElement], Bool)] = [(element, [], false)]
        var visited: [AXUIElement] = []
        while !queue.isEmpty {
            try check()
            let (node, ancestors, inSheet) = queue.removeFirst()
            guard visited.count < 1000, ancestors.count <= 20,
                  !visited.contains(where: { CFEqual($0, node) }) else {
                throw NativeFailure("staleReference", "Attached-sheet child proof is cyclic, aliased or exceeds bounds")
            }
            visited.append(node)
            try Self.validateOwner(node, pid: pid, uid: uid, birth: birth, bundle: bundle, check: check, runtime: runtime, stage: "sheet-child")
            AXUIElementSetMessagingTimeout(node, 0.1)
            let (status, role) = runtime.attribute(node, kAXRoleAttribute)
            try check()
            guard status == .success, let role = role as? String else { throw NativeFailure("staleReference", "Attached-sheet child role unavailable") }
            let attached = inSheet || role == kAXSheetRole
            if CFEqual(node, target) {
                guard attached else { throw NativeFailure("staleReference", "Target is not within an attached sheet") }
                // Re-read every edge of the chosen path before accepting it.
                let path = ancestors + [node]
                var stillAttached = false
                for (parent, child) in zip(path, path.dropFirst()) {
                    try Self.validateOwner(parent, pid: pid, uid: uid, birth: birth, bundle: bundle, check: check, runtime: runtime, stage: "sheet-path")
                    let (roleStatus, roleValue) = runtime.attribute(parent, kAXRoleAttribute)
                    try check()
                    guard roleStatus == .success, let parentRole = roleValue as? String else { throw NativeFailure("staleReference", "Attached-sheet path role unavailable") }
                    stillAttached = stillAttached || parentRole == kAXSheetRole
                    let children = try runtime.children(parent, check)
                    guard children.complete, children.elements.contains(where: { CFEqual($0, child) }) else { throw NativeFailure("staleReference", "Attached-sheet child path changed") }
                }
                guard stillAttached else { throw NativeFailure("staleReference", "Attached sheet disappeared from child path") }
                try Self.validateOwner(target, pid: pid, uid: uid, birth: birth, bundle: bundle, check: check, runtime: runtime, stage: "target")
                return path
            }
            let children = try runtime.children(node, check)
            guard children.complete, queue.count + visited.count + children.elements.count <= 1000 else { throw NativeFailure("staleReference", "Attached-sheet child census incomplete or exceeds bounds") }
            queue.append(contentsOf: children.elements.map { ($0, ancestors + [node], attached) })
        }
        throw NativeFailure("staleReference", "Target absent from selected window's attached sheet")
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
