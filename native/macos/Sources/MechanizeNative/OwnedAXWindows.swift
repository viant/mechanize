import AppKit
import ApplicationServices
import MechanizeNativeCore

/// AXWindows may contain Finder's owned AXScrollArea as well as real windows.
/// Classify only after exact owner validation; an unknown role is not absence.
enum OwnedAXWindows {
    static func enumerate(application: AXUIElement, pid: pid_t, uid: uid_t, birth: String, bundle: String,
                          check: () throws -> Void, runtime: ScopedNativeRootRuntime = .system) throws -> [AXUIElement] {
        try check()
        let (status, value) = runtime.attribute(application, kAXWindowsAttribute)
        try check()
        guard status == .success, let candidates = value as? [AXUIElement], candidates.count <= 256 else {
            throw NativeFailure("incompleteObservation", "Complete bounded window enumeration required")
        }
        var windows: [AXUIElement] = []
        for candidate in candidates {
            try check()
            AXUIElementSetMessagingTimeout(candidate, 0.1)
            let owner = runtime.owner(candidate)
            try check()
            guard owner.status == AXError.success.rawValue, owner.pid == pid, owner.uid == uid, owner.birth == birth, owner.bundle == bundle else {
                throw NativeFailure("rootOwnerMismatch", "AXWindows entry does not belong to the exact enrolled application process")
            }
            let (roleStatus, role) = runtime.attribute(candidate, kAXRoleAttribute)
            try check()
            guard roleStatus == .success else { throw NativeFailure("incompleteObservation", "Window candidate role read failed (AX status \(roleStatus.rawValue))") }
            if role as? String == kAXScrollAreaRole { continue }
            guard role as? String == kAXWindowRole else {
                let knownRoles = ["AXApplication", "AXSheet", "AXDialog", "AXUnknown", "AXGroup", "AXMenu"]
                let roleClass = (role as? String).flatMap { knownRoles.contains($0) ? $0 : nil } ?? "other-or-missing"
                throw NativeFailure("incompleteObservation", "Unsupported AXWindows entry (roleClass=\(roleClass))")
            }
            guard !windows.contains(where: { CFEqual($0, candidate) }) else { throw NativeFailure("incompleteObservation", "AXWindows contains duplicate window identities") }
            windows.append(candidate)
        }
        return windows
    }
}
