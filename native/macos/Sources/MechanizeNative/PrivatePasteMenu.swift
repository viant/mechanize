import ApplicationServices
import MechanizeNativeCore

// Resolve only the standard Command-V action in an exact owned menu tree.
// Labels and field values are neither needed nor returned. No keyboard event,
// application activation or clipboard read is performed here.
func privatePasteMenuItem(application: AXUIElement, check: () throws -> Void,
                          ownerMatches: (AXUIElement) -> Bool,
                          attribute: (AXUIElement, String) -> (AXError, CFTypeRef?)) throws -> AXUIElement {
    func unavailable() -> NativeFailure { NativeFailure("privatePasteMenuUnavailable", "Private paste command could not be verified") }
    try check()
    let (status, value) = attribute(application, kAXMenuBarAttribute)
    guard status == .success, let value, CFGetTypeID(value) == AXUIElementGetTypeID() else { throw unavailable() }
    var queue: [(AXUIElement, Int)] = [(value as! AXUIElement, 0)]
    var seen: [AXUIElement] = [], match: AXUIElement?
    while !queue.isEmpty {
        try check()
        let (node, depth) = queue.removeFirst()
        guard depth <= 8, seen.count < 512, !seen.contains(where: { CFEqual($0, node) }), ownerMatches(node) else { throw unavailable() }
        seen.append(node)
        AXUIElementSetMessagingTimeout(node, 0.1)
        let (roleStatus, roleValue) = attribute(node, kAXRoleAttribute)
        guard roleStatus == .success, let role = roleValue as? String,
              [kAXMenuBarRole, kAXMenuBarItemRole, kAXMenuRole, kAXMenuItemRole].contains(role) else { throw unavailable() }
        if role == kAXMenuItemRole {
            let (keyStatus, keyValue) = attribute(node, kAXMenuItemCmdCharAttribute)
            if keyStatus == .success {
                guard let key = keyValue as? String else { throw unavailable() }
                if key.lowercased() == "v" {
                    let (modifierStatus, modifiers) = attribute(node, kAXMenuItemCmdModifiersAttribute)
                    guard modifierStatus == .success, let mask = modifiers as? NSNumber,
                          CFGetTypeID(mask) != CFBooleanGetTypeID(), mask.doubleValue.isFinite,
                          mask.doubleValue >= 0, mask.doubleValue.rounded() == mask.doubleValue else { throw unavailable() }
                    if mask.doubleValue == 0 {
                        guard match == nil else { throw unavailable() }
                        let (enabledStatus, enabled) = attribute(node, kAXEnabledAttribute)
                        guard enabledStatus == .success, enabled as? Bool == true else { throw unavailable() }
                        match = node
                    }
                }
            } else if keyStatus != .noValue && keyStatus != .attributeUnsupported { throw unavailable() }
        }
        let (childrenStatus, childrenValue) = attribute(node, kAXChildrenAttribute)
        if childrenStatus == .success {
            guard let children = childrenValue as? [AXUIElement], children.count <= 512 - seen.count else { throw unavailable() }
            queue.append(contentsOf: children.map { ($0, depth + 1) })
        } else if role != kAXMenuItemRole || (childrenStatus != .noValue && childrenStatus != .attributeUnsupported) { throw unavailable() }
    }
    try check()
    guard let match else { throw unavailable() }
    return match
}
