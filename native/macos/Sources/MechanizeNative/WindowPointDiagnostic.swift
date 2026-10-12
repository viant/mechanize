import AppKit
import ApplicationServices
import MechanizeNativeCore

/// Read-only diagnostics. These facts never authorize a click or ignore an occluder.
func windowPointDiagnostic(_ permit: WindowFramePermit, _ point: CGPoint) -> String {
    let system = AXUIElementCreateSystemWide()
    AXUIElementSetMessagingTimeout(system, 0.1)
    var hit: AXUIElement?
    guard AXUIElementCopyElementAtPosition(system, Float(point.x), Float(point.y), &hit) == .success,
          let hit else { return "hitTest=unavailable" }
    AXUIElementSetMessagingTimeout(hit, 0.1)
    let owner = inspectAXElementOwner(hit)
    let matchesOwner = owner.pid == permit.pid && owner.uid == getuid() &&
        owner.birth == permit.processStartToken && owner.bundle == permit.bundleId
    guard matchesOwner else { return "hitMatchesTargetOwner=false" }
    var raw: CFTypeRef?
    var window: AXUIElement?
    if AXUIElementCopyAttributeValue(hit, kAXWindowAttribute as CFString, &raw) == .success,
       let raw, CFGetTypeID(raw) == AXUIElementGetTypeID() {
        window = (raw as! AXUIElement)
    } else {
        // Some app providers expose AXParent but not AXWindow. This bounded,
        // same-owner walk is diagnostic only and grants no input authority.
        var current = hit
        var visited: [AXUIElement] = []
        for _ in 0..<16 {
            if visited.contains(where: { CFEqual($0, current) }) { break }
            visited.append(current)
            AXUIElementSetMessagingTimeout(current, 0.1)
            let currentOwner = inspectAXElementOwner(current)
            guard currentOwner.pid == permit.pid && currentOwner.uid == getuid() &&
                    currentOwner.birth == permit.processStartToken && currentOwner.bundle == permit.bundleId else { break }
            var role: CFTypeRef?
            if AXUIElementCopyAttributeValue(current, kAXRoleAttribute as CFString, &role) == .success,
               role as? String == kAXWindowRole { window = current; break }
            var parent: CFTypeRef?
            guard AXUIElementCopyAttributeValue(current, kAXParentAttribute as CFString, &parent) == .success,
                  let parent, CFGetTypeID(parent) == AXUIElementGetTypeID() else { break }
            current = parent as! AXUIElement
        }
    }
    guard let window else { return "hitMatchesTargetOwner=true; hitWindow=unavailable" }
    AXUIElementSetMessagingTimeout(window, 0.1)
    let windowOwner = inspectAXElementOwner(window)
    guard windowOwner.pid == permit.pid && windowOwner.uid == getuid() &&
            windowOwner.birth == permit.processStartToken && windowOwner.bundle == permit.bundleId else {
        return "hitMatchesTargetOwner=true; hitWindowOwnerMatches=false"
    }
    var position: CFTypeRef?, size: CFTypeRef?, number: CFTypeRef?
    let positionStatus = AXUIElementCopyAttributeValue(window, kAXPositionAttribute as CFString, &position)
    let sizeStatus = AXUIElementCopyAttributeValue(window, kAXSizeAttribute as CFString, &size)
    var origin = CGPoint.zero, dimensions = CGSize.zero
    var boundsMatch = false
    if positionStatus == .success, sizeStatus == .success, let position, let size,
       CFGetTypeID(position) == AXValueGetTypeID(), CFGetTypeID(size) == AXValueGetTypeID(),
       AXValueGetValue(position as! AXValue, .cgPoint, &origin),
       AXValueGetValue(size as! AXValue, .cgSize, &dimensions) {
        boundsMatch = CGRect(origin: origin, size: dimensions) == permit.bounds
    }
    let numberStatus = AXUIElementCopyAttributeValue(window, "AXWindowNumber" as CFString, &number)
    let numberMatch: String
    if numberStatus == .success, let number = number as? NSNumber, CFGetTypeID(number) == CFNumberGetTypeID() {
        numberMatch = String(number.uint64Value == UInt64(permit.windowId))
    } else { numberMatch = "unavailable" }
    return "hitMatchesTargetOwner=true; hitWindowBoundsMatch=\(boundsMatch); hitWindowNumberMatch=\(numberMatch)"
}
