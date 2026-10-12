import ApplicationServices
import MechanizeNativeCore

struct BoundedSnapshotChildRead {
    let elements: [AXUIElement]
    let complete: Bool
}

/// Read only a bounded prefix at the IPC boundary. Do not fall back to an
/// unbounded AXChildren value when an app cannot support the array API.
func boundedSnapshotChildren(_ element: AXUIElement, limit: Int = 1001,
                             check: () throws -> Void,
                             count: (AXUIElement) -> (AXError, Int) = { element in
                                 var value = 0
                                 let status = AXUIElementGetAttributeValueCount(element, kAXChildrenAttribute as CFString, &value)
                                 return (status, value)
                             },
                             prefix: (AXUIElement, Int) -> (AXError, [AXUIElement]?) = { element, limit in
                                 var value: CFArray?
                                 let status = AXUIElementCopyAttributeValues(element, kAXChildrenAttribute as CFString, 0, limit, &value)
                                 return (status, value as? [AXUIElement])
                             }) throws -> BoundedSnapshotChildRead {
    guard limit > 0, limit <= 1001 else { throw NativeFailure("invalidScope", "Bounded child prefix required") }
    try check()
    let before = count(element)
    try check()
    if (before.0 == .noValue || before.0 == .attributeUnsupported) && before.1 == 0 {
        return BoundedSnapshotChildRead(elements: [], complete: true)
    }
    guard before.0 == .success, before.1 >= 0 else {
        return BoundedSnapshotChildRead(elements: [], complete: false)
    }
    if before.1 == 0 { return BoundedSnapshotChildRead(elements: [], complete: true) }
    let requested = min(limit, before.1)
    let fetched = prefix(element, requested)
    try check()
    guard fetched.0 == .success, let elements = fetched.1, elements.count <= requested else {
        return BoundedSnapshotChildRead(elements: [], complete: false)
    }
    let after = count(element)
    try check()
    let complete = after.0 == .success && before.1 == after.1 &&
        elements.count == requested && before.1 <= limit
    return BoundedSnapshotChildRead(elements: elements, complete: complete)
}
