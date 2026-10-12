import ApplicationServices
import CoreFoundation

/// Value-free error states: callers cannot confuse failed IPC with missing data.
enum TypedAXRead<Value> {
    case value(Value)
    case absent
    case unavailable
    var resolved: Value? { if case .value(let value) = self { return value }; return nil }
    var failed: Bool { if case .unavailable = self { return true }; return false }
}

func typedAXString(_ status: AXError, _ raw: Any?, maximumBytes: Int = 256) -> TypedAXRead<String> {
    if (status == .noValue || status == .attributeUnsupported) && raw == nil { return .absent }
    guard status == .success, maximumBytes > 0, let value = raw as? String,
          value.utf8.count <= maximumBytes else { return .unavailable }
    return .value(value)
}

func typedAXBoolean(_ status: AXError, _ raw: Any?) -> TypedAXRead<Bool> {
    if (status == .noValue || status == .attributeUnsupported) && raw == nil { return .absent }
    guard status == .success, let value = raw as? NSNumber else { return .unavailable }
    let type = CFGetTypeID(value)
    guard type == CFBooleanGetTypeID() || type == CFNumberGetTypeID(),
          value.doubleValue == 0 || value.doubleValue == 1 else { return .unavailable }
    return .value(value.doubleValue == 1)
}

func readAXAttribute(_ element: AXUIElement, _ name: String) -> (AXError, CFTypeRef?) {
    var value: CFTypeRef?
    let status = AXUIElementCopyAttributeValue(element, name as CFString, &value)
    return (status, value)
}
