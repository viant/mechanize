import ApplicationServices
import MechanizeNativeCore

/// Called only after exact identifier enrollment and nonsecure text classification.
func readNativeTextValue(_ element: AXUIElement, revalidate: () throws -> Void) throws -> String {
    try revalidate()
    var raw: CFTypeRef?
    let status = AXUIElementCopyAttributeValue(element, kAXValueAttribute as CFString, &raw)
    if status == .success, let value = raw as? String, value.utf8.count <= 65_536, !value.contains("\0") {
        try revalidate()
        return value
    }
    // Transport errors and malformed values are not evidence that AXValue is absent.
    guard (status == .noValue || status == .attributeUnsupported || status == .success) && raw == nil else {
        throw NativeFailure("attributeUnavailable", "Bounded text value unavailable")
    }
    do {
        return try TextRangeRead.read(count: {
            var countValue: CFTypeRef?
            guard AXUIElementCopyAttributeValue(element, kAXNumberOfCharactersAttribute as CFString, &countValue) == .success,
                  let number = countValue as? NSNumber, CFGetTypeID(number) == CFNumberGetTypeID(),
                  number.doubleValue.isFinite, number.doubleValue >= 0, number.doubleValue <= 65_536,
                  number.doubleValue.rounded(.towardZero) == number.doubleValue else { return nil }
            return number.intValue
        }, range: { length in
            var range = CFRange(location: 0, length: length)
            guard let value = AXValueCreate(.cfRange, &range) else { return nil }
            var result: CFTypeRef?
            guard AXUIElementCopyParameterizedAttributeValue(element, kAXStringForRangeParameterizedAttribute as CFString,
                                                             value, &result) == .success else { return nil }
            return result as? String
        }, revalidate: revalidate)
    } catch is TextRangeReadError {
        throw NativeFailure("attributeUnavailable", "Complete stable text range unavailable")
    }
}
