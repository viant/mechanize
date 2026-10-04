import ApplicationServices
import MechanizeNativeCore

struct NativeTextRuntime {
    let attribute: (AXUIElement, String) -> (AXError, CFTypeRef?)
    let settable: (AXUIElement, String) -> (AXError, Bool)
    let set: (AXUIElement, String, CFTypeRef) -> AXError
    static let system = NativeTextRuntime(attribute: { element, name in
        var value: CFTypeRef?
        let status = AXUIElementCopyAttributeValue(element, name as CFString, &value)
        return (status, value)
    }, settable: { element, name in
        var writable: DarwinBoolean = false
        let status = AXUIElementIsAttributeSettable(element, name as CFString, &writable)
        return (status, writable.boolValue)
    }, set: { AXUIElementSetAttributeValue($0, $1 as CFString, $2) })
}
struct NativeTextOutcome {
    let dispatchState: String
    let matches: Bool?
    let nativeCode: Int32
    let failure: NativeFailure?
}
func boundedTextLiteral(_ value: Any?) throws -> String {
    guard let value = value as? String, value.utf8.count <= 65_536, !value.contains("\0") else { throw NativeFailure("invalidValue", "Bounded plaintext literal required") }
    return value
}
private func classifiedNativeText(_ element: AXUIElement, runtime: NativeTextRuntime) -> Bool {
    let role = runtime.attribute(element, kAXRoleAttribute), subrole = runtime.attribute(element, kAXSubroleAttribute)
    guard role.0 == .success, let roleName = role.1 as? String else { return false }
    let subroleKnown = (subrole.0 == .success && subrole.1 is String) || (subrole.0 == .noValue || subrole.0 == .attributeUnsupported) && subrole.1 == nil
    var labels: [String] = []
    for name in [kAXTitleAttribute, kAXIdentifierAttribute] {
        let result = runtime.attribute(element, name)
        if result.0 == .success, let label = result.1 as? String { labels.append(label) }
        else if (result.0 == .noValue || result.0 == .attributeUnsupported) && result.1 == nil { labels.append("") }
        else { return false }
    }
    return ReplacementProof.permitted(role: roleName, subrole: subrole.1 as? String, subroleKnown: subroleKnown, valueSettable: true, labels: labels)
}
private func textCharacterCount(_ element: AXUIElement, runtime: NativeTextRuntime) throws -> Int {
    let (status, raw) = runtime.attribute(element, kAXNumberOfCharactersAttribute)
    guard status == .success, let number = raw as? NSNumber, CFGetTypeID(number) == CFNumberGetTypeID(), number.doubleValue.isFinite,
          number.doubleValue >= 0, number.doubleValue <= 65_536, number.doubleValue.rounded(.towardZero) == number.doubleValue else {
        throw NativeFailure("textRangeUnavailable", "Complete bounded character count unavailable")
    }
    return Int(number.doubleValue)
}
private func selectedWholeRange(_ element: AXUIElement, count: Int, runtime: NativeTextRuntime) throws {
    let (status, raw) = runtime.attribute(element, kAXSelectedTextRangeAttribute)
    guard status == .success, let raw, CFGetTypeID(raw) == AXValueGetTypeID() else { throw NativeFailure("textSelectionUnconfirmed", "Selected-text range unavailable") }
    let value = raw as! AXValue
    var range = CFRange(location: 0, length: 0)
    guard AXValueGetType(value) == .cfRange, AXValueGetValue(value, .cfRange, &range), range.location == 0, range.length == count,
          try textCharacterCount(element, runtime: runtime) == count else {
        throw NativeFailure("textSelectionUnconfirmed", "Whole targeted text selection changed or differs from the requested range")
    }
}
func nativeValueMatches(_ element: AXUIElement, expected: String, revalidate: () throws -> Void,
                        runtime: NativeTextRuntime = .system) throws -> Bool {
    _ = try boundedTextLiteral(expected)
    try revalidate()
    guard classifiedNativeText(element, runtime: runtime) else { throw NativeFailure("valueComparisonDenied", "Known nonsecure text classification required") }
    try revalidate()
    let matches = ReplacementProof.compare(expected: expected, permitted: true, read: {
        let (status, value) = runtime.attribute(element, kAXValueAttribute)
        return status == .success ? value as? String : nil
    }, revalidate: {
        try revalidate()
        guard classifiedNativeText(element, runtime: runtime) else { throw NativeFailure("valueComparisonDenied", "Text classification changed") }
        try revalidate()
    })
    try revalidate()
    guard classifiedNativeText(element, runtime: runtime) else { throw NativeFailure("valueComparisonDenied", "Text classification changed after comparison") }
    try revalidate()
    guard let matches else { throw NativeFailure("valueComparisonUnavailable", "Fresh bounded text comparison unavailable") }
    return matches
}
func replaceNativeText(_ element: AXUIElement, expected: String, verify: Bool, revalidate: () throws -> Void, willMutate: () throws -> Void,
                       runtime: NativeTextRuntime = .system) throws -> NativeTextOutcome {
    _ = try boundedTextLiteral(expected)
    func validate() throws {
        try revalidate()
        guard classifiedNativeText(element, runtime: runtime) else { throw NativeFailure("textReplacementDenied", "Known nonsecure text classification required") }
        let enabled = runtime.attribute(element, kAXEnabledAttribute)
        guard enabled.0 == .success, enabled.1 as? Bool == true else { throw NativeFailure("textReplacementDenied", "Text target must remain positively enabled") }
        for name in [kAXSelectedTextRangeAttribute, kAXSelectedTextAttribute] {
            let (status, writable) = runtime.settable(element, name)
            guard status == .success, writable else { throw NativeFailure("textReplacementUnsupported", "Both selected-text attributes must be independently settable") }
        }
        try revalidate()
    }
    try validate()
    let count = try textCharacterCount(element, runtime: runtime)
    var range = CFRange(location: 0, length: count)
    guard let selected = AXValueCreate(.cfRange, &range) else { throw NativeFailure("textRangeUnavailable", "Range could not be constructed") }
    try validate(); try willMutate()
    var code = runtime.set(element, kAXSelectedTextRangeAttribute, selected)
    // Selection itself is a mutation. Any error after this point is unknown;
    // selection and text writes are never retried or replaced by another route.
    do {
        guard code == .success else { throw NativeFailure("textSelectionUnconfirmed", "Selection setter was not acknowledged") }
        try validate(); try selectedWholeRange(element, count: count, runtime: runtime); try validate()
        code = runtime.set(element, kAXSelectedTextAttribute, expected as CFString)
        guard code == .success else { throw NativeFailure("textReplacementUnconfirmed", "Selected-text setter was not acknowledged") }
        let matches: Bool?
        if verify {
            matches = ReplacementProof.compare(expected: expected, permitted: true, read: {
                let (status, value) = runtime.attribute(element, kAXValueAttribute)
                return status == .success ? value as? String : nil
            }, revalidate: { try validate() })
        } else { matches = nil }
        return NativeTextOutcome(dispatchState: "dispatched", matches: matches, nativeCode: code.rawValue, failure: nil)
    } catch {
        return NativeTextOutcome(dispatchState: "unknown", matches: nil, nativeCode: code.rawValue,
            failure: NativeFailure("textReplacementUnconfirmed", "Selected-text replacement lacks complete proof; reconcile before another write"))
    }
}
