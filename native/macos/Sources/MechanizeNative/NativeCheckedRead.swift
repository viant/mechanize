import ApplicationServices
import MechanizeNativeCore

// Ribbon tabs can expose AXSelected instead of AXValue. This fallback is only
// for radio controls and explicit absence, never transport errors or mixed state.
func readCheckedState(role: String?, value: () -> (AXError, Any?), selected: () -> (AXError, Any?)) throws -> Bool {
    let primary = value()
    if primary.0 == .success, let raw = primary.1 {
        return try CheckedRead.decode(role: role, value: raw)
    }
    // Only an explicit missing-attribute status with no payload permits fallback.
    // A success without a value or an error carrying data remains uncertain.
    let absent = primary.1 == nil && (primary.0 == .noValue || primary.0 == .attributeUnsupported)
    guard role == "AXRadioButton", absent else {
        throw NativeFailure("checkedStateUnavailable", "Selection state unavailable")
    }
    let alternate = selected()
    guard alternate.0 == .success else {
        throw NativeFailure("checkedStateUnavailable", "Radio selection state unavailable")
    }
    return try CheckedRead.decode(role: role, value: alternate.1)
}
