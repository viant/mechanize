import Foundation
import CoreFoundation

public enum CheckedRead {
    public static func decode(role: String?, value: Any?) throws -> Bool {
        guard ["AXCheckBox", "AXRadioButton"].contains(role ?? ""), let number = value as? NSNumber else {
            throw NativeFailure("checkedStateUnavailable", "Exact checkbox or radio state required")
        }
        let type = CFGetTypeID(number)
        guard type == CFBooleanGetTypeID() || type == CFNumberGetTypeID(),
              number.doubleValue == 0 || number.doubleValue == 1 else {
            throw NativeFailure("checkedStateUnavailable", "Mixed or unknown selection state")
        }
        return number.doubleValue == 1
    }
}
