import AppKit
import Carbon
import MechanizeNativeCore

private func shiftedLayoutText(_ keyCode: CGKeyCode) throws -> [UniChar] {
    guard let source = TISCopyCurrentKeyboardLayoutInputSource()?.takeRetainedValue(),
          let property = TISGetInputSourceProperty(source, kTISPropertyUnicodeKeyLayoutData) else {
        throw NativeFailure("keyboardLayoutUnqualified", "Shifted keyboard layout unavailable")
    }
    let data = unsafeBitCast(property, to: CFData.self)
    guard let bytes = CFDataGetBytePtr(data) else { throw NativeFailure("keyboardLayoutUnqualified", "Keyboard layout data unavailable") }
    let layout = UnsafeRawPointer(bytes).assumingMemoryBound(to: UCKeyboardLayout.self)
    var dead: UInt32 = 0, count = 0
    var chars = [UniChar](repeating: 0, count: 4)
    let status = UCKeyTranslate(layout, keyCode, UInt16(kUCKeyActionDown), UInt32(shiftKey >> 8), UInt32(LMGetKbdType()), OptionBits(kUCKeyTranslateNoDeadKeysMask), &dead, chars.count, &count, &chars)
    guard status == noErr, (1...4).contains(count), dead == 0 else { throw NativeFailure("keyboardLayoutUnqualified", "Shifted character translation unavailable") }
    let text = String(utf16CodeUnits: chars, count: count)
    guard !text.unicodeScalars.contains(where: { $0.value < 32 || (127...159).contains($0.value) }) else {
        throw NativeFailure("keyboardLayoutUnqualified", "Shifted character is not printable")
    }
    return Array(chars.prefix(count))
}

// Setting CGEvent.flags does not update its cached Unicode payload. Some apps
// consume that payload directly. Translate Shift-only printable named keys;
// leave command/control/option chords and navigation/function keys untouched.
func namedWindowKeyEvents(key: String, keyCode: CGKeyCode, modifiers: [String],
                          translateShift: (CGKeyCode) throws -> [UniChar] = shiftedLayoutText) throws -> (CGEvent, CGEvent) {
    guard let down = CGEvent(keyboardEventSource: nil, virtualKey: keyCode, keyDown: true),
          let up = CGEvent(keyboardEventSource: nil, virtualKey: keyCode, keyDown: false) else { throw NativeFailure("eventUnavailable", "Named session chord unavailable") }
    var flags: CGEventFlags = []
    for modifier in modifiers {
        switch modifier {
        case "Command": flags.insert(.maskCommand)
        case "Shift": flags.insert(.maskShift)
        case "Option": flags.insert(.maskAlternate)
        case "Control": flags.insert(.maskControl)
        default: throw NativeFailure("invalidModifier", "Unsupported named modifier")
        }
    }
    down.flags = flags; up.flags = []
    if modifiers == ["Shift"], key.utf8.count == 1 {
        let text = try translateShift(keyCode)
        guard !text.isEmpty, text.count <= 4 else { throw NativeFailure("keyboardLayoutUnqualified", "Bounded shifted text required") }
        text.withUnsafeBufferPointer { buffer in
            down.keyboardSetUnicodeString(stringLength: buffer.count, unicodeString: buffer.baseAddress!)
            up.keyboardSetUnicodeString(stringLength: buffer.count, unicodeString: buffer.baseAddress!)
        }
    }
    down.setIntegerValueField(.eventSourceUserData, value: 0x4d454348)
    up.setIntegerValueField(.eventSourceUserData, value: 0x4d454348)
    return (down, up)
}

func validateNamedWindowKeyText(_ event: CGEvent, key: String, keyCode: CGKeyCode, modifiers: [String],
                               translateShift: (CGKeyCode) throws -> [UniChar] = shiftedLayoutText) throws {
    guard modifiers == ["Shift"], key.utf8.count == 1 else { return }
    let expected = try translateShift(keyCode)
    var count = 0; var actual = [UniChar](repeating: 0, count: 4)
    event.keyboardGetUnicodeString(maxStringLength: actual.count, actualStringLength: &count, unicodeString: &actual)
    guard !expected.isEmpty, expected.count <= 4, count == expected.count, Array(actual.prefix(count)) == expected else {
        throw NativeFailure("keyboardLayoutChanged", "Shifted character mapping changed before input")
    }
}
