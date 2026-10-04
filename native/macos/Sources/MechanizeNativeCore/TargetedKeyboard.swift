import Foundation

/// Closed, one-key chord. No Unicode text, raw codes, held keys or sequences.
public struct TargetedKeyChord: Equatable {
    public let key: String
    public let modifiers: [String]
    public init(_ source: String) throws {
        guard !source.isEmpty, source.utf8.count <= 64 else { throw NativeFailure("invalidKey", "Bounded named key chord required") }
        let pieces = source.split(separator: "+", omittingEmptySubsequences: false).map(String.init)
        guard let key = pieces.last, !key.isEmpty else { throw NativeFailure("invalidKey", "Named key required") }
        let special: Set<String> = ["Space", "Tab", "Return", "Enter", "Escape", "ArrowLeft", "ArrowRight", "ArrowUp", "ArrowDown", "Home", "End", "PageUp", "PageDown", "Backspace", "Delete"]
        let functionKeys = Set((1...20).map { "F\($0)" })
        guard special.contains(key) || functionKeys.contains(key) || (key.utf8.count == 1 && key.utf8.allSatisfy({ (65...90).contains($0) })) else { throw NativeFailure("invalidKey", "Unsupported named key") }
        let mods = pieces.dropLast().map { $0 == "Cmd" ? "Command" : $0 }
        guard mods.count <= 4, Set(mods).count == mods.count, mods.allSatisfy({ ["Command", "Shift", "Option", "Control"].contains($0) }) else { throw NativeFailure("invalidModifier", "Unique closed modifier names required") }
        self.key = key == "Enter" ? "Return" : key
        self.modifiers = mods
    }
}
