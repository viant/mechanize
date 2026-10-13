import Foundation

public struct WindowTextPlan {
    public let text: String
    public let focusRole: String
    public let focusIdentifier: String
    public let focusName: String
    public let chunks: [[UInt16]]
    public init(text: String, role: String, identifier: String, name: String) throws {
        func bounded(_ value: String, _ maximum: Int) -> Bool {
            value.utf8.count <= maximum && !value.unicodeScalars.contains {
                $0.value < 32 || (127...159).contains($0.value) || $0.value == 0x2028 || $0.value == 0x2029
            }
        }
        guard !text.isEmpty, bounded(text, 4096), bounded(identifier, 256), bounded(name, 256),
              ["AXTextField", "AXTextArea", "AXLayoutArea", "AXSplitGroup"].contains(role),
              !identifier.isEmpty || !name.isEmpty else { throw NativeFailure("invalidText", "Bounded single-line text and exact focus identity required") }
        guard !Self.protected(identifier + " " + name) else { throw NativeFailure("protectedTextTarget", "Protected text target unsupported") }
        self.text = text; focusRole = role; focusIdentifier = identifier; focusName = name
        var result: [[UInt16]] = [], chunk: [UInt16] = []
        for scalar in text.unicodeScalars {
            let units = Array(String(scalar).utf16)
            if chunk.count + units.count > 20 { result.append(chunk); chunk = [] }
            chunk.append(contentsOf: units)
        }
        if !chunk.isEmpty { result.append(chunk) }
        chunks = result
    }
    public static func protected(_ value: String) -> Bool {
        let value = value.lowercased()
        return ["password", "credential", "secret", "token", "securetextfield"].contains { value.contains($0) }
    }
    public func permits(role: String, identifier: String, name: String, bundle: String) -> Bool {
        guard role == focusRole, focusIdentifier.isEmpty || focusIdentifier == identifier,
              focusName.isEmpty || focusName == name, !Self.protected(identifier + " " + name) else { return false }
        switch role {
        case "AXTextField", "AXTextArea": return true
        case "AXLayoutArea": return bundle == "com.microsoft.Excel" && name == "Content Area"
        case "AXSplitGroup": return bundle == "com.microsoft.Word" && identifier == "Document Pane"
        default: return false
        }
    }
}

public struct WindowTextSequenceResult {
    public let dispatchState: String
    public let failure: NativeFailure?
}

/// A failed chunk is never resent. Any attempted down makes later failure unknown.
public enum WindowTextSequence {
    public static func perform(_ chunks: [[UInt16]], preflight: () throws -> Void,
                               send: ([UInt16], () -> Void) throws -> Void) -> WindowTextSequenceResult {
        var attempted = false
        do {
            for chunk in chunks {
                try preflight()
                try send(chunk) { attempted = true }
            }
            // Each send has confirmed its key-up/release. A later focus read
            // cannot change that delivery receipt; callers verify UI separately.
            return WindowTextSequenceResult(dispatchState: "dispatched", failure: nil)
        } catch {
            return WindowTextSequenceResult(dispatchState: attempted ? "unknown" : "notDispatched",
                failure: error as? NativeFailure ?? NativeFailure("textUnconfirmed", "Text delivery is uncertain; do not replay"))
        }
    }
}
