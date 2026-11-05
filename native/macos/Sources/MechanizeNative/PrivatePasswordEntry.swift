import Foundation
import ApplicationServices

// Private, per-attempt native adapter state; never a public keyboard API.
// The host owns the original durable reservation and clipboard cleanup. Input
// transport must invoke its final check inside the held physical executor fence.
final class PrivatePasswordEntry {
    enum Result: String { case notDispatched, unknown, dispatched }
    private enum Phase { case fresh, ready, consumed }
    private let recipient: PrivatePasswordRecipient
    private let lock = NSLock()
    private var phase = Phase.fresh
    init(recipient: PrivatePasswordRecipient) { self.recipient = recipient }

    func probe(check: () throws -> Void, runtime: PrivatePasswordRecipientRuntime = .system,
               write: (AXUIElement, String) -> AXError = { element, value in
                   AXUIElementSetAttributeValue(element, kAXValueAttribute as CFString, value as CFString)
               }) -> Result {
        guard lock.try() else { return .notDispatched }
        defer { lock.unlock() }
        guard phase == .fresh else { return .notDispatched }
        do { try recipient.requireCharacterCount(0, check: check, runtime: runtime) }
        catch { return .notDispatched }
        phase = .consumed
        do {
            try recipient.writeProbe(inserting: true, check: check, runtime: runtime, write: write)
            try recipient.writeProbe(inserting: false, check: check, runtime: runtime, write: write)
            phase = .ready
            return .dispatched
        } catch { return .unknown }
    }

    // Matching count is structural evidence, not password equality or login.
    // No system-wide key fallback is supplied here: the enrolled private
    // transport must target this recipient and preserve its input receipt.
    func paste(expectedCharacters: Int, check: @escaping () throws -> Void,
               runtime: PrivatePasswordRecipientRuntime = .system,
               dispatch: (_ revalidate: () throws -> Void) throws -> Void) -> Result {
        guard lock.try() else { return .notDispatched }
        defer { lock.unlock() }
        guard phase == .ready, (1...4096).contains(expectedCharacters) else { return .notDispatched }
        do { try recipient.requireCharacterCount(0, check: check, runtime: runtime) }
        catch { return .notDispatched }
        phase = .consumed
        do {
            var admitted = false
            try dispatch {
                guard !admitted else { throw NSError(domain: "privateInputUnavailable", code: 1) }
                try self.recipient.requireCharacterCount(0, check: check, runtime: runtime)
                admitted = true
            }
            guard admitted else { return .unknown }
            try recipient.requireCharacterCount(expectedCharacters, check: check, runtime: runtime)
            return .dispatched
        } catch { return .unknown }
    }
}
