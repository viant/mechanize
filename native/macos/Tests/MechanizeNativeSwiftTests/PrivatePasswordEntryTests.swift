import Testing
import ApplicationServices
@testable import MechanizeNative

struct PrivatePasswordEntryTests {
    @Test func probeRemovalAndOneShotPasteUseOnlyMetadata() throws {
        let f = PrivatePasswordRecipientTests.Fixture()
        let entry = PrivatePasswordEntry(recipient: try f.pin())
        var writes: [String] = [], pastes = 0
        #expect(entry.paste(expectedCharacters: 15, check: {}, runtime: f.runtime, dispatch: { _ in pastes += 1 }) == .notDispatched)
        #expect(entry.probe(check: {}, runtime: f.runtime, write: { element, value in
            if !CFEqual(element, f.field) { Issue.record("Wrong field") }; writes.append(value); f.count = value.utf16.count; return .success
        }) == .dispatched)
        #expect(writes == ["x", ""])
        #expect(entry.paste(expectedCharacters: 15, check: {}, runtime: f.runtime, dispatch: { check in
            try check(); pastes += 1; f.count = 15
        }) == .dispatched)
        #expect(entry.paste(expectedCharacters: 15, check: {}, runtime: f.runtime, dispatch: { _ in pastes += 1 }) == .notDispatched)
        #expect(pastes == 1)
    }
    @Test func uncertainProbeCannotBeReplayedOrFollowedByPaste() throws {
        for drift in [false, true] {
            let f = PrivatePasswordRecipientTests.Fixture()
            let entry = PrivatePasswordEntry(recipient: try f.pin())
            var writes = 0, pastes = 0
            #expect(entry.probe(check: {}, runtime: f.runtime, write: { _, value in
                writes += 1; f.count = value.utf16.count
                if drift { f.mode = "replacement"; return .success }
                return .cannotComplete
            }) == .unknown)
            #expect(entry.probe(check: {}, runtime: f.runtime, write: { _, _ in writes += 1; return .success }) == .notDispatched)
            #expect(entry.paste(expectedCharacters: 1, check: {}, runtime: f.runtime, dispatch: { _ in pastes += 1 }) == .notDispatched)
            #expect(writes == 1 && pastes == 0)
        }
    }
    @Test func missingFinalCheckAndUncertainPasteStayConsumed() throws {
        for mode in ["missingCheck", "changedFocus", "wrongCount", "throwAfterPaste"] {
            let f = PrivatePasswordRecipientTests.Fixture()
            let entry = PrivatePasswordEntry(recipient: try f.pin())
            #expect(entry.probe(check: {}, runtime: f.runtime, write: { _, value in f.count = value.utf16.count; return .success }) == .dispatched)
            #expect(entry.paste(expectedCharacters: 15, check: {}, runtime: f.runtime, dispatch: { check in
                if mode == "changedFocus" { f.mode = "replacement" }
                if mode != "missingCheck" { try check() }
                f.count = mode == "wrongCount" ? 14 : 15
                if mode == "throwAfterPaste" { throw NSError(domain: "synthetic", code: 1) }
            }) == .unknown)
            #expect(entry.paste(expectedCharacters: 15, check: {}, runtime: f.runtime, dispatch: { _ in Issue.record("replayed") }) == .notDispatched)
        }
    }
}
