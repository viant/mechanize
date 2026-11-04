import Testing
import MechanizeNativeCore

@Test func rejectedDownDoesNotReleaseAnUnpostedButton() throws {
    let input = InputSafety(); input.enable()
    var downs = 0, ups = 0
    do {
        try input.pressClassified(token: "mouse:left", down: { downs += 1; return .notPosted }, up: { ups += 1; return true })
        Issue.record("Rejected input unexpectedly succeeded")
    } catch let error as NativeFailure {
        #expect(error.code == "inputDownNotPosted")
    }
    #expect(downs == 1 && ups == 0)
    let cleanup = input.inhibitAndRelease()
    #expect(cleanup.released == 0 && cleanup.unknown == 0 && ups == 0)
}

@Test func uncertainDownRetainsReleaseAndNeverReplaysDown() throws {
    let input = InputSafety(); input.enable()
    var downs = 0, ups = 0
    do {
        try input.pressClassified(token: "mouse:left", down: { downs += 1; return .unknown }, up: { ups += 1; return true })
        Issue.record("Uncertain input unexpectedly succeeded")
    } catch let error as NativeFailure {
        #expect(error.code == "inputDispatchUnknown")
    }
    #expect(downs == 1 && ups == 0)
    let cleanup = input.inhibitAndRelease()
    #expect(cleanup.released == 1 && cleanup.unknown == 0)
    #expect(downs == 1 && ups == 1)
}

@Test func postedDownWithUnknownReleaseRetainsCleanup() throws {
    let input = InputSafety(); input.enable()
    var ups = 0
    do {
        try input.pressClassified(token: "mouse:left", down: { .posted }, up: { ups += 1; return false })
        Issue.record("Unknown release unexpectedly succeeded")
    } catch let error as NativeFailure {
        #expect(error.code == "inputDispatchUnknown")
    }
    #expect(input.inhibitAndRelease().unknown == 1)
    #expect(ups == 2)
}
