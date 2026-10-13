import XCTest
@testable import MechanizeNativeCore
final class WindowTextTests: XCTestCase {
    func testUnicodeChunkingNeverSplitsSurrogatesAndPreservesLiteral() throws {
        let text = String(repeating: "a", count: 19) + "😀=SUM(17,23)é"
        let plan = try WindowTextPlan(text: text, role: "AXTextField", identifier: "editor", name: "")
        XCTAssertEqual(String(decoding: plan.chunks.flatMap { $0 }, as: UTF16.self), text)
        for chunk in plan.chunks { XCTAssertLessThanOrEqual(chunk.count, 20); XCTAssertFalse((0xD800...0xDBFF).contains(chunk.last!)) }
    }
    func testExplicitCanvasProfilesAndProtectedControls() throws {
        let p = try WindowTextPlan(text: "17", role: "AXLayoutArea", identifier: "", name: "Content Area")
        XCTAssertTrue(p.permits(role: "AXLayoutArea", identifier: "", name: "Content Area", bundle: "com.microsoft.Excel"))
        XCTAssertFalse(p.permits(role: "AXLayoutArea", identifier: "", name: "Content Area", bundle: "other.app"))
        XCTAssertFalse(p.permits(role: "AXLayoutArea", identifier: "password", name: "Content Area", bundle: "com.microsoft.Excel"))
        for text in ["", "a\nb", "\t", "\0", String(repeating:"x",count:4097)] { XCTAssertThrowsError(try WindowTextPlan(text:text,role:"AXTextArea",identifier:"editor",name:"")) }
        XCTAssertThrowsError(try WindowTextPlan(text:"x",role:"AXTextArea",identifier:"",name:""))
    }
    func testInterruptedSequenceNeverRetriesOrSendsRemainder() {
        let chunks: [[UInt16]] = [[97],[98],[99]]
        for failAfter in 0..<3 {
            var sent = 0
            let result = WindowTextSequence.perform(chunks, preflight: {
                if sent == failAfter { throw NativeFailure("cancelled","Cancelled") }
            }, send: { _, willPost in willPost(); sent += 1 })
            XCTAssertEqual(sent, failAfter)
            XCTAssertEqual(result.dispatchState, failAfter == 0 ? "notDispatched" : "unknown")
        }
        var sent = 0
        let failure = WindowTextSequence.perform(chunks, preflight: {}, send: { _, willPost in
            willPost(); sent += 1; throw NativeFailure("releaseUnknown","Unconfirmed release")
        })
        XCTAssertEqual(sent, 1); XCTAssertEqual(failure.dispatchState, "unknown")
    }
    func testCompletedReleasedTextDoesNotRequirePostDeliveryFocusObservation() {
        let chunks: [[UInt16]] = [[97],[98],[99]]
        var sent = 0, checks = 0
        let result = WindowTextSequence.perform(chunks, preflight: {
            checks += 1
            if sent == chunks.count { throw NativeFailure("foregroundRefreshUnavailable","Observation unavailable") }
        }, send: { _, willPost in willPost(); sent += 1 })
        XCTAssertEqual(sent,3); XCTAssertEqual(checks,3)
        XCTAssertEqual(result.dispatchState,"dispatched"); XCTAssertNil(result.failure)
    }
}
