import XCTest
@testable import ConsentCore

final class BrowserConnectionTests: XCTestCase {
    func testProcessFailureIsSeparateFromMissingEnrollment() throws {
        let failed = try JSONDecoder().decode(BrowserConnectionStatus.self, from: Data(#"{"available":false,"channels":[],"attentionCode":"chromeProcessUnqualified"}"#.utf8))
        XCTAssertTrue(failed.processQualificationFailed)
        let absent = try JSONDecoder().decode(BrowserConnectionStatus.self, from: Data(#"{"available":false,"channels":[]}"#.utf8))
        XCTAssertFalse(absent.processQualificationFailed)
        let unknown = try JSONDecoder().decode(BrowserConnectionStatus.self, from: Data(#"{"available":false,"channels":[],"attentionCode":"untrusted-arbitrary-reason"}"#.utf8))
        XCTAssertFalse(unknown.processQualificationFailed)
    }
    private func channel(_ changes: [String: Any] = [:]) throws -> BrowserConnectionChannel {
        var row: [String: Any] = ["trustScope":"desktop", "connected":true, "fixtureOnly":false,
            "processQualified":true, "scopeQualified":true, "profileQualified":false,
            "executorQualified":true, "inventoryComplete":true, "documentCount":1,
            "pendingCount":0, "unknownCount":0]
        row.merge(changes) { _, new in new }
        return try JSONDecoder().decode(BrowserConnectionChannel.self, from: JSONSerialization.data(withJSONObject: row))
    }
    func testReconnectExplanationIsClosedAndDoesNotChangeReadiness() throws {
        let valid = try channel(["attentionCode":"storedFenceMismatch", "reconnectPhase":"inspect", "reconnectReason":"restrictedBrowserPage"])
        XCTAssertTrue(valid.reconnectExplanation?.contains("internal pages") == true)
        XCTAssertFalse(valid.ready)
        for values in [["reconnectPhase":"PRIVATE_PHASE"], ["reconnectReason":"https://private.invalid/SECRET"], ["attentionCode":"executorNotQuiescent"]] {
            var input = ["attentionCode":"storedFenceMismatch", "reconnectPhase":"inspect", "reconnectReason":"restrictedBrowserPage"]
            input.merge(values) { _, new in new }
            XCTAssertNil(try channel(input).reconnectExplanation)
        }
        XCTAssertNil(try channel().reconnectExplanation)
    }
    func testTransportAloneCannotShowReady() throws {
        XCTAssertTrue(try channel().ready)
        for key in ["processQualified", "scopeQualified", "executorQualified", "inventoryComplete"] {
            XCTAssertFalse(try channel([key:false]).ready)
        }
        XCTAssertFalse(try channel(["trustScope":"profile", "profileQualified":false]).ready)
        XCTAssertFalse(try channel(["trustScope":"unknown"]).ready)
        XCTAssertFalse(try channel(["fixtureOnly":true]).ready)
        XCTAssertFalse(try channel(["connected":false]).ready)
        XCTAssertFalse(try channel(["attentionCode":"inventoryIncomplete"]).ready)
        XCTAssertEqual(try channel(["documentCount":0]).readiness, "Open an approved website")
    }
    func testRecoveryAndPendingTakePriorityOverReconnectAdvice() throws {
        XCTAssertEqual(try channel(["unknownCount":1,"connected":false,"pendingCount":1]).readiness, "Recovery required")
        XCTAssertEqual(try channel(["pendingCount":1]).readiness, "Operation pending")
    }
    func testWebsiteScopeIsSeparateFromConnectionReadiness() throws {
        XCTAssertEqual(try channel().websiteAccessDescription, "Selected websites")
        XCTAssertEqual(try channel(["allWebsites":true]).websiteAccessDescription, "All websites")
        XCTAssertFalse(try channel(["allWebsites":true,"connected":false]).ready)
        XCTAssertThrowsError(try channel(["allWebsites":"true"]))
    }
}
