import XCTest
@testable import ConsentCore

final class BrowserControllersTests: XCTestCase {
    func testOriginDraftDoesNotAuthorizeAndRejectsMalformedOrigins() {
        XCTAssertTrue(BrowserControllerPolicy(enabled: false, origins: BrowserControllerPolicy.suggestedOrigins).isValid)
        XCTAssertFalse(BrowserControllerPolicy(enabled: true, origins: []).isValid)
        for origin in ["https://site.test/path", "https://site.test/", "https://user:password@site.test", "https://*.test", "http://site.test", "https://site.test?x=1", "https://site.test#x", "file:///tmp/a"] {
            XCTAssertFalse(BrowserControllerPolicy.validOrigin(origin), origin)
        }
    }
    func testPendingApprovedAndRevokedStateDecode() throws {
        let base: [String:Any] = ["policy": ["enabled":true,"origins":["https://site.test"]],"connected":true]
        var value = base
        let session: [String:Any] = ["id":"session-1","origin":"https://site.test","documentId":"document-1","tabId":1,"approved":false,"expiresAt":"2026-10-07T10:00:00.123456789Z"]
        value["sessions"] = [session]
        var result = try decode(value)
        XCTAssertTrue(result.isValid); XCTAssertFalse(result.sessions[0].approved)
        var approved = session; approved["approved"] = true; value["sessions"] = [approved]
        result = try decode(value); XCTAssertTrue(result.sessions[0].approved)
        value["sessions"] = []; XCTAssertTrue(try decode(value).sessions.isEmpty)
        value["sessions"] = [session]; value["policy"] = ["enabled": false, "origins":["https://site.test"]]
        XCTAssertFalse(try decode(value).isValid)
        value = base; var foreign = session; foreign["origin"] = "https://foreign.test"; value["sessions"] = [foreign]
        XCTAssertFalse(try decode(value).isValid)
        value["sessions"] = [session, session]; XCTAssertFalse(try decode(value).isValid)
        value["sessions"] = [["id":"session-1"]]; XCTAssertThrowsError(try decode(value))
    }
    func testLocalhostPortPatternsAreExactHostOnly() {
        for pattern in ["localhost:*", "http://localhost:*", "https://localhost:*"] {
            XCTAssertTrue(BrowserControllerPolicy.validOrigin(pattern))
            for origin in ["http://localhost", "https://localhost", "http://localhost:49173", "https://localhost:65535"] {
                let expected = pattern == "localhost:*" || origin.hasPrefix(pattern.components(separatedBy: "://")[0] + "://")
                XCTAssertEqual(BrowserControllerPolicy.allows([pattern], origin: origin), expected)
            }
            for origin in ["http://127.0.0.1:3000", "http://localhost.evil:3000", "https://evil.localhost:3000", "http://localhost.:3000", "http://user@localhost:3000", "http://localhost:3000/path", "http://localhost:3000?q=x", "http://localhost:3000#x", "http://localhost:", "http://localhost:0", "http://localhost:65536", "http://localhost:03000", "localhost:*"] {
                XCTAssertFalse(BrowserControllerPolicy.allows([pattern], origin: origin), origin)
            }
        }
        for pattern in ["*", "*.localhost:*", "localhost:*/path", "http://localhost:*/", "https://user@localhost:*", "https://localhost:*?x=1", "https://localhost:*#x", "https://localhost.evil:*", "http://127.0.0.1:*"] {
            XCTAssertFalse(BrowserControllerPolicy.validOrigin(pattern), pattern)
        }
    }
    private func decode(_ value: [String:Any]) throws -> BrowserControllerState {
        try ConsentWire.decoder().decode(BrowserControllerState.self, from: JSONSerialization.data(withJSONObject: value))
    }
}
