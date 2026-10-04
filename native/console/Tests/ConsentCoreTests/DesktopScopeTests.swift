import XCTest
@testable import ConsentCore

final class DesktopScopeTests: XCTestCase {
    func testExplicitDesktopScopeWireAndPresentation() throws {
        let scope = try ConsentWire.decoder().decode(ConsentScope.self, from: Data("{\"kind\":\"desktop\"}".utf8))
        XCTAssertTrue(scope.isExact)
        XCTAssertEqual(scope.exactDescription, "All applications and connected browsers")
        XCTAssertTrue(ConsentScope(kind: .desktop, displayName: "Misleading narrow label").isExact)
        XCTAssertEqual(ConsentScope(kind: .desktop, displayName: "One app").exactDescription, "All applications and connected browsers")
        XCTAssertEqual(try ConsentWire.decoder().decode(ConsentScope.self, from: ConsentWire.encoder().encode(scope)), scope)
    }
    func testDesktopCannotCarryNarrowSelectors() {
        XCTAssertFalse(ConsentScope(kind: .desktop, bundleID: "com.example.Mail").isExact)
        XCTAssertFalse(ConsentScope(kind: .desktop, windowID: "42").isExact)
        XCTAssertFalse(ConsentScope(kind: .desktop, origin: "https://example.com").isExact)
        XCTAssertFalse(ConsentScope(kind: .application, bundleID: "*").isExact)
        XCTAssertFalse(ConsentScope(kind: .origin, origin: "https://*.example.com").isExact)
        XCTAssertFalse(ConsentScope(kind: .origin, origin: "https://example.com/").isExact)
    }
    func testModesStayDistinctForDesktopRequest() {
        let now = Date()
        let request = ConsentRequest(id: "desktop-request", verifiedClient: VerifiedClient(id: "fixture", displayName: "Fixture", verification: .verified), scope: ConsentScope(kind: .desktop), modes: [.observe, .control, .record], purpose: "Work across applications", durationSeconds: 60, createdAt: now, expiresAt: now.addingTimeInterval(60))
        XCTAssertTrue(request.isValid(at: now))
        XCTAssertEqual(Set(request.modes), Set([.observe, .control, .record]))
    }
}
