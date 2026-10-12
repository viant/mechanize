import XCTest
@testable import ConsentCore

final class BrowserScopeTests: XCTestCase {
    func testExplicitBrowserScopeDoesNotClaimNativeControl() throws {
        let scope = try ConsentWire.decoder().decode(ConsentScope.self, from: Data("{\"kind\":\"browser\",\"bundleID\":\"com.google.Chrome\",\"displayName\":\"One page\"}".utf8))
        XCTAssertTrue(scope.isExact)
        XCTAssertEqual(scope.exactDescription, "Chrome: all websites")
        XCTAssertNotEqual(scope.kind, .application)
        XCTAssertEqual(try ConsentWire.decoder().decode(ConsentScope.self, from: ConsentWire.encoder().encode(scope)), scope)
    }
    func testBrowserScopeRejectsDifferentOrNarrowSelectors() {
        for scope in [ConsentScope(kind: .browser), ConsentScope(kind: .browser, bundleID: "com.other.Browser"),
                      ConsentScope(kind: .browser, bundleID: "com.google.Chrome", origin: "https://fixture.test"),
                      ConsentScope(kind: .browser, bundleID: "com.google.Chrome", windowID: "42")] {
            XCTAssertFalse(scope.isExact)
        }
    }
}
