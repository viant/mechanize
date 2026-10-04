import XCTest
@testable import ConsentCore

final class VaultTests: XCTestCase {
    func testExactOriginAndOpaqueAccount() {
        let expiry = Date().addingTimeInterval(60)
        XCTAssertTrue(VaultEntryRequest(id: "request", origin: "https://example.test", accountAlias: "business", expiresAt: expiry).isValid)
        for origin in ["http://example.test", "https://example.test/", "https://user@example.test", "https://example.test?x=y", "https://example.test#x", "https://example.test:443", "https://example.test."] {
            XCTAssertFalse(VaultEntryRequest(id: "request", origin: origin, accountAlias: "business", expiresAt: expiry).isValid, origin)
        }
        XCTAssertFalse(VaultEntryRequest(id: "request", origin: "https://example.test", accountAlias: "a@b", expiresAt: expiry).isValid)
        XCTAssertFalse(VaultEntryRequest(id: "request", origin: "https://example.test", accountAlias: "business", expiresAt: .distantPast).isValid)
    }
}
