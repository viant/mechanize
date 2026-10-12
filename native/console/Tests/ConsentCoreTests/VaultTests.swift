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
    func testCanonicalWebsiteInputRejectsCredentialBearingAndAmbiguousURLs() {
        XCTAssertEqual(VaultOrigin.canonical(" HTTPS://EXAMPLE.TEST:443/ "), "https://example.test")
        XCTAssertEqual(VaultOrigin.canonical("https://example.test:8443"), "https://example.test:8443")
        for input in ["https://user:secret@example.test", "https://user@example.test", "https://example.test/login", "https://example.test?password=secret", "https://example.test#secret", "http://example.test", "https://example.test:0", "https://example.test:65536", "https://example.test.", "https://"] {
            XCTAssertNil(VaultOrigin.canonical(input))
        }
        XCTAssertNil(VaultOrigin.canonical("https://" + String(repeating: "a", count: 2048)))
    }

}
