import XCTest
import Foundation
@testable import MechanizeNative

final class DesktopScopeTests: XCTestCase {
    func testTypedDesktopScopeSupportsDifferentConcreteAppsWithoutInventory() {
        let scope: [String: Any] = ["allApplications": true, "allowedBundles": [String]()]
        XCTAssertTrue(fenceScopeAllows(scope, "com.apple.mail"))
        XCTAssertTrue(fenceScopeAllows(scope, "com.apple.TextEdit"))
        XCTAssertTrue(fenceScopeAllows(scope, "com.new.installation"))
        XCTAssertFalse(fenceScopeAllows(scope, "*"))
        XCTAssertFalse(fenceScopeAllows(scope, "/Applications/Mail.app"))
        XCTAssertFalse(fenceScopeAllows(scope, "file:///Applications/Mail.app"))
    }
    func testNumericStringMixedAndEmptyScopesCannotMintDesktopAuthority() {
        for scope: [String: Any] in [
            ["allApplications": NSNumber(value: 1), "allowedBundles": [String]()],
            ["allApplications": "true", "allowedBundles": [String]()],
            ["allApplications": true, "allowedBundles": ["com.apple.mail"]],
            ["allowedBundles": [String]()],
            ["allowedBundles": ["*"]],
            ["allowedBundles": ["com.apple.mail", "com.apple.mail"]]
        ] { XCTAssertFalse(fenceScopeAllows(scope, "com.apple.mail")) }
        XCTAssertTrue(fenceScopeAllows(["allowedBundles": ["com.apple.mail"]], "com.apple.mail"))
        XCTAssertFalse(fenceScopeAllows(["allowedBundles": ["com.apple.mail"]], "com.apple.TextEdit"))
    }
}
