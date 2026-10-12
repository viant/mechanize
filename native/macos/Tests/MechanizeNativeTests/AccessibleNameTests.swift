import XCTest
import ApplicationServices
@testable import MechanizeNative

final class AccessibleNameTests: XCTestCase {
    func testTitlePrecedenceAndPurposeFallback() {
        let element = AXUIElementCreateApplication(101)
        var requests: [String] = []
        let title = accessibleName(element) { _, name in
            requests.append(name); return (.success, "Title" as CFString)
        }
        XCTAssertEqual(title.1 as? String, "Title")
        XCTAssertEqual(requests, [kAXTitleAttribute])
        for missing in [AXError.noValue, .attributeUnsupported, .success] {
            let name = accessibleName(element) { _, attribute in
                if attribute == kAXTitleAttribute { return (missing, missing == .success ? "" as CFString : nil) }
                XCTAssertEqual(attribute, kAXDescriptionAttribute)
                return (.success, "Message body" as CFString)
            }
            XCTAssertEqual(name.1 as? String, "Message body")
        }
    }
    func testUnavailableOrMalformedMetadataNeverBecomesAName() {
        let element = AXUIElementCreateApplication(101)
        let failed = accessibleName(element) { _, attribute in
            XCTAssertEqual(attribute, kAXTitleAttribute)
            return (.cannotComplete, nil)
        }
        XCTAssertEqual(failed.0, .cannotComplete)
        let malformed = accessibleName(element) { _, _ in (.success, kCFBooleanTrue) }
        XCTAssertEqual(malformed.0, .failure)
        let missing = accessibleName(element) { _, _ in (.noValue, nil) }
        XCTAssertEqual(missing.0, .noValue)
        let descriptionFailure = accessibleName(element) { _, attribute in
            attribute == kAXTitleAttribute ? (.noValue, nil) : (.cannotComplete, nil)
        }
        XCTAssertEqual(descriptionFailure.0, .cannotComplete)
    }
}
