import XCTest
import ApplicationServices
@testable import MechanizeNative

final class OutlookRecipientTests: XCTestCase {
    func testExactFocusedEditableRecipientOnly() {
        func allowed(bundle: String = "com.microsoft.Outlook", identifier: String = "toTextField",
                     role: String = kAXTextFieldRole, status: AXError = .attributeUnsupported,
                     enabled: CFTypeRef? = nil, focusStatus: AXError = .success,
                     focused: CFTypeRef? = kCFBooleanTrue, editableStatus: AXError = .success,
                     editable: Bool = true) -> Bool {
            qualifiedOutlookRecipient(role: role, identifier: identifier, bundle: bundle,
                enabledStatus: status, enabled: enabled, focusedStatus: focusStatus, focused: focused,
                editableStatus: editableStatus, editable: editable)
        }
        XCTAssertTrue(allowed())
        XCTAssertTrue(allowed(status: .noValue))
        XCTAssertFalse(allowed(bundle: "com.example.other"))
        XCTAssertFalse(allowed(identifier: "subjectTextField"))
        XCTAssertFalse(allowed(role: kAXTextAreaRole))
        XCTAssertFalse(allowed(status: .success, enabled: kCFBooleanFalse))
        XCTAssertFalse(allowed(status: .cannotComplete))
        XCTAssertFalse(allowed(enabled: kCFBooleanTrue))
        XCTAssertFalse(allowed(focusStatus: .cannotComplete))
        XCTAssertFalse(allowed(focused: kCFBooleanFalse))
        XCTAssertFalse(allowed(focused: nil))
        XCTAssertFalse(allowed(focused: "true" as CFString))
        XCTAssertFalse(allowed(editableStatus: .cannotComplete))
        XCTAssertFalse(allowed(editable: false))
    }
}
