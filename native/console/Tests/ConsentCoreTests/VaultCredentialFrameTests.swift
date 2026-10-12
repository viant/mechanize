import XCTest
@testable import ConsentCore

final class VaultCredentialFrameTests: XCTestCase {
    func testBinaryGoldenFrameMatchesGoDecoder() throws {
        var called = false
        try VaultCredentialFrame.withBytes(username: Data([97]), password: Data([206,178])) { frame in
            called = true
            XCTAssertEqual(Array(frame), [77,86,76,84,0,0,0,1,0,0,0,1,0,0,0,2,97,206,178])
        }
        XCTAssertTrue(called)
    }
    func testInvalidEmptyNulUtf8AndOversizedInputNeverReachTransport() {
        for (user, password) in [(Data(),Data([97])),(Data([97]),Data([0])),(Data([255]),Data([97])),(Data(repeating:97,count:65536),Data([97]))] {
            var called = false
            XCTAssertThrowsError(try VaultCredentialFrame.withBytes(username:user,password:password) { _ in called = true })
            XCTAssertFalse(called)
        }
    }
    func testTransportErrorsAreSanitized() {
        struct SyntheticPrivateError: Error {}
        XCTAssertThrowsError(try VaultCredentialFrame.withBytes(username:Data([97]),password:Data([98])) { _ in throw SyntheticPrivateError() }) { error in
            guard case VaultCredentialFrameError.transportUnavailable = error else { return XCTFail("Original transport error escaped") }
        }
    }
}
