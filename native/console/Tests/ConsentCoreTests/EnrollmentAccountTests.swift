import XCTest
@testable import ConsentCore

final class EnrollmentAccountTests: XCTestCase {
    private let bundle = "com.viant.mechanize.consent"
    private let uid: UInt32 = 501
    private var fresh: String { "com.viant.mechanize.consent:501:0123456789abcdef0123456789abcdef" }
    func testAbsentSignedAccountKeepsLegacySelection() throws {
        var lookups: [String] = []
        let enrollment = KeychainEnrollment(trustedBundleID: bundle, uid: uid, enrolledAccount: nil) { account in
            lookups.append(account); return Data("fixture".utf8)
        }
        _ = try enrollment.credential()
        XCTAssertEqual(lookups, ["com.viant.mechanize.consent:501"])
    }
    func testFreshSignedAccountUsesOneLookupWithoutLegacyFallback() {
        var lookups: [String] = []
        let enrollment = KeychainEnrollment(trustedBundleID: bundle, uid: uid, enrolledAccount: fresh) { account in
            lookups.append(account); throw BrokerTransportError.missingEnrollment
        }
        XCTAssertThrowsError(try enrollment.credential())
        XCTAssertEqual(lookups, [fresh])
    }
    func testMalformedExplicitAccountsCannotLookUpAnyCredential() {
        let rejected = ["", "com.viant.mechanize.consent:501", "com.viant.mechanize.consent:502:0123456789abcdef0123456789abcdef", "other:501:0123456789abcdef0123456789abcdef", fresh + "0", String(fresh.dropLast()), fresh.uppercased(), fresh + "\n", "com.viant.mechanize.consent:501:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"]
        for account in rejected {
            let enrollment = KeychainEnrollment(trustedBundleID: bundle, uid: uid, enrolledAccount: account) { _ in
                XCTFail("Invalid signed account must not fall back or perform Keychain lookup"); return Data()
            }
            XCTAssertThrowsError(try enrollment.credential(), account)
        }
        let foreign = KeychainEnrollment(trustedBundleID: "com.other", uid: uid, enrolledAccount: nil) { _ in XCTFail("Wrong bundle looked up credentials"); return Data() }
        XCTAssertThrowsError(try foreign.credential())
    }
}
