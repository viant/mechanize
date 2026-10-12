import XCTest
import CryptoKit
@testable import ConsentCore

@MainActor final class MigrationSignedPackageSourceTests: XCTestCase {
    func envelope(_ payload: Data, key: Curve25519.Signing.PrivateKey, domain: Bool = true) throws -> Data {
        let signature = try key.signature(for: domain ? MigrationSignedPackageSource.signingMessage(payload) : payload)
        return try JSONSerialization.data(withJSONObject: ["version": 1,
            "payloadBase64": payload.base64EncodedString(), "signatureBase64": signature.base64EncodedString()])
    }
    func testReviewedSignatureRevalidatedForEverySelection() async throws {
        let key = Curve25519.Signing.PrivateKey()
        let payload = try MigrationUpgradeSelectionTests().payload()
        var bytes = try envelope(payload, key: key)
        let source = try MigrationSignedPackageSource(publicKey: key.publicKey.rawRepresentation) { bytes }
        let package = try await source.selectedPackage()
        XCTAssertEqual(package.digest, MigrationUpgradeIntent.digest(payload))
        bytes = try envelope(payload, key: Curve25519.Signing.PrivateKey())
        do { _ = try await source.selectedPackage(); XCTFail("substituted signer accepted") } catch {}
    }
    func testTamperingWrongDomainAndUnknownFieldsRejected() async throws {
        let key = Curve25519.Signing.PrivateKey(), payload = try MigrationUpgradeSelectionTests().payload()
        let valid = try envelope(payload, key: key)
        var tampered = try JSONSerialization.jsonObject(with: valid) as! [String: Any]
        tampered["payloadBase64"] = try MigrationUpgradeSelectionTests().payload(title: "Substitution").base64EncodedString()
        var extra = try JSONSerialization.jsonObject(with: valid) as! [String: Any]; extra["approved"] = true
        for bytes in [try JSONSerialization.data(withJSONObject: tampered),
                      try envelope(payload, key: key, domain: false),
                      try JSONSerialization.data(withJSONObject: extra), Data()] {
            let source = try MigrationSignedPackageSource(publicKey: key.publicKey.rawRepresentation) { bytes }
            do { _ = try await source.selectedPackage(); XCTFail("invalid package accepted") } catch {}
        }
    }
    func testUnenrolledBundleUnavailable() {
        XCTAssertNil(MigrationSignedPackageSource.enrolled(in: Bundle(for: Self.self)))
    }
}
