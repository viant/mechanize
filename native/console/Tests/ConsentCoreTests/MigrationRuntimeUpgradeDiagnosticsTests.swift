import XCTest
import CryptoKit
@testable import ConsentCore

@MainActor final class MigrationRuntimeUpgradeDiagnosticsTests: XCTestCase {
    func source(_ payload: Data) throws -> MigrationSignedPackageSource {
        let key = Curve25519.Signing.PrivateKey()
        let envelope = try MigrationSignedPackageSourceTests().envelope(payload, key:key)
        return try MigrationSignedPackageSource(publicKey:key.publicKey.rawRepresentation) { envelope }
    }
    func testClosedExplicitCLIOnlyCapturesPreservation() throws {
        let selected = try source(MigrationPreserveExtensionTests().packageData())
        var reads = 0, captures = 0
        let provider = { reads += 1; return selected }
        for args in [[], ["--check-runtime-upgrade", "--path", "/untrusted"], ["--check-runtime-upgrade", "--approve"]] {
            let report = MigrationRuntimeUpgradeDiagnostics.run(arguments:args,source:provider,capture:{ _ in captures += 1 })
            XCTAssertFalse(report.qualified);XCTAssertEqual(report.errorCode,"invalidArguments")
        }
        XCTAssertEqual(reads,0);XCTAssertEqual(captures,0)
        let report = MigrationRuntimeUpgradeDiagnostics.run(arguments:["--check-runtime-upgrade"],source:provider,capture:{ package in
            XCTAssertNotNil(package.observerEnrollment.preservedChrome);captures += 1
        })
        XCTAssertTrue(report.qualified);XCTAssertEqual(reads,1);XCTAssertEqual(captures,1)
        let json = try JSONSerialization.jsonObject(with:report.json()) as! [String:Any]
        XCTAssertEqual(Set(json.keys),Set(["qualified","stage","errorCode"]))
    }
    func testUnavailableWrongVariantAndObserverFailuresAreSanitized() throws {
        let normal = try source(MigrationUpgradeSelectionTests().payload())
        var captures = 0
        let unsupported = MigrationRuntimeUpgradeDiagnostics.run(arguments:["--check-runtime-upgrade"],source:{normal},capture:{_ in captures += 1})
        XCTAssertEqual(unsupported.errorCode,"preservationRequired");XCTAssertEqual(captures,0)
        let absent = MigrationRuntimeUpgradeDiagnostics.run(arguments:["--check-runtime-upgrade"],source:{nil})
        XCTAssertEqual(absent.errorCode,"enrollmentUnavailable")
        let selected = try source(MigrationPreserveExtensionTests().packageData())
        let failed = MigrationRuntimeUpgradeDiagnostics.run(arguments:["--check-runtime-upgrade"],source:{selected},capture:{_ in throw NSError(domain:"PRIVATE_PATH_CANARY",code:1)})
        XCTAssertFalse(failed.qualified);XCTAssertEqual(failed.errorCode,"observationUnavailable")
        XCTAssertFalse(String(decoding:failed.json(),as:UTF8.self).contains("PRIVATE_PATH_CANARY"))
    }
    func testTypedObserverFailureIsAClosedScalar() throws {
        let selected=try source(MigrationPreserveExtensionTests().packageData())
        let report=MigrationRuntimeUpgradeDiagnostics.run(arguments:["--check-runtime-upgrade"],source:{selected},capture:{_ in throw MigrationObserverReadinessError.accessibilityRequired})
        XCTAssertEqual(report.stage,"observer");XCTAssertEqual(report.errorCode,"accessibilityRequired");XCTAssertFalse(report.qualified)
    }
    func testBadSignatureNeverCaptures() throws {
        let key = Curve25519.Signing.PrivateKey()
        let selected = try MigrationSignedPackageSource(publicKey:key.publicKey.rawRepresentation) { Data("{}".utf8) }
        let report = MigrationRuntimeUpgradeDiagnostics.run(arguments:["--check-runtime-upgrade"],source:{selected},capture:{_ in XCTFail("untrusted package reached observer")})
        XCTAssertEqual(report.errorCode,"packageUnavailable")
    }
    func testResponsiveDiagnosticServicesMainRunLoopWhileObserverRunsOffMain() throws {
        let selected=try source(MigrationPreserveExtensionTests().packageData())
        let serviced=DispatchSemaphore(value:0)
        let report=MigrationRuntimeUpgradeDiagnostics.runResponsive(arguments:["--check-runtime-upgrade"],source:{selected},timeout:2,capture:{_ in
            guard !Thread.isMainThread else {throw MigrationConsoleError.unavailable}
            RunLoop.main.perform(inModes:[.default]) {serviced.signal()}
            guard serviced.wait(timeout:.now()+1) == .success else{throw MigrationConsoleError.unavailable}
        })
        XCTAssertTrue(report.qualified)
    }
    func testResponsiveDiagnosticTimeoutRemainsClosedAndDoesNotRetry() throws {
        let selected=try source(MigrationPreserveExtensionTests().packageData())
        let release=DispatchSemaphore(value:0),started=DispatchSemaphore(value:0)
        let report=MigrationRuntimeUpgradeDiagnostics.runResponsive(arguments:["--check-runtime-upgrade"],source:{selected},timeout:0.05,capture:{_ in
            started.signal();_ = release.wait(timeout:.now()+1)
        })
        release.signal()
        XCTAssertEqual(started.wait(timeout:.now()+1),.success)
        XCTAssertFalse(report.qualified);XCTAssertEqual(report.errorCode,"observationUnavailable")
    }
}
