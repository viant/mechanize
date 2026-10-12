import XCTest
@testable import ConsentCore

final class MigrationObserverLiveTests: XCTestCase {
    func testEnrolledReadOnlyObserverAgainstLiveOwnedBroker() throws {
        guard let path = ProcessInfo.processInfo.environment["MECHANIZE_TEST_OBSERVER_REVIEW_PATH"] else {
            throw XCTSkip("Explicit owned live observer fixture only")
        }
        let root = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: URL(fileURLWithPath:path))) as? [String:Any])
        let value = try XCTUnwrap(root["observer"] as? [String:Any])
        let binding = try MigrationObserverConsentBinding(value["consentBinding"])
        let enrollment = try MigrationObserverReaderEnrollment(
            port: try XCTUnwrap(value["port"] as? NSNumber).uint16Value,
            brokerPID: try XCTUnwrap(value["brokerPID"] as? NSNumber).int32Value,
            brokerStart: try XCTUnwrap(value["brokerStart"] as? String),
            brokerRequirement: try XCTUnwrap(value["brokerRequirement"] as? String),
            credentialURL: URL(fileURLWithPath:try XCTUnwrap(value["credentialURL"] as? String)),
            credentialSHA256: try XCTUnwrap(value["credentialSHA256"] as? String), consentBinding:binding)
        var phase = MigrationObserverReadPhase.validation
        do {
            let data = try MigrationObserverMCPReader(enrollment).observe(
                chromePID:try XCTUnwrap(value["chromePID"] as? NSNumber).int32Value,
                chromeStart:try XCTUnwrap(value["chromeStart"] as? String),
                windowTitle:try XCTUnwrap(value["windowTitle"] as? String),
                deadline:Date().addingTimeInterval(10),onPhase:{ phase=$0 })
            let observation = try XCTUnwrap(JSONSerialization.jsonObject(with:data) as? [String:Any])
            XCTAssertFalse(try XCTUnwrap(observation["nodes"] as? [Any]).isEmpty)
        } catch {
            XCTFail("Live observer failed at closed phase: \(phase.rawValue)")
        }
    }
}
