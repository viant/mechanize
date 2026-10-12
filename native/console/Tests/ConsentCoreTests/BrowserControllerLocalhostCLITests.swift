import XCTest
@testable import ConsentCore

private struct LocalhostCredential: EnrollmentCredentialProvider {
    var read: () throws -> Data
    func credential() throws -> Data { try read() }
}
private final class LocalhostTransport: FramedBrokerTransport {
    var mode = "ready", verified = true, closed = false
    var policy: [String: Any] = ["enabled": true, "origins": ["https://retained.fixture.test", "http://localhost:3000"]]
    var methods: [String] = []
    var configureCount = 0, statuses = 0, browserStatuses = 0
    func connectAuthenticated() throws { if !verified { throw BrokerTransportError.untrustedPeer } }
    func exchange(_ request: Data) throws -> Data {
        let input = try JSONSerialization.jsonObject(with: request) as! [String: Any]
        let method = input["method"] as! String, id = input["id"] as! String
        methods.append(method)
        let params = input["params"] as? [String: Any] ?? [:]
        let result: Any
        switch method {
        case "hello": result = ["protocolVersion": 1, "sessionID": "private-session-canary", "brokerName": "private-broker-canary"]
        case "browserStatus":
            browserStatuses += 1
            var channel: [String: Any] = ["profileChannel": "private-profile", "browserInstance": "private-browser", "trustScope": "desktop", "connected": true, "fixtureOnly": false, "processQualified": true, "scopeQualified": true, "profileQualified": false, "executorQualified": false, "inventoryComplete": false, "documentCount": 0, "pendingCount": 0, "unknownCount": 1]
            if mode == "unqualified" { channel["processQualified"] = false }
            if mode == "channelChanged" && browserStatuses > 1 { channel["browserInstance"] = "private-replacement" }
            result = ["available": true, "channels": mode == "ambiguous" ? [channel, channel] : [channel]]
        case "browserControllers":
            XCTAssertEqual(params["profileChannel"] as? String, "private-profile"); XCTAssertEqual(params["browserInstance"] as? String, "private-browser")
            if params["action"] as? String == "configure" {
                configureCount += 1; policy = params["policy"] as! [String: Any]
                if mode == "lostReply" { throw BrokerTransportError.remoteRejected }
            } else {
                XCTAssertEqual(params["action"] as? String, "status"); statuses += 1
                if mode == "policyChanged" && statuses == 2 { policy = ["enabled": true, "origins": ["https://private-new.fixture.test"]] }
                if mode == "readbackMismatch" && configureCount > 0 { policy = ["enabled": false, "origins": []] }
            }
            result = ["connected": true, "policy": policy, "sessions": []]
        default: XCTFail("Unexpected RPC"); throw BrokerTransportError.remoteRejected
        }
        return try JSONSerialization.data(withJSONObject: ["jsonrpc": "2.0", "id": id, "result": result])
    }
    func close() { closed = true }
}
final class BrowserControllerLocalhostCLITests: XCTestCase {
    private func run(_ transport: LocalhostTransport) async -> BrowserControllerLocalhostReport {
        await BrowserControllerLocalhostCLI.run(arguments: BrowserControllerLocalhostCLI.arguments, transport: transport, credentials: LocalhostCredential { Data("private-enrollment-canary".utf8) })
    }
    func testPreservesOtherOriginsAndConfirmsReadbackWithoutDOM() async throws {
        let transport = LocalhostTransport(), report = await run(transport)
        XCTAssertTrue(report.succeeded); XCTAssertEqual(report.updated, true); XCTAssertEqual(transport.configureCount, 1)
        XCTAssertEqual(transport.policy["origins"] as? [String], ["https://retained.fixture.test", "http://localhost:3000", "localhost:*"])
        XCTAssertEqual(transport.methods, ["hello", "browserStatus", "browserControllers", "browserStatus", "browserControllers", "browserControllers", "browserControllers", "browserStatus"])
        XCTAssertTrue(transport.closed)
        let output = String(decoding: report.json(), as: UTF8.self)
        XCTAssertFalse(output.contains("private")); XCTAssertFalse(output.contains("http")); XCTAssertFalse(output.contains("origins"))
        let fields = try JSONSerialization.jsonObject(with: report.json()) as! [String: Any]
        XCTAssertEqual(Set(fields.keys), ["stage", "succeeded", "updated"])
    }
    func testExistingPatternDoesNotSaveOrExtendSessions() {
        let transport = LocalhostTransport(); transport.policy = ["enabled": true, "origins": ["https://retained.fixture.test", "localhost:*"]]
        let report = BrowserControllerLocalhostCLI.runFromExplicitCLI(arguments: BrowserControllerLocalhostCLI.arguments, transport: transport, credentials: LocalhostCredential { Data("private-canary".utf8) })
        XCTAssertTrue(report.succeeded); XCTAssertEqual(report.updated, false); XCTAssertEqual(transport.configureCount, 0)
    }
    func testAmbiguityUnqualifiedAndDriftRefuseBeforeSave() async {
        for (mode, code) in [("ambiguous", "channelAmbiguous"), ("unqualified", "channelUnavailable"), ("channelChanged", "channelChanged"), ("policyChanged", "policyChanged")] {
            let transport = LocalhostTransport(); transport.mode = mode
            let report = await run(transport)
            XCTAssertFalse(report.succeeded); XCTAssertEqual(report.errorCode, code); XCTAssertEqual(transport.configureCount, 0)
            XCTAssertFalse(String(decoding: report.json(), as: UTF8.self).contains("private"))
        }
    }
    func testUnconfirmedSaveIsNeverRetriedOrReportedAbsent() async {
        for mode in ["lostReply", "readbackMismatch"] {
            let transport = LocalhostTransport(); transport.mode = mode
            let report = await run(transport)
            XCTAssertFalse(report.succeeded); XCTAssertEqual(report.errorCode, "configurationUnconfirmed"); XCTAssertNil(report.updated); XCTAssertEqual(transport.configureCount, 1)
        }
    }
    func testInvalidArgumentsAndUntrustedPeerCannotReadEnrollment() async {
        for arguments in [["--trust-localhost-controllers", "http://foreign.test"], ["--rpc", "vault.create"], []] {
            let transport = LocalhostTransport()
            let report = await BrowserControllerLocalhostCLI.run(arguments: arguments, transport: transport, credentials: LocalhostCredential { XCTFail("Invalid arguments read enrollment"); return Data() })
            XCTAssertEqual(report.errorCode, "invalidArguments"); XCTAssertTrue(transport.methods.isEmpty)
        }
        let transport = LocalhostTransport(); transport.verified = false
        let report = await BrowserControllerLocalhostCLI.run(arguments: BrowserControllerLocalhostCLI.arguments, transport: transport, credentials: LocalhostCredential { XCTFail("Unverified peer read enrollment"); return Data() })
        XCTAssertEqual(report.errorCode, "untrustedPeer"); XCTAssertTrue(transport.methods.isEmpty)
    }
    func testFullPolicyIsNotTruncatedToMakeRoom() async {
        let transport = LocalhostTransport(); let origins = (1...20).map { "https://site\($0).fixture.test" }
        transport.policy = ["enabled": true, "origins": origins]
        let report = await run(transport)
        XCTAssertEqual(report.errorCode, "policyCapacity"); XCTAssertEqual(transport.configureCount, 0); XCTAssertEqual(transport.policy["origins"] as? [String], origins)
    }
}
