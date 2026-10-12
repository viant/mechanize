import XCTest
@testable import ConsentCore

private struct VaultDiagnosticCredential: EnrollmentCredentialProvider {
    var fail = false
    func credential() throws -> Data {
        if fail { throw BrokerTransportError.missingEnrollment }
        return Data("private-enrollment-canary".utf8)
    }
}
private final class VaultDiagnosticTransport: FramedBrokerTransport {
    var methods: [String] = []
    var refused: String?
    var ready: Any = true
    var verified = true
    var closed = false
    func connectAuthenticated() throws { if !verified { throw BrokerTransportError.untrustedPeer } }
    func close() { closed = true }
    func exchange(_ request: Data) throws -> Data {
        let object = try JSONSerialization.jsonObject(with: request) as! [String: Any]
        let method = object["method"] as! String, id = object["id"] as! String
        methods.append(method)
        if refused == method { return try JSONSerialization.data(withJSONObject: ["jsonrpc":"2.0", "id":id, "error":["message":"private-remote-canary"]]) }
        let result: Any
        switch method {
        case "hello": result = ["protocolVersion":1, "sessionID":"private-session-canary", "brokerName":"private-broker-canary"]
        case "vault.status": result = ["keyReady":ready]
        case "vault.inventory": result = ["entries":[["origin":"https://private-inventory-canary.test", "accountAlias":"private-account-canary", "reference":["resourceURL":"mechanize-vault://credential/" + String(repeating:"a",count:64) + "/" + String(repeating:"b",count:64)], "revision":String(repeating:"c",count:64)]]]
        default: XCTFail("Unexpected diagnostic method"); throw BrokerTransportError.remoteRejected
        }
        return try JSONSerialization.data(withJSONObject: ["jsonrpc":"2.0", "id":id, "result":result])
    }
}
final class VaultDiagnosticsTests: XCTestCase {
    func testReadOnlyStatusInventoryAndValueFreeOutput() throws {
        let transport = VaultDiagnosticTransport()
        let report = VaultDiagnostics.runFromExplicitCLI(transport: transport, credentials: VaultDiagnosticCredential())
        XCTAssertTrue(report.succeeded); XCTAssertTrue(report.authenticated); XCTAssertEqual(report.keyReady, true); XCTAssertTrue(report.inventoryReadable)
        XCTAssertEqual(transport.methods, ["hello", "vault.status", "vault.inventory"]); XCTAssertTrue(transport.closed)
        let text = String(decoding:report.json(),as:UTF8.self)
        XCTAssertFalse(text.contains("private-")); XCTAssertFalse(text.contains("origin")); XCTAssertFalse(text.contains("resourceURL")); XCTAssertFalse(text.contains("credential"))
        let object = try JSONSerialization.jsonObject(with:report.json()) as! [String:Any]
        XCTAssertTrue(Set(object.keys).isSubset(of:["stage","authenticated","keyReady","inventoryReadable","errorCode"]))
    }
    func testFalseReadinessDoesNotInventMissingKeyOrAttemptSetup() {
        let transport = VaultDiagnosticTransport(); transport.ready = false
        let report = VaultDiagnostics.run(transport:transport,credentials:VaultDiagnosticCredential())
        XCTAssertEqual(report.stage,"keyReadiness"); XCTAssertEqual(report.errorCode,"keyNotReady"); XCTAssertEqual(report.keyReady,false)
        XCTAssertEqual(transport.methods,["hello","vault.status"]); XCTAssertFalse(report.succeeded)
    }
    func testFailuresPreserveOnlyFixedStageAndCode() {
        for (method,stage,code) in [("hello","connection","authenticationRejected"),("vault.status","keyReadiness","keyStatusUnavailable"),("vault.inventory","inventory","inventoryUnavailable")] {
            let transport = VaultDiagnosticTransport(); transport.refused = method
            let report = VaultDiagnostics.run(transport:transport,credentials:VaultDiagnosticCredential())
            XCTAssertEqual(report.stage,stage); XCTAssertEqual(report.errorCode,code); XCTAssertTrue(transport.closed)
            XCTAssertFalse(String(decoding:report.json(),as:UTF8.self).contains("private-"))
            XCTAssertFalse(report.succeeded)
        }
        let transport = VaultDiagnosticTransport(); transport.ready = 1
        let report = VaultDiagnostics.run(transport:transport,credentials:VaultDiagnosticCredential())
        XCTAssertEqual(report.errorCode,"keyStatusUnavailable"); XCTAssertNil(report.keyReady)
        XCTAssertEqual(transport.methods,["hello","vault.status"])
    }
    func testUnverifiedConnectionNeverSendsEnrollment() {
        let transport = VaultDiagnosticTransport(); transport.verified = false
        let report = VaultDiagnostics.run(transport:transport,credentials:VaultDiagnosticCredential(fail:true))
        XCTAssertEqual(report.errorCode,"untrustedPeer"); XCTAssertFalse(report.authenticated); XCTAssertTrue(transport.methods.isEmpty)
    }
}
