import XCTest
@testable import ConsentCore

private struct DiagnosticFixtureCredential: EnrollmentCredentialProvider {
    let read: () throws -> Data
    func credential() throws -> Data { try read() }
}
private final class DiagnosticFixtureTransport: FramedBrokerTransport {
    var verified = true
    var methods: [String] = []
    var errorMethod: String?
    var closed = false
    func connectAuthenticated() throws { if !verified { throw BrokerTransportError.untrustedPeer } }
    func exchange(_ request: Data) throws -> Data {
        let object = try JSONSerialization.jsonObject(with: request) as! [String: Any]
        let method = object["method"] as! String; methods.append(method)
        let id = object["id"] as! String
        if method == errorMethod {
            return try JSONSerialization.data(withJSONObject: ["jsonrpc": "2.0", "id": id, "error": ["message": "private-error-marker"]])
        }
        let result: Any
        switch method {
        case "hello": result = ["protocolVersion": 1, "sessionID": "private-session-marker", "brokerName": "private-broker-marker"]
        case "snapshot": result = ["requests": [], "grants": []]
        case "inventory", "helperPermissionDoctor": result = []
        default: XCTFail("Diagnostic dispatched mutation or settings operation: " + method); throw BrokerTransportError.remoteRejected
        }
        return try JSONSerialization.data(withJSONObject: ["jsonrpc": "2.0", "id": id, "result": result])
    }
    func close() { closed = true }
}
final class ConnectionDiagnosticsTests: XCTestCase {
    func testReadOnlySequenceAndScalarOutput() async throws {
        let transport = DiagnosticFixtureTransport()
        let credential = DiagnosticFixtureCredential { Data("private-token-marker".utf8) }
        let report = await ConnectionDiagnostics.run(transport: transport, credentials: credential)
        XCTAssertTrue(report.succeeded); XCTAssertTrue(report.brokerVerified); XCTAssertTrue(report.credentialAvailable); XCTAssertTrue(report.authenticated)
        XCTAssertEqual(transport.methods, ["hello", "snapshot", "inventory", "helperPermissionDoctor"])
        XCTAssertTrue(transport.closed)
        let output = String(decoding: report.json(), as: UTF8.self)
        XCTAssertFalse(output.contains("private-")); XCTAssertFalse(output.contains("requests")); XCTAssertFalse(output.contains("grants"))
        let object = try JSONSerialization.jsonObject(with: report.json()) as! [String: Any]
        XCTAssertTrue(Set(object.keys).isSubset(of: ["stage", "brokerVerified", "credentialAvailable", "authenticated", "errorCode"]))
    }
    func testUnverifiedPeerDoesNotLoadCredential() async {
        let transport = DiagnosticFixtureTransport(); transport.verified = false
        let report = await ConnectionDiagnostics.run(transport: transport, credentials: DiagnosticFixtureCredential { XCTFail("Credential loaded before signed peer verification"); return Data() })
        XCTAssertEqual(report.stage, "broker"); XCTAssertEqual(report.errorCode, "untrustedPeer")
        XCTAssertFalse(report.brokerVerified); XCTAssertFalse(report.credentialAvailable); XCTAssertFalse(report.authenticated)
        XCTAssertTrue(transport.methods.isEmpty); XCTAssertTrue(transport.closed)
    }
    func testMissingSelectedCredentialCannotAuthenticateOrReadSnapshot() async {
        let transport = DiagnosticFixtureTransport()
        let report = await ConnectionDiagnostics.run(transport: transport, credentials: DiagnosticFixtureCredential { throw BrokerTransportError.missingEnrollment })
        XCTAssertEqual(report.stage, "credential"); XCTAssertEqual(report.errorCode, "missingEnrollment")
        XCTAssertTrue(report.brokerVerified); XCTAssertFalse(report.credentialAvailable); XCTAssertFalse(report.authenticated)
        XCTAssertTrue(transport.methods.isEmpty)
    }
    func testRemoteFailuresAreStagefulAndNeverIncludePrivateError() async {
        for (method, stage) in [("hello", "authentication"), ("snapshot", "snapshot"), ("inventory", "inventory"), ("helperPermissionDoctor", "permissions")] {
            let transport = DiagnosticFixtureTransport(); transport.errorMethod = method
            let report = await ConnectionDiagnostics.run(transport: transport, credentials: DiagnosticFixtureCredential { Data("private-token-marker".utf8) })
            XCTAssertEqual(report.stage, stage); XCTAssertEqual(report.errorCode, "remoteRejected")
            XCTAssertTrue(report.brokerVerified); XCTAssertTrue(report.credentialAvailable)
            // A validated application-level rejection after hello does not undo
            // peer authentication. The diagnostic still fails at its actual stage.
            XCTAssertEqual(report.authenticated, method != "hello")
            XCTAssertFalse(report.succeeded)
            XCTAssertFalse(String(decoding: report.json(), as: UTF8.self).contains("private-"))
            XCTAssertFalse(transport.methods.contains("decide")); XCTAssertFalse(transport.methods.contains("revoke"))
        }
    }
    func testExplicitCLIUsesSameReadOnlyFlow() {
        let transport = DiagnosticFixtureTransport()
        let report = ConnectionDiagnostics.runFromExplicitCLI(transport: transport, credentials: DiagnosticFixtureCredential { Data("fixture".utf8) })
        XCTAssertTrue(report.succeeded)
        XCTAssertEqual(transport.methods, ["hello", "snapshot", "inventory", "helperPermissionDoctor"])
    }
}
