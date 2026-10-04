import XCTest
@testable import ConsentCore

private struct ApplicationAccessCredential: EnrollmentCredentialProvider {
    func credential() throws -> Data { Data("fixture-token".utf8) }
}

private final class ApplicationAccessTransport: FramedBrokerTransport {
    var requests: [[String: Any]] = []
    func connectAuthenticated() throws {}
    func exchange(_ request: Data) throws -> Data {
        let object = try JSONSerialization.jsonObject(with: request) as! [String: Any]
        requests.append(object)
        let id = object["id"] as! String
        let result: Any
        switch object["method"] as! String {
        case "hello":
            result = ["protocolVersion": 1, "sessionID": "fixture-session", "brokerName": "Fixture"]
        case "applicationAccess.get", "applicationAccess.set":
            result = [
                "revision": 8,
                "policy": ["desktopWide": false, "applications": [["bundleID": "com.example.Editor", "displayName": "Editor", "modes": ["observe", "control"]]]],
                "rows": [["bundleID": "com.example.Editor", "displayName": "Editor", "modes": ["observe", "control"], "status": "configured", "detail": "Explicitly configured"]]
            ]
        default:
            throw BrokerTransportError.remoteRejected
        }
        return try JSONSerialization.data(withJSONObject: ["jsonrpc": "2.0", "id": id, "result": result])
    }
    func close() {}
}

final class ApplicationAccessTests: XCTestCase {
    func testModelsRoundTripThroughConsentWire() throws {
        let policy = ApplicationAccessPolicy(desktopWide: true, applications: [
            ApplicationAccessRule(bundleID: "com.example.Editor", displayName: "Editor", modes: [.observe, .record])
        ])
        let snapshot = ApplicationAccessSnapshot(revision: 3, policy: policy, rows: [
            ApplicationAccessEntry(bundleID: "com.example.Editor", displayName: "Editor", modes: [.observe, .record], status: "configured", detail: "Configured by user")
        ])
        let data = try ConsentWire.encoder().encode(snapshot)
        XCTAssertEqual(try ConsentWire.decoder().decode(ApplicationAccessSnapshot.self, from: data), snapshot)
    }

    func testBrokerUsesVersionedApplicationAccessRPCs() async throws {
        let transport = ApplicationAccessTransport()
        let broker = SocketConsentBroker(transport: transport, credentials: ApplicationAccessCredential())
        try broker.connectFromUserAction()

        let read = try await broker.applicationAccess()
        XCTAssertEqual(read.revision, 8)
        XCTAssertEqual(read.rows.first?.status, "configured")

        let policy = ApplicationAccessPolicy(desktopWide: true, applications: [
            ApplicationAccessRule(bundleID: "com.example.Editor", displayName: "Editor", modes: [.observe])
        ])
        let updated = try await broker.updateApplicationAccess(expectedRevision: 7, policy: policy)
        XCTAssertEqual(updated.revision, 8)

        XCTAssertEqual(transport.requests.map { $0["method"] as? String }, ["hello", "applicationAccess.get", "applicationAccess.set"])
        let params = try XCTUnwrap(transport.requests.last?["params"] as? [String: Any])
        XCTAssertEqual(params["sessionID"] as? String, "fixture-session")
        XCTAssertEqual(params["expectedRevision"] as? Int, 7)
        let sentPolicy = try XCTUnwrap(params["policy"] as? [String: Any])
        XCTAssertEqual(sentPolicy["desktopWide"] as? Bool, true)
        let applications = try XCTUnwrap(sentPolicy["applications"] as? [[String: Any]])
        XCTAssertEqual(applications.first?["bundleID"] as? String, "com.example.Editor")
        XCTAssertEqual(applications.first?["modes"] as? [String], ["observe"])
    }
}
