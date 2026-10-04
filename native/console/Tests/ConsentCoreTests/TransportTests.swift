import XCTest
@testable import ConsentCore

private struct FixtureCredential: EnrollmentCredentialProvider {
    let value: String
    func credential() throws -> Data { Data(value.utf8) }
}
private final class FixtureTransport: FramedBrokerTransport {
    var trusted = true
    var exchanges = 0
    var requests: [[String: Any]] = []
    var reply: (([String: Any]) -> [String: Any])?
    var closed = false
    func connectAuthenticated() throws { guard trusted else { throw BrokerTransportError.untrustedPeer }; closed = false }
    func exchange(_ request: Data) throws -> Data {
        exchanges += 1
        let object = try JSONSerialization.jsonObject(with: request) as! [String: Any]; requests.append(object)
        let id = object["id"] as! String
        if let reply { return try JSONSerialization.data(withJSONObject: reply(object)) }
        if object["method"] as? String == "hello" { return try JSONSerialization.data(withJSONObject: ["jsonrpc": "2.0", "id": id, "result": ["protocolVersion": 1, "sessionID": "s", "brokerName": "Fixture"]]) }
        return try JSONSerialization.data(withJSONObject: ["jsonrpc": "2.0", "id": id, "result": ["requests": [], "grants": []]])
    }
    func close() { closed = true }
}
final class TransportTests: XCTestCase {
    func testFramingRejectsOversizeTruncationAndTrailingBytes() throws {
        let body = Data("{}".utf8); XCTAssertEqual(try BrokerFrame.decode(BrokerFrame.encode(body)), body)
        for bad in [Data(), Data([0, 0, 0, 0]), Data([0, 4, 0, 1]), Data([0, 0, 0, 2, 123]), Data([0, 0, 0, 1, 123, 125])] { XCTAssertThrowsError(try BrokerFrame.decode(bad)) }
        XCTAssertThrowsError(try BrokerFrame.encode(Data(count: BrokerFrame.maximumLength + 1)))
    }
    func testCredentialSentOnlyAfterPeerAuthentication() {
        let t = FixtureTransport(); t.trusted = false
        let b = SocketConsentBroker(transport: t, credentials: FixtureCredential(value: "secret-marker"))
        XCTAssertThrowsError(try b.connectFromUserAction()) { XCTAssertFalse($0.localizedDescription.contains("secret-marker")) }
        XCTAssertEqual(t.exchanges, 0); XCTAssertNil(b.authenticatedPeerDescription)
    }
    func testHelloAndSessionAuthenticatedEnvelope() async throws {
        let t = FixtureTransport(); let b = SocketConsentBroker(transport: t, credentials: FixtureCredential(value: "enrollment"))
        try b.connectFromUserAction(); let snapshot = try await b.snapshot(); XCTAssertTrue(snapshot.grants.isEmpty)
        XCTAssertEqual(t.requests[0]["method"] as? String, "hello")
        let hello = t.requests[0]["params"] as! [String: Any]; XCTAssertEqual(hello["credential"] as? String, "enrollment")
        let p = t.requests[1]["params"] as! [String: Any]; XCTAssertEqual(p["sessionID"] as? String, "s"); XCTAssertNil(p["credential"])
    }
    func testMismatchedIDFailsClosedAndDoesNotLogCredential() {
        let t = FixtureTransport(); t.reply = { _ in ["jsonrpc": "2.0", "id": "wrong", "result": "secret-marker"] }
        let b = SocketConsentBroker(transport: t, credentials: FixtureCredential(value: "secret-marker"))
        XCTAssertThrowsError(try b.connectFromUserAction()) { XCTAssertFalse($0.localizedDescription.contains("secret-marker")) }
        XCTAssertNil(b.authenticatedPeerDescription); XCTAssertTrue(t.closed)
    }
    func testUnknownRevokeStatusDisconnects() async throws {
        let t = FixtureTransport(); let b = SocketConsentBroker(transport: t, credentials: FixtureCredential(value: "credential")); try b.connectFromUserAction()
        t.reply = { r in ["jsonrpc": "2.0", "id": r["id"]!, "result": ["status": "successMaybe"]] }
        do { _ = try await b.revoke(grantID: "g"); XCTFail("Accepted unknown revoke status") } catch { XCTAssertNil(b.authenticatedPeerDescription); XCTAssertTrue(t.closed) }
    }
    func testRemoteErrorDetailsNeverReachUI() {
        let t = FixtureTransport(); t.reply = { r in ["jsonrpc": "2.0", "id": r["id"]!, "error": ["code": -1, "message": "secret-marker"]] }
        let b = SocketConsentBroker(transport: t, credentials: FixtureCredential(value: "secret-marker"))
        XCTAssertThrowsError(try b.connectFromUserAction()) { XCTAssertEqual($0.localizedDescription, "Broker rejected the request.") }
        XCTAssertNil(b.authenticatedPeerDescription); XCTAssertTrue(t.closed)
    }
    func testValidatedRemoteRejectionKeepsAuthenticatedSessionUsable() async throws {
        let t = FixtureTransport(); let b = SocketConsentBroker(transport: t, credentials: FixtureCredential(value: "credential"))
        try b.connectFromUserAction()
        t.reply = { r in ["jsonrpc": "2.0", "id": r["id"]!, "error": ["code": -1, "message": "revision conflict"]] }
        do { _ = try await b.applicationAccess(); XCTFail("Expected remote rejection") }
        catch { XCTAssertEqual(error.localizedDescription, "Broker rejected the request.") }
        XCTAssertEqual(b.authenticatedPeerDescription, "Fixture")
        XCTAssertFalse(t.closed)
        t.reply = nil
        let snapshot = try await b.snapshot()
        XCTAssertTrue(snapshot.grants.isEmpty)
        XCTAssertEqual(b.authenticatedPeerDescription, "Fixture")
        XCTAssertFalse(t.closed)
    }
    func testMalformedCallResponseStillDisconnects() async throws {
        let t = FixtureTransport(); let b = SocketConsentBroker(transport: t, credentials: FixtureCredential(value: "credential"))
        try b.connectFromUserAction()
        t.reply = { r in ["jsonrpc": "2.0", "id": "wrong", "result": ["requests": [], "grants": []]] }
        do { _ = try await b.snapshot(); XCTFail("Accepted mismatched response ID") }
        catch { XCTAssertEqual(error.localizedDescription, "Broker response is malformed or mismatched.") }
        XCTAssertNil(b.authenticatedPeerDescription)
        XCTAssertTrue(t.closed)
    }
    func testMalformedJSONTypesAndAmbiguousEnvelopeRejected() {
        for result in [NSNull(), ["jsonrpc": "2.0", "id": 1] as [String: Any]] as [Any] {
            let t = FixtureTransport(); t.reply = { r in ["jsonrpc": "2.0", "id": r["id"]!, "result": result, "error": ["code": 0]] }
            XCTAssertThrowsError(try SocketConsentBroker(transport: t, credentials: FixtureCredential(value: "x")).connectFromUserAction())
        }
    }
}
