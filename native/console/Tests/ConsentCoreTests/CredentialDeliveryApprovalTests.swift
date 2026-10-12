import XCTest
@testable import ConsentCore

private final class ApprovalBrokerFixture: NativeCredentialApprovalBroker {
    var pending: [NativeCredentialRequest] = []
    var records: [VaultRecordMetadata] = []
    var binds: [(String, VaultRecordMetadata)] = []
    var cancelled: [String] = []
    var fail = false
    func pendingCredentialRequests() async throws -> [NativeCredentialRequest] { if fail { throw BrokerTransportError.unavailable }; return pending }
    func credentialRecordReferences() async throws -> [VaultRecordMetadata] { records }
    func bindCredentialRequest(id: String, record: VaultRecordMetadata) async throws {
        binds.append((id, record)); if fail { throw BrokerTransportError.unavailable }
        pending.removeAll { $0.id == id }
    }
    func cancelCredentialRequest(id: String) async throws { cancelled.append(id); pending.removeAll { $0.id == id } }
}

@MainActor final class CredentialDeliveryApprovalTests: XCTestCase {
    func request(expired: Bool = false) throws -> NativeCredentialRequest {
        try NativeCredentialRequest(id: String(repeating: "a", count: 64), origin: "https://fixture.test", clientId: "verified-tool", purpose: "Sign in locally", expiresAt: Date().addingTimeInterval(expired ? -1 : 60))
    }
    func record() -> VaultRecordMetadata { VaultRecordMetadata(id: String(repeating: "b", count: 64), revision: String(repeating: "c", count: 64)) }
    func testMetadataDecoderRejectsSecretFieldsDuplicateIDsAndMalformedOrigins() throws {
        let row: [String: Any] = ["id": String(repeating: "a", count: 64), "origin": "https://fixture.test", "clientId": "tool", "purpose": "Sign in", "expiresAt": "2026-10-07T22:00:00Z"]
        XCTAssertEqual(try NativeCredentialRequest.decode(JSONSerialization.data(withJSONObject: [row])).count, 1)
        var secret = row; secret["password"] = "synthetic-private-value"
        var origin = row; origin["origin"] = "https://user:pass@fixture.test"
        for rows in [[secret], [row, row], [origin]] {
            XCTAssertThrowsError(try NativeCredentialRequest.decode(JSONSerialization.data(withJSONObject: rows)))
        }
    }
    func testRevisionSelectionAndExpiryCheckedBeforeBind() async throws {
        let broker = ApprovalBrokerFixture(); broker.pending = [try request()]; broker.records = [record()]
        let model = CredentialDeliveryApprovalModel(broker: broker)
        await model.refresh()
        let wrong = VaultRecordMetadata(id: record().id, revision: String(repeating: "d", count: 64))
        XCTAssertFalse(model.canBind(broker.pending[0], record: wrong))
        XCTAssertFalse(model.canBind(try request(expired: true), record: record()))
        XCTAssertTrue(model.canBind(broker.pending[0], record: record()))
        await model.bind(broker.pending[0], record: record())
        XCTAssertEqual(broker.binds.count, 1); XCTAssertEqual(broker.binds[0].1.revision, record().revision)
        XCTAssertTrue(model.requests.isEmpty)
    }
    func testUncertainBindIsNotRetriedBeforeFreshPendingEvidence() async throws {
        let broker = ApprovalBrokerFixture(); let pending = try request(); broker.pending = [pending]; broker.records = [record()]
        let model = CredentialDeliveryApprovalModel(broker: broker); await model.refresh(); broker.fail = true
        await model.bind(pending, record: record()); await model.bind(pending, record: record())
        XCTAssertEqual(broker.binds.count, 1); XCTAssertFalse(model.canBind(pending, record: record()))
        await model.refresh(); XCTAssertTrue(model.requests.isEmpty)
        broker.fail = false; await model.refresh()
        XCTAssertTrue(model.canBind(pending, record: record()))
    }
    func testCancelUsesOnlyRequestReference() async throws {
        let broker = ApprovalBrokerFixture(); let pending = try request(); broker.pending = [pending]; broker.records = [record()]
        let model = CredentialDeliveryApprovalModel(broker: broker); await model.refresh(); await model.cancel(pending)
        XCTAssertEqual(broker.cancelled, [pending.id]); XCTAssertTrue(broker.binds.isEmpty); XCTAssertTrue(model.requests.isEmpty)
    }
}
