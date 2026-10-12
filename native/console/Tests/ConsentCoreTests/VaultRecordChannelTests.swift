import XCTest
@testable import ConsentCore

private struct RecordEnrollment: EnrollmentCredentialProvider {
    func credential() throws -> Data { Data("synthetic-enrollment".utf8) }
}
private final class RecordTransport: NativeVaultRecordBinaryTransport {
    var admission: Any = ["nativeInputReady": true]
    var denied = false, wrongID = false, lostReply = false, closed = false
    var calls = 0
    var requestID = ""
    var metadata: Data = Data()
    func connectAuthenticated() throws {}
    func exchange(_ data: Data) throws -> Data {
        let object = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        let id = object["id"] as! String
        if object["method"] as? String == "hello" {
            return try JSONSerialization.data(withJSONObject: ["jsonrpc": "2.0", "id": id,
                "result": ["protocolVersion": 1, "sessionID": String(repeating: "a", count: 48), "brokerName": "Mechanize"]])
        }
        metadata = data; requestID = id
        if denied { return try JSONSerialization.data(withJSONObject: ["jsonrpc": "2.0", "id": id, "error": ["message": "synthetic-private-error"]]) }
        return try JSONSerialization.data(withJSONObject: ["jsonrpc": "2.0", "id": wrongID ? "wrong" : id, "result": admission])
    }
    func sendNativeRecordFrame(_ frame: VaultRecordFrame) throws -> Data {
        calls += 1
        try frame.writeOnce { raw in XCTAssertEqual(Array(raw.prefix(8)), [77, 86, 76, 84, 0, 0, 0, 2]) }
        if lostReply { throw BrokerTransportError.unavailable }
        return try JSONSerialization.data(withJSONObject: ["jsonrpc": "2.0", "id": requestID,
            "result": ["reference": ["id": String(repeating: "b", count: 64)], "revision": String(repeating: "c", count: 64)]])
    }
    func close() { closed = true }
}
final class VaultRecordChannelTests: XCTestCase {
    private let entryID = String(repeating: "d", count: 64)
    private var request: VaultEntryRequest { VaultEntryRequest(id: "fixture", origin: "https://vault.mechanize.invalid",
        accountAlias: "account-00000000-0000-0000-0000-000000000000", expiresAt: Date().addingTimeInterval(60)) }
    private func frame() throws -> VaultRecordFrame {
        var key = Data("private-key-canary".utf8)
        var fields = [(name: Data("private-name-canary".utf8), value: Data("private-value-canary".utf8))]
        return try VaultRecordFrame(key: &key, fields: &fields)
    }
    private func client(_ transport: RecordTransport) throws -> SocketConsentBroker {
        let client = SocketConsentBroker(transport: transport, credentials: RecordEnrollment())
        try client.connectFromUserAction(); return client
    }
    func testAdmittedRecordUsesOnlyOpaqueJSONAndSingleBinaryWrite() throws {
        let transport = RecordTransport(), input = try frame()
        let result = try client(transport).submitNativeRecord(request: request, entryID: entryID, frame: input)
        XCTAssertEqual(result.id, String(repeating: "b", count: 64)); XCTAssertEqual(transport.calls, 1)
        XCTAssertTrue(transport.closed)
        let text = String(decoding: transport.metadata, as: UTF8.self)
        for forbidden in ["canary", "origin", "password", "username"] { XCTAssertFalse(text.contains(forbidden)) }
        XCTAssertThrowsError(try input.writeOnce { _ in XCTFail("frame replayed") })
    }
    func testRejectedOrMalformedAdmissionNeverSendsSecretBytesAndDestroysFrame() throws {
        for mode in ["denied", "id", "numeric", "false", "extra"] {
            let transport = RecordTransport(), input = try frame()
            switch mode {
            case "denied": transport.denied = true
            case "id": transport.wrongID = true
            case "numeric": transport.admission = ["nativeInputReady": 1]
            case "false": transport.admission = ["nativeInputReady": false]
            default: transport.admission = ["nativeInputReady": true, "unexpected": "value"]
            }
            XCTAssertThrowsError(try client(transport).submitNativeRecord(request: request, entryID: entryID, frame: input))
            XCTAssertEqual(transport.calls, 0); XCTAssertTrue(transport.closed)
            XCTAssertThrowsError(try input.writeOnce { _ in XCTFail("rejected input retained") })
        }
    }
    func testLostAcknowledgementIsUnknownAndCannotReplay() throws {
        let transport = RecordTransport(), input = try frame(); transport.lostReply = true
        XCTAssertThrowsError(try client(transport).submitNativeRecord(request: request, entryID: entryID, frame: input)) {
            guard case VaultNativeChannelError.outcomeUnknown = $0 else { return XCTFail("lost write treated as safe retry") }
        }
        XCTAssertEqual(transport.calls, 1); XCTAssertTrue(transport.closed)
        XCTAssertThrowsError(try input.writeOnce { _ in XCTFail("lost acknowledgement replayed") })
    }
    func testInvalidMetadataRejectsBeforeExchangeOrBytes() throws {
        let transport = RecordTransport(), input = try frame()
        XCTAssertThrowsError(try client(transport).submitNativeRecord(request: request, entryID: "invalid", frame: input))
        XCTAssertTrue(transport.metadata.isEmpty); XCTAssertEqual(transport.calls, 0)
        XCTAssertThrowsError(try input.writeOnce { _ in XCTFail("invalid input retained") })
    }
    func testUpdateCarriesOnlyOpaqueRevisionAndDeleteHasNoFrame() throws {
        let record = VaultRecordMetadata(id: String(repeating: "b", count: 64), revision: String(repeating: "c", count: 64))
        let update = RecordTransport()
        _ = try client(update).submitNativeRecord(request: request, entryID: entryID, replacing: record, frame: frame())
        let object = try JSONSerialization.jsonObject(with: update.metadata) as! [String: Any]
        XCTAssertEqual(object["method"] as? String, "vault.record.update")
        let params = object["params"] as! [String: Any]
        XCTAssertEqual(Set(params.keys), ["sessionID", "entryID", "accountAlias", "refID", "revision"])
        let deletion = RecordTransport(); deletion.admission = ["deleted": true]
        try client(deletion).deleteNativeRecord(request: request, entryID: entryID, record: record)
        XCTAssertEqual(deletion.calls, 0); XCTAssertTrue(deletion.closed)
    }
    func testRecordReadyAndInventoryReturnOnlyClosedOpaqueMetadata() throws {
        let transport = RecordTransport(), broker = try client(transport)
        transport.admission = ["recordReady": true]
        XCTAssertTrue(try broker.nativeRecordReady())
        let row: [String: Any] = ["reference": ["id": String(repeating: "b", count: 64)], "revision": String(repeating: "c", count: 64)]
        transport.admission = ["entries": [row]]
        XCTAssertEqual(try broker.nativeRecordInventory().count, 1)
        transport.admission = ["entries": [row, row]]
        XCTAssertThrowsError(try broker.nativeRecordInventory())
        XCTAssertEqual(transport.calls, 0)
    }
}
