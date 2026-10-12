import XCTest
@testable import ConsentCore

private struct VaultFixtureCredential: EnrollmentCredentialProvider {
    func credential() throws -> Data { Data("synthetic-enrollment".utf8) }
}
private final class VaultFixtureTransport: NativeVaultBinaryTransport {
    var admission: Any = ["nativeInputReady": true]
    var deny = false
    var wrongID = false
    var loseReply = false
    var closed = false
    var binaryCalls = 0
    var routing: [[String: Any]] = []
    var requestID = ""
    let reference = "mechanize-vault://credential/" + String(repeating: "a", count: 64) + "/" + String(repeating: "b", count: 64)
    func connectAuthenticated() throws {}
    func exchange(_ request: Data) throws -> Data {
        let object = try JSONSerialization.jsonObject(with: request) as! [String: Any]
        let method = object["method"] as! String
        let id = object["id"] as! String
        if method == "hello" {
            return try JSONSerialization.data(withJSONObject: ["jsonrpc":"2.0","id":id,"result":["protocolVersion":1,"sessionID":"synthetic-session","brokerName":"Mechanize"]])
        }
        routing.append(object); requestID = id
        if deny { return try JSONSerialization.data(withJSONObject:["jsonrpc":"2.0","id":id,"error":["message":"synthetic-private-error"]]) }
        return try JSONSerialization.data(withJSONObject:["jsonrpc":"2.0","id":wrongID ? "wrong" : id,"result":admission])
    }
    func sendNativeVaultFrame(username: Data, password: Data) throws -> Data {
        binaryCalls += 1
        if loseReply { throw BrokerTransportError.unavailable }
        return try JSONSerialization.data(withJSONObject:["jsonrpc":"2.0","id":requestID,"result":["reference":["resourceURL":reference]]])
    }
    func close() { closed = true }
}
final class VaultNativeChannelTests: XCTestCase {
    var request: VaultEntryRequest { VaultEntryRequest(id:"synthetic-request",origin:"https://example.test",accountAlias:"fixture-account",expiresAt:Date().addingTimeInterval(60)) }
    private func broker(_ transport: VaultFixtureTransport) throws -> SocketConsentBroker {
        let broker = SocketConsentBroker(transport:transport,credentials:VaultFixtureCredential())
        try broker.connectFromUserAction();return broker
    }
    func testAdmittedInputNeverUsesGenericJSONAndReturnsOnlyReference() throws {
        let transport=VaultFixtureTransport();let client=try broker(transport)
        let reference=try client.submitNativeVault(request:request,entryID:String(repeating:"c",count:64),username:Data("synthetic-user-canary".utf8),password:Data("synthetic-password-canary".utf8))
        XCTAssertEqual(reference,transport.reference);XCTAssertEqual(transport.binaryCalls,1)
        let raw=String(decoding:try JSONSerialization.data(withJSONObject:transport.routing),as:UTF8.self)
        XCTAssertFalse(raw.contains("canary"));XCTAssertFalse(raw.contains("username"));XCTAssertFalse(raw.contains("password"))
        XCTAssertTrue(transport.closed);XCTAssertNil(client.authenticatedPeerDescription)
    }
    func testRefusalMalformedAndMismatchedAdmissionNeverReleaseBytes() throws {
        for mode in ["denied","id","number","string","extra"] {
            let transport=VaultFixtureTransport()
            switch mode {
            case "denied":transport.deny=true
            case "id":transport.wrongID=true
            case "number":transport.admission=["nativeInputReady":1]
            case "string":transport.admission=["nativeInputReady":"true"]
            default:transport.admission=["nativeInputReady":true,"unexpected":"value"]
            }
            let client=try broker(transport)
            XCTAssertThrowsError(try client.submitNativeVault(request:request,entryID:String(repeating:"c",count:64),username:Data([97]),password:Data([98])))
            XCTAssertEqual(transport.binaryCalls,0);XCTAssertTrue(transport.closed)
        }
    }
    func testLostAcknowledgementIsUnknownAndDoesNotReplay() throws {
        let transport=VaultFixtureTransport();transport.loseReply=true;let client=try broker(transport)
        XCTAssertThrowsError(try client.submitNativeVault(request:request,entryID:String(repeating:"c",count:64),username:Data([97]),password:Data([98]))) { error in
            guard case VaultNativeChannelError.outcomeUnknown = error else { return XCTFail("Lost acknowledgement classified as safe retry") }
        }
        XCTAssertEqual(transport.binaryCalls,1);XCTAssertNil(client.authenticatedPeerDescription)
    }
    func testOpaqueReferencesRejectArbitraryOrCredentialURLs() {
        XCTAssertFalse(nativeVaultReference("https://user:secret@example.test"))
        XCTAssertFalse(nativeVaultReference("mechanize-vault://credential/invalid/value"))
    }
    func testLifecycleStrictBeginCloseAndPublicMetadataOnly() throws {
        let transport = VaultFixtureTransport()
        let entryID = String(repeating: "c", count: 64)
        transport.admission = ["entryID": entryID]
        let client = try broker(transport)
        XCTAssertEqual(try client.beginNativeVaultEntry(request: request), entryID)
        XCTAssertFalse(transport.closed)
        transport.admission = ["entryProtected": true]
        try client.confirmNativeVaultEntry(entryID: entryID)
        transport.admission = ["entryClosed": true]
        try client.closeNativeVaultEntry(entryID: entryID)
        XCTAssertFalse(transport.closed)
        XCTAssertEqual(transport.binaryCalls, 0)
        let metadata = String(decoding: try JSONSerialization.data(withJSONObject: transport.routing), as: UTF8.self)
        XCTAssertFalse(metadata.contains("username")); XCTAssertFalse(metadata.contains("password"))
        XCTAssertTrue(metadata.contains("vault.entry.begin")); XCTAssertTrue(metadata.contains("vault.entry.confirm")); XCTAssertTrue(metadata.contains("vault.entry.close"))
    }
    func testMalformedLifecycleResponsesRetainUnknownProtectionAndCloseConnection() throws {
        for mode in ["id", "entry-id", "extra", "numeric-close", "numeric-confirm", "false-confirm", "rejection"] {
            let transport = VaultFixtureTransport()
            transport.admission = ["entryID": String(repeating: "c", count: 64)]
            switch mode {
            case "id": transport.wrongID = true
            case "entry-id": transport.admission = ["entryID": "invalid"]
            case "extra": transport.admission = ["entryID": String(repeating: "c", count: 64), "cleanupConfirmed": true]
            case "numeric-close": transport.admission = ["entryClosed": 1]
            case "numeric-confirm": transport.admission = ["entryProtected": 1]
            case "false-confirm": transport.admission = ["entryProtected": false]
            default: transport.deny = true
            }
            let client = try broker(transport)
            XCTAssertThrowsError(try {
                if mode == "numeric-close" { try client.recoverNativeVaultEntry() }
                else if mode == "numeric-confirm" || mode == "false-confirm" { try client.confirmNativeVaultEntry(entryID: String(repeating: "c", count: 64)) }
                else { _ = try client.beginNativeVaultEntry(request: request) }
            }()) { error in
                guard case VaultNativeChannelError.protectionUnknown = error else { return XCTFail("Lifecycle uncertainty discarded") }
            }
            XCTAssertTrue(transport.closed); XCTAssertNil(client.authenticatedPeerDescription)
            XCTAssertEqual(transport.binaryCalls, 0)
        }
    }
    func testInvalidProtectionIDNeverReleasesCredentials() throws {
        let transport = VaultFixtureTransport(); let client = try broker(transport)
        XCTAssertThrowsError(try client.submitNativeVault(request: request, entryID: "invalid", username: Data([97]), password: Data([98])))
        XCTAssertTrue(transport.routing.isEmpty); XCTAssertEqual(transport.binaryCalls, 0)
    }
    func testKeySetupAndStatusUseOnlyBooleanMetadata() throws {
        let transport = VaultFixtureTransport(); let client = try broker(transport)
        transport.admission = ["keyReady": false]
        XCTAssertFalse(try client.nativeVaultKeyReady())
        transport.admission = ["keyReady": true]
        try client.setupNativeVaultKey()
        XCTAssertTrue(try client.nativeVaultKeyReady())
        XCTAssertEqual(transport.binaryCalls, 0)
        for request in transport.routing {
            let params = request["params"] as! [String: Any]
            XCTAssertEqual(Set(params.keys), ["sessionID"])
        }
    }
    func testMalformedOrRefusedKeySetupIsUnknownAndNeverReleasesInput() throws {
        for mode in ["number", "extra", "denied", "id"] {
            let transport = VaultFixtureTransport()
            switch mode {
            case "number": transport.admission = ["keyReady": 1]
            case "extra": transport.admission = ["keyReady": true, "key": "synthetic-key-canary"]
            case "denied": transport.deny = true
            default: transport.wrongID = true
            }
            let client = try broker(transport)
            XCTAssertThrowsError(try client.setupNativeVaultKey()) { error in
                guard case VaultNativeChannelError.keySetupUnknown = error else { return XCTFail("Unsafe setup retry classification") }
            }
            XCTAssertTrue(transport.closed); XCTAssertEqual(transport.binaryCalls, 0)
        }
    }
    func testInventoryAcceptsOnlyPublicMetadataAndNoExtraSecretFields() throws {
        let transport = VaultFixtureTransport(); let client = try broker(transport)
        let row: [String: Any] = ["origin": request.origin, "accountAlias": request.accountAlias,
            "reference": ["resourceURL": transport.reference], "revision": String(repeating: "d", count: 64)]
        transport.admission = ["entries": [row]]
        let rows = try client.nativeVaultInventory()
        XCTAssertEqual(rows.count, 1); XCTAssertEqual(rows[0].resourceURL, transport.reference)
        XCTAssertEqual(rows[0].request().origin, request.origin)
        XCTAssertEqual(transport.binaryCalls, 0)
        XCTAssertEqual(Set((transport.routing[0]["params"] as! [String: Any]).keys), ["sessionID"])
        for field in ["username", "password", "unexpected"] {
            var bad = row; bad[field] = "synthetic-private-value"
            XCTAssertThrowsError(try parseNativeVaultInventory(["entries": [bad]]))
        }
        XCTAssertThrowsError(try parseNativeVaultInventory(["entries": [row, row]]))
        var bad = row; bad["origin"] = "https://user:secret@example.test"
        XCTAssertThrowsError(try parseNativeVaultInventory(["entries": [bad]]))
        bad = row; bad["revision"] = "invalid"
        XCTAssertThrowsError(try parseNativeVaultInventory(["entries": [bad]]))
        bad = row; bad["reference"] = ["resourceURL": transport.reference, "username": "synthetic-private-value"]
        XCTAssertThrowsError(try parseNativeVaultInventory(["entries": [bad]]))
    }
    func testBindPreservesOpaqueAliasAndRequiresExactBooleanAcknowledgement() throws {
        let entryID = String(repeating: "c", count: 64)
        let transport = VaultFixtureTransport(); let client = try broker(transport)
        transport.admission = ["entryBound": true]
        try client.bindNativeVaultEntry(entryID: entryID, origin: request.origin)
        let params = transport.routing[0]["params"] as! [String: Any]
        XCTAssertEqual(Set(params.keys), ["sessionID", "entryID", "origin"])
        XCTAssertEqual(transport.binaryCalls, 0)
        for result: [String: Any] in [["entryBound": 1], ["entryBound": false], ["entryBound": true, "extra": true]] {
            let invalid = VaultFixtureTransport(); let session = try broker(invalid); invalid.admission = result
            XCTAssertThrowsError(try session.bindNativeVaultEntry(entryID: entryID, origin: request.origin))
            XCTAssertTrue(invalid.closed); XCTAssertNil(session.authenticatedPeerDescription)
        }
        let invalid = VaultFixtureTransport(); let session = try broker(invalid)
        XCTAssertThrowsError(try session.bindNativeVaultEntry(entryID: entryID, origin: "https://user:secret@example.test"))
        XCTAssertTrue(invalid.routing.isEmpty)
    }
    func testDeleteIsRevisionBoundBinaryFreeAndDoesNotReplayOnUnknownOutcome() throws {
        let entryID = String(repeating: "c", count: 64), revision = String(repeating: "d", count: 64)
        let transport = VaultFixtureTransport(); let client = try broker(transport)
        transport.admission = ["deleted": true]
        try client.deleteNativeVault(request: request, entryID: entryID, revision: revision)
        XCTAssertEqual(transport.binaryCalls, 0); XCTAssertTrue(transport.closed); XCTAssertNil(client.authenticatedPeerDescription)
        XCTAssertEqual(transport.routing[0]["method"] as? String, "vault.delete")
        let params = transport.routing[0]["params"] as! [String: Any]
        XCTAssertEqual(params["revision"] as? String, revision)
        for result: [String: Any] in [["deleted": 1], ["deleted": false], ["deleted": true, "extra": true]] {
            let invalid = VaultFixtureTransport(); let session = try broker(invalid); invalid.admission = result
            XCTAssertThrowsError(try session.deleteNativeVault(request: request, entryID: entryID, revision: revision)) { error in
                guard case VaultNativeChannelError.outcomeUnknown = error else { return XCTFail("Delete uncertainty was lost") }
            }
            XCTAssertTrue(invalid.closed); XCTAssertEqual(invalid.binaryCalls, 0)
            XCTAssertNil(session.authenticatedPeerDescription)
        }
        let invalid = VaultFixtureTransport(); let session = try broker(invalid)
        XCTAssertThrowsError(try session.deleteNativeVault(request: request, entryID: entryID, revision: "invalid"))
        XCTAssertTrue(invalid.routing.isEmpty)
    }
    func testMalformedUpdateRevisionNeverReleasesCredentialBytes() throws {
        let transport = VaultFixtureTransport(); let client = try broker(transport)
        XCTAssertThrowsError(try client.submitNativeVault(request: request, entryID: String(repeating: "c", count: 64), revision: "invalid", username: Data([97]), password: Data([98])))
        XCTAssertTrue(transport.routing.isEmpty); XCTAssertEqual(transport.binaryCalls, 0)
    }

}


extension VaultNativeChannelTests {
    func testExplicitImportAndInspectionUseMetadataOnlyDedicatedChannel() throws {
        for inspect in [false,true] {
            let transport=VaultFixtureTransport()
            transport.admission=["reference":["id":String(repeating:"d",count:64)],"revision":String(repeating:"e",count:64)]
            let client=try broker(transport)
            let metadata=try client.importNativeVaultCredential(request:request,entryID:String(repeating:"c",count:64),resourceURL:transport.reference,revision:String(repeating:"f",count:64),inspect:inspect)
            XCTAssertEqual(metadata.id,String(repeating:"d",count:64));XCTAssertEqual(transport.binaryCalls,0);XCTAssertTrue(transport.closed)
            XCTAssertEqual(transport.routing.count,1)
            XCTAssertEqual(transport.routing[0]["method"] as? String,inspect ? "vault.record.inspectImport" : "vault.record.importCredential")
            let params=try XCTUnwrap(transport.routing[0]["params"] as? [String:Any])
            XCTAssertEqual(Set(params.keys),Set(["sessionID","entryID","origin","accountAlias","resourceURL","revision"]))
        }
    }
    func testImportRejectsValueBearingReplyAndArbitrarySourceWithoutReplay() throws {
        let transport=VaultFixtureTransport();transport.admission=["reference":["id":String(repeating:"d",count:64)],"revision":String(repeating:"e",count:64),"password":"private-canary"]
        let client=try broker(transport)
        XCTAssertThrowsError(try client.importNativeVaultCredential(request:request,entryID:String(repeating:"c",count:64),resourceURL:transport.reference,revision:String(repeating:"f",count:64),inspect:false))
        XCTAssertEqual(transport.routing.count,1);XCTAssertEqual(transport.binaryCalls,0);XCTAssertTrue(transport.closed)
        let another=VaultFixtureTransport();let second=try broker(another)
        XCTAssertThrowsError(try second.importNativeVaultCredential(request:request,entryID:String(repeating:"c",count:64),resourceURL:"file:///arbitrary",revision:String(repeating:"f",count:64),inspect:false))
        XCTAssertTrue(another.routing.isEmpty);XCTAssertEqual(another.binaryCalls,0)
    }
}
