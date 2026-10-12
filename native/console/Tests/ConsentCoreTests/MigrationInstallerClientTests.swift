import XCTest
@testable import ConsentCore

private final class InstallerTransportFixture: MigrationInstallerTransport {
    var operations:[String] = [], payloads:[Data] = []
    var bootstrapCount = 0, cancelCount = 0
    var statuses = ["verified","verified"]
    var malformed = false
    let transition:String
    init(_ transition:String) { self.transition = transition }
    func bootstrap(_ value:MigrationWorkerBootstrap) throws { bootstrapCount += 1 }
    func cancel() { cancelCount += 1 }
    func roundTrip(_ payload:Data, closing:Bool) throws -> Data {
        let request = try JSONSerialization.jsonObject(with:payload) as! [String:Any]
        let operation = request["op"] as! String
        operations.append(operation);payloads.append(payload)
        if malformed { return Data("{}".utf8) }
        var reply:[String:Any] = ["version":1,"id":request["id"]!,"session":request["session"]!,"status":statuses.removeFirst()]
        if operation != "close" { reply["transitionId"] = transition; reply["scope"] = operation == "finalize" ? "runtime-artifacts" : "custody-broker-config" }
        var bytes = try MigrationWorkerSession.canonical(reply,order:["version","id","session","status","transitionId","scope"])
        if operation == "finalize", reply["status"] as? String == "verified" {
            bytes.removeLast(); bytes.append(Data(",\"runtime\":{\"brokerPID\":123,\"brokerStartToken\":\"123:456\"}}".utf8))
        }
        return bytes
    }
}
final class MigrationInstallerClientTests:XCTestCase {
    func fixture() throws -> (MigrationUpgradeIntent,MigrationNativePreparation) {
        let helper = MigrationNativePreparationTests(), intent = try helper.intent()
        return (intent,try MigrationNativePreparation.decode(helper.packet(intent),intent:intent,requestID:helper.hex("1"),validUntil:Date().addingTimeInterval(60)))
    }
    func testExecutePreservesEvidenceIdentityAndOriginalDeadline() throws {
        let (intent,prepared) = try fixture(), wire = InstallerTransportFixture(prepared.preparation.transitionID)
        let client = try NativeMigrationInstallerClient(intent:intent,prepared:prepared,transport:wire)
        _ = try client.execute(); _ = try client.finalize()
        XCTAssertEqual(wire.bootstrapCount,1);XCTAssertEqual(wire.operations,["execute","finalize"])
        let request = try JSONSerialization.jsonObject(with:wire.payloads[0]) as! [String:Any]
        XCTAssertEqual(request["identity"] as? String,prepared.itemIdentity.base64EncodedString())
        XCTAssertEqual(request["deadlineUnixMilliseconds"] as? Int64,Int64(floor(prepared.preparation.validUntil.timeIntervalSince1970*1000)))
        XCTAssertTrue(wire.payloads[0].range(of:prepared.canonicalEvidence) != nil)
        let finalize = try JSONSerialization.jsonObject(with:wire.payloads[1]) as! [String:Any]
        XCTAssertEqual(Set(finalize.keys),Set(["version","id","session","op"]))
        XCTAssertGreaterThan(wire.cancelCount,0);XCTAssertThrowsError(try client.execute());XCTAssertThrowsError(try client.finalize())
        XCTAssertFalse(String(reflecting:client).contains("persistent-reference"))
    }
    func testUnknownAllowsOneReconcileWithoutExecuteReplay() throws {
        let (intent,prepared) = try fixture(), wire = InstallerTransportFixture(prepared.preparation.transitionID)
        wire.statuses = ["unknown","unknown"]
        let client = try NativeMigrationInstallerClient(intent:intent,prepared:prepared,transport:wire)
        _ = try client.execute();XCTAssertTrue(client.canReconcile)
        XCTAssertThrowsError(try client.execute());_ = try client.reconcile()
        XCTAssertFalse(client.canReconcile);XCTAssertThrowsError(try client.reconcile());XCTAssertThrowsError(try client.finalize())
        XCTAssertEqual(wire.operations,["execute","reconcile"])
    }
    func testMalformedReplyLatchesPossibleDispatchAndCloses() throws {
        let (intent,prepared) = try fixture(), wire = InstallerTransportFixture(prepared.preparation.transitionID)
        wire.malformed = true
        let client = try NativeMigrationInstallerClient(intent:intent,prepared:prepared,transport:wire)
        XCTAssertThrowsError(try client.execute());XCTAssertTrue(client.executionMayHaveDispatched)
        XCTAssertFalse(client.canReconcile);XCTAssertThrowsError(try client.execute());XCTAssertGreaterThan(wire.cancelCount,0)
        XCTAssertEqual(wire.operations,["execute"])
    }
    func testDecoderRejectsWrongTranscriptScopeTransitionAndOpenFrames() throws {
        let (intent,prepared) = try fixture(), id = String(repeating:"1",count:64)
        let valid:[String:Any] = ["version":1,"id":id,"session":intent.bootstrap.session,"status":"verified","transitionId":prepared.preparation.transitionID,"scope":"custody-broker-config"]
        for (key,value) in [("id","wrong"),("session","wrong"),("transitionId","wrong"),("scope","runtime-artifacts"),("approved","true")] {
            var fields = valid;fields[key] = value
            let bytes = try MigrationWorkerSession.canonical(fields,order:["version","id","session","status","transitionId","scope","approved"])
            XCTAssertThrowsError(try MigrationInstallerWire.decode(bytes,operation:.execute,id:id,intent:intent,prepared:prepared))
        }
        let bytes = try MigrationWorkerSession.canonical(valid,order:["version","id","session","status","transitionId","scope"])
        let duplicate = String(data:bytes,encoding:.utf8)!.replacingOccurrences(of:"\"version\":1",with:"\"version\":1,\"version\":1")
        XCTAssertThrowsError(try MigrationInstallerWire.decode(Data(duplicate.utf8),operation:.execute,id:id,intent:intent,prepared:prepared))
        XCTAssertThrowsError(try MigrationInstallerWire.decode(bytes,operation:.close,id:id,intent:intent,prepared:prepared))
    }
    func testRuntimeIdentityRequiredOnlyOnExactFinalReceipt() throws {
        let (intent,prepared) = try fixture(), id = String(repeating:"1",count:64)
        func packet(_ runtime:String?, _ scope:String = "runtime-artifacts") throws -> Data {
            var bytes = try MigrationWorkerSession.canonical(["version":1,"id":id,"session":intent.bootstrap.session,"status":"verified","transitionId":prepared.preparation.transitionID,"scope":scope],order:["version","id","session","status","transitionId","scope"])
            if let runtime { bytes.removeLast(); bytes.append(Data((",\"runtime\":"+runtime+"}").utf8)) }
            return bytes
        }
        let valid = "{\"brokerPID\":123,\"brokerStartToken\":\"123:456\"}"
        let receipt = try MigrationInstallerWire.decode(packet(valid),operation:.finalize,id:id,intent:intent,prepared:prepared)
        XCTAssertEqual(receipt.runtime?.brokerPID,123); XCTAssertEqual(receipt.runtime?.brokerStartToken,"123:456")
        XCTAssertThrowsError(try MigrationInstallerWire.decode(packet(nil),operation:.finalize,id:id,intent:intent,prepared:prepared))
        XCTAssertThrowsError(try MigrationInstallerWire.decode(packet(valid,"custody-broker-config"),operation:.execute,id:id,intent:intent,prepared:prepared))
        for raw in ["{\"brokerPID\":0,\"brokerStartToken\":\"123:456\"}","{\"brokerPID\":true,\"brokerStartToken\":\"123:456\"}","{\"brokerPID\":123.0,\"brokerStartToken\":\"123:456\"}","{\"brokerPID\":123,\"brokerStartToken\":\"123:1000000\"}","{\"brokerPID\":123,\"brokerStartToken\":\"0123:456\"}","{\"brokerStartToken\":\"123:456\",\"brokerPID\":123}"] {
            XCTAssertThrowsError(try MigrationInstallerWire.decode(packet(raw),operation:.finalize,id:id,intent:intent,prepared:prepared))
        }
    }

}
