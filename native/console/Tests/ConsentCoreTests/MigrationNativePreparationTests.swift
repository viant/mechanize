import XCTest
@testable import ConsentCore

private final class PreparationCredentials:EnrollmentCredentialProvider {
    var reads=0
    func credential()throws->Data{reads+=1;return Data("fixture-native-credential".utf8)}
}
private final class PreparationWire:MigrationConsoleWire {
    var auth=0;var denyAt=0;var writes:[Data]=[];var readCalls=0;var closed=false
    func authenticate()throws{auth+=1;if auth==denyAt{throw MigrationConsoleError.unavailable}}
    func write(_ data:Data,deadline:Date)throws{writes.append(data)}
    func readExactly(_ count:Int,deadline:Date)throws->Data{readCalls+=1;throw MigrationConsoleError.unavailable}
    func close(){closed=true}
}
final class MigrationNativePreparationTests:XCTestCase {
    func hex(_ s:String)->String{String(repeating:s,count:64)}
    func pin(_ role:String,_ c:String)->String{"identifier \"com.viant.mechanize.\(role)\" and cdhash H\"\(String(repeating:c,count:40))\""}
    func intent()throws->MigrationUpgradeIntent{
        let worker=try MigrationWorkerManifest(executable:URL(fileURLWithPath:"/private/fixture/mutation"),requirement:pin("custody-migration","3"),sha256:hex("d"))
        let bootstrap=try MigrationWorkerBootstrap(session:hex("a"),configSHA256:hex("b"),canonicalExecutable:"/private/fixture/mechanize",oldRequirement:pin("broker","1"),newRequirement:pin("broker","2"),alias:"vault-master",service:"com.viant.mechanize.vault",account:"fixture",workerRequirement:worker.requirement)
        return try MigrationUpgradeIntent(worker:worker,bootstrap:bootstrap,runtimeManifestSHA256:hex("e"))
    }
    func packet(_ intent:MigrationUpgradeIntent,change:String?=nil)throws->Data{
        let identity=Data("actual-persistent-reference".utf8),itemHash=MigrationUpgradeIntent.digest(Data("actual-persistent-reference".utf8)),id=hex("f")
        let names=intent.transitionNames
        let values=[id]+Array(intent.options.prefix(6))+[itemHash,try intent.transitionBinding(id:id,itemSHA256:itemHash)]+(intent.newCanonicalExecutable.map { [$0] } ?? [])
        var transition=Dictionary(uniqueKeysWithValues:zip(names,values))
        if change=="item"{transition["ItemReferenceSHA256"]=hex("0")};if change=="binding"{transition["Binding"]=hex("0")};if change=="policy"{transition["OldRequirement"]=pin("broker","9")}
        let t=try MigrationWorkerSession.canonical(transition,order:names)
        var e:[String:Any]=["intentSHA256":intent.binding,"configSHA256":intent.bootstrap.value["configSHA256"]!,"optionsSHA256":intent.optionsSHA256,"runtimeManifestSHA256":intent.runtimeManifestSHA256,"mutationRequirement":intent.worker.requirement]
        if let change, ["intentSHA256","configSHA256","optionsSHA256","runtimeManifestSHA256","mutationRequirement"].contains(change){e[change]=hex("0")}
        var evidence=try MigrationWorkerSession.canonical(e,order:["intentSHA256","configSHA256","optionsSHA256","runtimeManifestSHA256","mutationRequirement"])
        evidence.removeLast();evidence.append(Data(",\"transition\":".utf8));evidence.append(t);evidence.append(125)
        var root=try MigrationWorkerSession.canonical(["version":1,"id":hex("1"),"session":intent.bootstrap.session,"status":"prepared","identity":identity.base64EncodedString()],order:["version","id","session","status","identity"])
        root.removeLast();root.append(Data(",\"evidence\":".utf8));root.append(evidence);root.append(125)
        return root
    }
    func testCredentialOnlyChannelAuthenticatesWithoutAnyApprovalReadOrReply()throws{
        let wire=PreparationWire(),credentials=PreparationCredentials()
        let channel=MigrationPreparationCredentialChannel(wire:wire,credentials:credentials,deadline:Date().addingTimeInterval(30))
        try channel.authenticateAndServe()
        XCTAssertEqual(wire.auth,2);XCTAssertEqual(credentials.reads,1);XCTAssertEqual(wire.writes.count,1);XCTAssertEqual(wire.readCalls,0)
        XCTAssertEqual(wire.writes[0].prefix(8),Data([77,77,65,85,84,72,0,1]))
        XCTAssertThrowsError(try channel.authenticateAndServe());XCTAssertEqual(wire.writes.count,1)
    }
    func testUntrustedPeerCannotReadOrEmitCredential()throws{
        for stage in [1,2]{let wire=PreparationWire(),credentials=PreparationCredentials();wire.denyAt=stage
            let channel=MigrationPreparationCredentialChannel(wire:wire,credentials:credentials,deadline:Date().addingTimeInterval(30))
            XCTAssertThrowsError(try channel.authenticateAndServe());XCTAssertTrue(wire.writes.isEmpty);XCTAssertEqual(credentials.reads,stage==1 ? 0:1)
        }
    }
    func testAuthenticatedEvidenceBindsWholeIntentAndExactTransition()throws{
        let intent=try intent();let evidence=try MigrationNativePreparation.decode(packet(intent),intent:intent,requestID:hex("1"),validUntil:Date().addingTimeInterval(30))
        XCTAssertEqual(evidence.preparation.intentBinding,intent.binding);XCTAssertEqual(evidence.itemIdentity,Data("actual-persistent-reference".utf8))
        XCTAssertFalse(String(reflecting:evidence).contains("persistent"))
    }
    func testMismatchedEvidenceAndUnclosedJSONRejected()throws{
        let intent=try intent()
        for change in ["item","binding","policy","intentSHA256","configSHA256","optionsSHA256","runtimeManifestSHA256","mutationRequirement"]{
            XCTAssertThrowsError(try MigrationNativePreparation.decode(packet(intent,change:change),intent:intent,requestID:hex("1"),validUntil:Date().addingTimeInterval(30)),change)
        }
        let valid=try packet(intent)
        let text=String(data:valid,encoding:.utf8)!
        for malformed in [text+"{}",text.replacingOccurrences(of:"\"version\":1",with:"\"version\":1,\"version\":1"),text.replacingOccurrences(of:"\"status\":\"prepared\"",with:"\"status\":\"prepared\",\"approved\":true")]{
            XCTAssertThrowsError(try MigrationNativePreparation.decode(Data(malformed.utf8),intent:intent,requestID:hex("1"),validUntil:Date().addingTimeInterval(30)))
        }
    }
}
