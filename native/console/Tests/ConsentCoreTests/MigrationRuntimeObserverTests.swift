import XCTest
@testable import ConsentCore

final class MigrationRuntimeObserverTests: XCTestCase {
    let f = MigrationNativePreparationTests()
    func observation(at: Date = Date().addingTimeInterval(-1)) throws -> Data {
        func node(_ id:String,_ parent:String?,_ role:String,_ name:String="",_ identifier:String="")->[String:Any] {
            var value:[String:Any]=["ref":["id":id],"nativeRole":role,"name":name,"identifier":identifier,"nativeOwnerMatchesRoot":true,"nativeOwnerProcessId":42,"nativeOwnerStartToken":"1790000000:1","nativeOwnerBundleId":"com.google.Chrome","nativeOwnerUid":getuid()]
            if let parent {value["parentId"]=parent};return value
        }
        let date=ISO8601DateFormatter().string(from:at)
        return try JSONSerialization.data(withJSONObject:["truncated":false,"surface":["kind":"native","bundleId":"com.google.Chrome","processId":42,"processStartToken":"1790000000:1"],"windowScope":["title":"Extensions - Google Chrome","role":"AXWindow"],"started":date,"ended":date,"nodes":[node("web",nil,"AXWebArea"),node("details","web","AXGroup","","details-view"),node("row","details","AXGroup"),node("label","row","AXStaticText","Loaded from"),node("path","row","AXStaticText","/private/fixture/extension")]],options:[.sortedKeys,.withoutEscapingSlashes])
    }
    func fixture(at:Date=Date().addingTimeInterval(-1),document:@escaping (Int32,String,String,String)throws->Void={_,_,_,_ in},stopped:@escaping ([String])throws->Void={_ in})throws->(MigrationRuntimeObserverCollector,MigrationUpgradeIntent) {
        let base=try f.intent(),id=String(repeating:"a",count:32),storage=f.hex("b")
        let plan:[String:Any]=["runtime":["BrokerPath":"/private/fixture/mechanize","ActiveHelperPath":"/private/fixture/helper","ChromeExecutable":"/private/fixture/Chrome","OldConsoleBirth":"1790000000:2","ExtensionID":id,"ExtensionStorageSHA256":storage,"Artifacts":[["role":"extension","target":"/private/fixture/extension"],["role":"helper","target":"/private/fixture/helper"],["role":"native-host","target":"/private/fixture/native-host"],["role":"console","OldRequirement":f.pin("consent","9")]]]]
        let frozen=try JSONSerialization.data(withJSONObject:plan,options:[.sortedKeys,.withoutEscapingSlashes])
        let intent=try MigrationUpgradeIntent(worker:base.worker,bootstrap:base.bootstrap,runtimeManifestSHA256:MigrationUpgradeIntent.digest(frozen))
        let raw=try JSONSerialization.data(withJSONObject:["profileChannel":"profile","browserInstance":"browser","brokerEpoch":"epoch","channelEpoch":"channel","scopeHash":f.hex("c"),"metadata":["version":1,"extensionId":id,"storageSHA256":storage,"storageScope":"extension-local-v1","storageStable":true,"nativeConnected":true,"activeCommands":0,"unknownAttempts":0,"mutationBusy":false],"brokerPending":0,"brokerUnknown":0,"observedAt":ISO8601DateFormatter().string(from:at),"receiptSHA256":f.hex("d"),"chromeRequirement":"fixture-Chrome", "chromeParent":["pid":42,"uid":getuid(),"executable":"/private/fixture/Chrome","startToken":"1790000000:1"]],options:[.sortedKeys,.withoutEscapingSlashes])
        let native=try observation(at:at)
        let collector=try MigrationRuntimeObserverCollector(intent:intent,frozenPlan:frozen,profile:"profile",browser:"browser",title:"Extensions - Google Chrome",setup:{raw},observe:{pid,birth,title,_ in
            XCTAssertEqual(pid,42);XCTAssertEqual(birth,"1790000000:1");XCTAssertEqual(title,"Extensions - Google Chrome");return native
        },document:document,stopped:stopped,console:{requirement,birth in XCTAssertEqual(requirement,self.f.pin("consent","9"));XCTAssertEqual(birth,"1790000000:2")}, image: { pid,birth,path,requirement in MigrationShutdownIdentity(pid:pid,uid:getuid(),birth:birth,executable:path,requirement:requirement) })
        return(collector,intent)
    }
    func request(_ intent:MigrationUpgradeIntent,nonce:String=String(repeating:"1",count:64))throws->Data {
        try MigrationWorkerSession.canonical(["version":1,"nonce":nonce,"session":intent.bootstrap.session,"manifestSHA256":intent.runtimeManifestSHA256,"deadlineUnixMilliseconds":Int64(Date().addingTimeInterval(2).timeIntervalSince1970*1000)],order:["version","nonce","session","manifestSHA256","deadlineUnixMilliseconds"])
    }
    func testOriginalFreshnessPreservedAcrossRequestsAndNonceCannotReplay()throws {
        var checks=0
        let (collector,intent)=try fixture(stopped:{paths in checks+=1;XCTAssertEqual(paths.count,4)})
        try collector.capture()
        let one=try request(intent),first=try collector.response(one,authorizationDeadline:Date().addingTimeInterval(30))
        let two=try request(intent,nonce:f.hex("2")),second=try collector.response(two,authorizationDeadline:Date().addingTimeInterval(30))
        let a=try JSONSerialization.jsonObject(with:first) as! [String:Any],b=try JSONSerialization.jsonObject(with:second) as! [String:Any]
        XCTAssertEqual(a["observedAtUnixMilliseconds"] as? Int64,b["observedAtUnixMilliseconds"] as? Int64)
        XCTAssertEqual(a["sourceReceiptSHA256"] as? String,b["sourceReceiptSHA256"] as? String)
        XCTAssertEqual(checks,2)
        XCTAssertThrowsError(try collector.response(one,authorizationDeadline:Date().addingTimeInterval(30)))
        XCTAssertThrowsError(try collector.capture())
    }
    func testWebsiteOrLiveProcessesCannotProduceQuiescence()throws {
        var sourceChecks=0
        let (lookalike,_)=try fixture(document:{_,_,_,_ in sourceChecks+=1;throw MigrationConsoleError.unavailable})
        XCTAssertThrowsError(try lookalike.capture());XCTAssertEqual(sourceChecks,1)
        let (live,intent)=try fixture(stopped:{_ in throw MigrationConsoleError.unavailable})
        try live.capture();XCTAssertThrowsError(try live.response(request(intent),authorizationDeadline:Date().addingTimeInterval(30)))
        let (stale,_)=try fixture(at:Date().addingTimeInterval(-60));XCTAssertThrowsError(try stale.capture())
    }
    func testSubstitutedSessionManifestAndOpenFramesFail()throws {
        for mode in ["session","manifestSHA256","approved","deadlineUnixMilliseconds"] {
            let (collector,intent)=try fixture();try collector.capture()
            var object=try JSONSerialization.jsonObject(with:request(intent)) as! [String:Any]
            object[mode]=mode=="deadlineUnixMilliseconds" ? 1 : f.hex("e")
            let payload=try JSONSerialization.data(withJSONObject:object,options:[.sortedKeys,.withoutEscapingSlashes])
            XCTAssertThrowsError(try collector.response(payload,authorizationDeadline:Date().addingTimeInterval(30)))
        }
    }
    func testLoadedPathRejectsNestedDetachedAmbiguousIncompleteAndForeignTrees()throws {
        for mode in ["nested","detached","ambiguous","truncated","unavailable","foreign","missing provenance"] {
            var root=try JSONSerialization.jsonObject(with:observation()) as! [String:Any]
            var nodes=root["nodes"] as! [[String:Any]]
            switch mode {
            case "nested":var web=nodes[0];web["ref"]=["id":"nested"];web["parentId"]="details";nodes.append(web)
            case "detached":nodes[1]["parentId"]="other"
            case "ambiguous":var path=nodes[4];path["ref"]=["id":"path2"];nodes.append(path)
            case "truncated":root["truncated"]=true
            case "unavailable":nodes[4]["unavailable"]=["children"]
            case "foreign":nodes[4]["nativeOwnerProcessId"]=99
            default:nodes[4].removeValue(forKey:"nativeOwnerMatchesRoot")
            }
            root["nodes"]=nodes
            let data=try JSONSerialization.data(withJSONObject:root)
            XCTAssertThrowsError(try MigrationRuntimeObserverCollector.loadedPath(data,pid:42,birth:"1790000000:1",title:"Extensions - Google Chrome"),mode)
        }
    }
}

private final class ObserverWireFixture: MigrationConsoleWire {
    var input: Data
    var writes: [Data] = []
    var authentications = 0, rejectAt = 0
    init(_ input: Data) { self.input = input }
    func authenticate() throws { authentications += 1; if rejectAt == authentications { throw MigrationConsoleError.unavailable } }
    func write(_ data: Data, deadline: Date) throws { writes.append(data) }
    func readExactly(_ count: Int, deadline: Date) throws -> Data { guard input.count >= count else { throw MigrationConsoleError.unavailable }; let result = Data(input.prefix(count)); input.removeFirst(count); return result }
    func close() {}
}
private final class ObserverCredentialFixture: EnrollmentCredentialProvider {
    func credential() throws -> Data { Data("synthetic-credential".utf8) }
}
extension MigrationRuntimeObserverTests {
    func testObserverFramesRevalidatePeerBeforeMetadataEmission() throws {
        for changed in [false, true] {
            let (collector, intent) = try fixture(); try collector.capture()
            let prepared = try MigrationNativePreparation.decode(f.packet(intent), intent: intent, requestID: f.hex("1"), validUntil: Date().addingTimeInterval(30))
            let payload = try request(intent)
            var frame = Data([77,77,79,66,83,81,0,1]); var size = UInt32(payload.count).bigEndian
            withUnsafeBytes(of: &size) { frame.append(contentsOf: $0) }; frame.append(payload)
            let wire = ObserverWireFixture(frame); wire.rejectAt = changed ? 6 : 0
            let channel = MigrationConsoleChannel(wire: wire, credentials: ObserverCredentialFixture(), authorization: try prepared.preparation.authorization(intent), observer: collector)
            // The fixture closes after one observer request; no approval frame is supplied.
            XCTAssertThrowsError(try channel.attestExistingAuthorization())
            XCTAssertEqual(wire.writes.count, changed ? 1 : 2)
            if !changed {
                XCTAssertEqual(wire.writes[1].prefix(8), Data([77,77,79,66,83,82,0,1]))
                XCTAssertFalse(String(data: wire.writes[1], encoding: .utf8)?.contains("synthetic-credential") == true)
            }
        }
    }
}
