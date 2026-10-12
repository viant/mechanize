import XCTest
@testable import ConsentCore

@MainActor final class MigrationApprovalCompatibilityTests: XCTestCase {
    func testFrozenObserverRoutesTruthfulNewApprovalPinAndBirth() throws {
        var outer=try JSONSerialization.jsonObject(with:MigrationUnifiedAppManifestTests().payload()) as! [String:Any]
        var plan=try JSONSerialization.jsonObject(with:Data(base64Encoded:outer["installPlanBase64"] as! String)!) as! [String:Any]
        var runtime=plan["runtime"] as! [String:Any],legacy=runtime["LegacyArtifacts"] as! [[String:Any]]
        let i=legacy.firstIndex{$0["role"] as? String=="console"}!,original=legacy[i]
        let pin=original["NewRequirement"] as! String,birth="1800000000:2"
        runtime["OriginalConsoleArtifact"]=["path":original["target"]!,"requirement":original["OldRequirement"]!,"inventory":original["Old"]!,"inventorySHA256":original["OldDigest"]!]
        runtime["ApprovalConsole"]=["installedPath":FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Applications/Mechanize.app").path,"requirement":pin,"birth":birth]
        runtime["preinstalledUnifiedApp"]=true;runtime["preinstalledApprovalConsole"]=true;runtime["OldConsoleBirth"]=birth
        legacy[i]["target"]=original["candidate"];legacy[i]["Old"]=original["New"];legacy[i]["OldDigest"]=original["NewDigest"];legacy[i]["OldRequirement"]=pin
        runtime["LegacyArtifacts"]=legacy;plan["runtime"]=runtime
        let frozen=try JSONSerialization.data(withJSONObject:plan,options:[.sortedKeys,.withoutEscapingSlashes]);outer["installPlanBase64"]=frozen.base64EncodedString();outer["installPlanSHA256"]=MigrationUpgradeIntent.digest(frozen)
        let bytes=try JSONSerialization.data(withJSONObject:outer),package=try MigrationReviewedUpgradePackage(authenticatedPayload:bytes,expectedSHA256:MigrationUpgradeIntent.digest(bytes))
        var checked=false
        let observation=try MigrationRuntimeObserverTests().observation()
        let collector=try MigrationRuntimeObserverCollector(intent:package.intent,frozenPlan:package.frozenPlan,profile:"",browser:"",title:"Extensions - Google Chrome",setup:{throw MigrationConsoleError.unavailable},observe:{_,_,_,_ in observation},document:{_,_,_,_ in},loaded:{_,_,_,_,_ in ("/private/fixture/extension",Date())},stopped:{_ in},console:{actualPin,actualBirth in XCTAssertEqual(actualPin,pin);XCTAssertEqual(actualBirth,birth);checked=true},preservedChrome:package.observerEnrollment.preservedChrome,image:{pid,birth,path,pin in MigrationShutdownIdentity(pid:pid,uid:getuid(),birth:birth,executable:path,requirement:pin)})
        try collector.capture()
        let request=try MigrationWorkerSession.canonical(["version":1,"nonce":String(repeating:"a",count:64),"session":package.intent.bootstrap.session,"manifestSHA256":package.intent.runtimeManifestSHA256,"deadlineUnixMilliseconds":Int64(Date().addingTimeInterval(2).timeIntervalSince1970*1000),"mode":"unified-app-v2"],order:["version","nonce","session","manifestSHA256","requestSHA256","deadlineUnixMilliseconds","mode"])
        _=try collector.response(request,authorizationDeadline:Date().addingTimeInterval(30));XCTAssertTrue(checked)
        XCTAssertNotEqual(original["OldRequirement"] as? String,pin)
    }
}
