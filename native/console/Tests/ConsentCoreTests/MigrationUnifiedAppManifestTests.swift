import XCTest
@testable import ConsentCore

@MainActor final class MigrationUnifiedAppManifestTests: XCTestCase {
    func payload(change: String? = nil) throws -> Data {
        let f = MigrationNativePreparationTests()
        var package = try JSONSerialization.jsonObject(with:MigrationPreserveExtensionTests().packageData()) as! [String:Any]
        var plan = try JSONSerialization.jsonObject(with:Data(base64Encoded:package["installPlanBase64"] as! String)!) as! [String:Any]
        var runtime = plan["runtime"] as! [String:Any]
        let target = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Applications/Mechanize.app").path
        let candidate = "/private/fixture/staged/Mechanize.app"
        let directory: [String:Any] = ["kind":"directory","mode":0o755,"size":0,"sha256":""]
        let file: [String:Any] = ["kind":"file","mode":0o755,"size":1,"sha256":f.hex("a")]
        var inventory: [String:Any] = [".":directory,"Contents":directory,"Contents/MacOS":directory,"Contents/Helpers":directory]
        for path in ["Contents/MacOS/MechanizeConsent","Contents/Helpers/mechanize","Contents/Helpers/mechanize-native","Contents/Helpers/mechanize-native-host"] { inventory[path] = file }
        let digest = try MigrationUnifiedAppManifest.inventoryDigest(inventory)
        var legacy = runtime["Artifacts"] as! [[String:Any]]
        for i in legacy.indices {
            let role = legacy[i]["role"] as! String
            let new: [String:Any] = role == "console" ? inventory : [".":file]
            let old: [String:Any] = role == "console" ? [".":directory] : [".":file]
            legacy[i]["Old"] = old; legacy[i]["OldDigest"] = try MigrationUnifiedAppManifest.inventoryDigest(old)
            legacy[i]["New"] = new; legacy[i]["NewDigest"] = try MigrationUnifiedAppManifest.inventoryDigest(new)
            legacy[i]["NewRequirement"] = f.pin(role == "console" ? "consent" : role == "helper" ? "native" : "chrome.nativehost","3")
            legacy[i]["candidate"] = role == "console" ? candidate : candidate + "/Contents/Helpers/" + (role == "helper" ? "mechanize-native" : "mechanize-native-host")
        }
        var app: [String:Any] = ["role":"unified-app","target":target,"candidate":candidate,"Old":[:],"OldDigest":"","OldRequirement":"","New":inventory,"NewDigest":digest,"NewRequirement":f.pin("consent","3")]
        runtime["Mode"] = "unified-app-v2"; runtime["NewBrokerPath"] = target + "/Contents/Helpers/mechanize"
        var bootstrap = package["bootstrap"] as! [String:Any]; bootstrap["newCanonicalExecutable"] = runtime["NewBrokerPath"]
        switch change {
        case "preinstalled": runtime["preinstalledUnifiedApp"] = true
        case "invalidPreinstalled": runtime["preinstalledUnifiedApp"] = 1
        case "target": app["target"] = target + "-other"
        case "old": app["Old"] = [".":directory]
        case "subimage": legacy[1]["New"] = [".":directory]
        case "digest": app["NewDigest"] = f.hex("f")
        case "destination": bootstrap["newCanonicalExecutable"] = target + "/Contents/Helpers/other"
        case "legacyOverlap": legacy[0]["target"] = target
        case "legacyDigest": legacy[0]["OldDigest"] = f.hex("f")
        case "legacyCandidate": legacy[1]["candidate"] = "/private/fixture/other"
        default: break
        }
        plan["version"] = 2; runtime["Artifacts"] = [app]; runtime["LegacyArtifacts"] = legacy; plan["runtime"] = runtime
        let bytes = try JSONSerialization.data(withJSONObject:plan,options:[.sortedKeys,.withoutEscapingSlashes])
        package["bootstrap"] = bootstrap; package["installPlanBase64"] = bytes.base64EncodedString(); package["installPlanSHA256"] = MigrationUpgradeIntent.digest(bytes)
        return try JSONSerialization.data(withJSONObject:package,options:[.sortedKeys,.withoutEscapingSlashes])
    }
    func testReviewedPreinstalledFlagIsExplicitBooleanTrue() throws {
        let bytes=try payload(change:"preinstalled")
        XCTAssertNoThrow(try MigrationReviewedUpgradePackage(authenticatedPayload:bytes,expectedSHA256:MigrationUpgradeIntent.digest(bytes)))
        let bad=try payload(change:"invalidPreinstalled")
        XCTAssertThrowsError(try MigrationReviewedUpgradePackage(authenticatedPayload:bad,expectedSHA256:MigrationUpgradeIntent.digest(bad)))
    }
    func testObserverUsesRetainedLegacyIdentityAndClosedRelocationMode() throws {
        let bytes = try payload()
        let package = try MigrationReviewedUpgradePackage(authenticatedPayload:bytes,expectedSHA256:MigrationUpgradeIntent.digest(bytes))
        let observation = try MigrationRuntimeObserverTests().observation()
        var checked: [String] = []
        let collector = try MigrationRuntimeObserverCollector(intent:package.intent,frozenPlan:package.frozenPlan,profile:"",browser:"",title:"Extensions - Google Chrome",
            setup:{ XCTFail("plugin setup not preservation evidence"); throw MigrationConsoleError.unavailable },observe:{_,_,_,_ in observation},document:{_,_,_,_ in},
            loaded:{_,_,_,_,_ in ("/private/fixture/extension",Date())},stopped:{checked = $0},console:{_,_ in},
            preservedChrome:package.observerEnrollment.preservedChrome,image:{pid,birth,path,pin in MigrationShutdownIdentity(pid:pid,uid:getuid(),birth:birth,executable:path,requirement:pin)})
        try collector.capture()
        func request(_ mode: String, _ nonce: String) throws -> Data {
            try MigrationWorkerSession.canonical(["version":1,"nonce":String(repeating:nonce,count:64),"session":package.intent.bootstrap.session,"manifestSHA256":package.intent.runtimeManifestSHA256,"deadlineUnixMilliseconds":Int64(Date().addingTimeInterval(2).timeIntervalSince1970*1000),"mode":mode],order:["version","nonce","session","manifestSHA256","deadlineUnixMilliseconds","mode"])
        }
        XCTAssertThrowsError(try collector.response(request("preserve-extension-v1","1"),authorizationDeadline:Date().addingTimeInterval(30)))
        let response = try collector.response(request("unified-app-v2","2"),authorizationDeadline:Date().addingTimeInterval(30))
        let result = try JSONSerialization.jsonObject(with:response) as! [String:Any]
        XCTAssertEqual(result["mode"] as? String,"unified-app-v2")
        XCTAssertNil(result["storageSHA256"])
        XCTAssertTrue(checked.contains(package.intent.options[0]))
        XCTAssertTrue(checked.contains("/private/fixture/helper"))
        XCTAssertFalse(checked.contains(package.intent.installedBrokerExecutable))
    }
    func testWholeAppSelectionBindsNewBrokerAndPreservesLegacyEvidence() throws {
        let bytes = try payload()
        let package = try MigrationReviewedUpgradePackage(authenticatedPayload:bytes,expectedSHA256:MigrationUpgradeIntent.digest(bytes))
        let manifest = try MigrationRuntimeConsoleManifest(frozenPlan:package.frozenPlan,intent:package.intent)
        XCTAssertEqual(manifest.bundle.lastPathComponent,"Mechanize.app")
        XCTAssertEqual(package.intent.installedBrokerExecutable,manifest.bundle.appendingPathComponent("Contents/Helpers/mechanize").path)
        XCTAssertNotNil(package.observerEnrollment.preservedChrome)
        XCTAssertNoThrow(try package.makePreservationObserver())
        for mode in ["target","old","subimage","digest","destination","legacyOverlap","legacyDigest","legacyCandidate"] {
            let invalid = try payload(change:mode)
            XCTAssertThrowsError(try MigrationReviewedUpgradePackage(authenticatedPayload:invalid,expectedSHA256:MigrationUpgradeIntent.digest(invalid)),mode)
        }
    }
}
