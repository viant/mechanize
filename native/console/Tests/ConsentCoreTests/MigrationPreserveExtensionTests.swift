import XCTest
@testable import ConsentCore

@MainActor final class MigrationPreserveExtensionTests: XCTestCase {
    func testRuntimeOnlyFlagRequiresEveryCurrentResourceAndBooleanTrue() throws {
        let package = try JSONSerialization.jsonObject(with:packageData()) as! [String:Any]
        let plan = try JSONSerialization.jsonObject(with:Data(base64Encoded:package["installPlanBase64"] as! String)!) as! [String:Any]
        var runtime = plan["runtime"] as! [String:Any]
        var entry = runtime["PreservedExtension"] as! [String:Any]
        entry["runtimeResourcesOnly"] = true;runtime["PreservedExtension"] = entry
        XCTAssertThrowsError(try MigrationPreservedExtensionManifest(runtime:runtime))
        var inventory = entry["inventory"] as! [String:[String:Any]]
        for name in ["fingerprint.js","retirement.js","setup-metadata.js","secure-input.js","controller.js"] {inventory[name] = inventory["worker.js"]}
        entry["inventory"] = inventory;entry["inventorySHA256"] = try MigrationPreservedExtensionManifest.inventoryDigest(inventory)
        runtime["PreservedExtension"] = entry
        XCTAssertNoThrow(try MigrationPreservedExtensionManifest(runtime:runtime))
        for invalid:Any in [false,1,"true"] {entry["runtimeResourcesOnly"] = invalid;runtime["PreservedExtension"] = entry;XCTAssertThrowsError(try MigrationPreservedExtensionManifest(runtime:runtime))}
    }
    func testRecoveryAndRecordRootAreClosedReviewedMetadata() throws {
        let package = try JSONSerialization.jsonObject(with: packageData()) as! [String:Any]
        let plan = try JSONSerialization.jsonObject(with: Data(base64Encoded: package["installPlanBase64"] as! String)!) as! [String:Any]
        var runtime = plan["runtime"] as! [String:Any]
        runtime["ChromeRequirement"] = "identifier \"com.google.Chrome\" and (cdhash H\"" + String(repeating:"a",count:40) + "\" or cdhash H\"" + String(repeating:"b",count:40) + "\")"
        runtime["ChromeRecovery"] = ["originalConfig":["path":"/private/review/original.json","sha256":String(repeating:"a",count:64)],"originalChromeSHA256":String(repeating:"b",count:64)]
        runtime["NativeRecordRoot"] = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".secret/vault-records").path
        XCTAssertNoThrow(try MigrationPreservedExtensionManifest(runtime:runtime))
        runtime["NativeRecordRoot"] = "/arbitrary/records"
        XCTAssertThrowsError(try MigrationPreservedExtensionManifest(runtime:runtime))
        runtime.removeValue(forKey:"NativeRecordRoot");runtime["ChromeRequirement"] = "identifier \"com.google.Chrome\""
        XCTAssertThrowsError(try MigrationPreservedExtensionManifest(runtime:runtime))
    }
    func packageData(runtimeOnly: Bool = false) throws -> Data {
        let base=MigrationUpgradeSelectionTests(),f=MigrationNativePreparationTests()
        var package=try JSONSerialization.jsonObject(with:base.payload()) as! [String:Any]
        let encoded=package["installPlanBase64"] as! String
        var plan=try JSONSerialization.jsonObject(with:Data(base64Encoded:encoded)!) as! [String:Any]
        var runtime=plan["runtime"] as! [String:Any]
        var inventory:[String:[String:Any]]=[".":["kind":"directory","mode":448,"size":0,"sha256":""]]
        for name in ["browser.js","content.js","dom.js","manifest.json","options.html","options.js","protocol.js","recorder.js","worker.js"] {
            inventory[name]=["kind":"file","mode":384,"size":10,"sha256":f.hex("a")]
        }
        runtime["Mode"]="preserve-extension-v1";runtime["ChromeRequirement"]="fixture-Chrome";runtime["ChromeExecutable"]="/private/fixture/Chrome"
        runtime["ExtensionID"]=String(repeating:"a",count:32);runtime["OldConsoleBirth"]="1790000000:2"
        runtime["ActiveHelperPath"]="/private/fixture/helper";runtime["ActiveHelperRequirement"]=f.pin("native","8")
        runtime["PreservedExtension"]=["path":"/private/fixture/extension","extensionID":String(repeating:"a",count:32),"inventory":inventory,"inventorySHA256":try MigrationPreservedExtensionManifest.inventoryDigest(inventory)]
        if runtimeOnly {
            for name in ["fingerprint.js","retirement.js","setup-metadata.js","secure-input.js","controller.js"] { inventory[name]=inventory["worker.js"] }
            runtime["PreservedExtension"]=["path":"/private/fixture/extension","extensionID":String(repeating:"a",count:32),"inventory":inventory,"inventorySHA256":try MigrationPreservedExtensionManifest.inventoryDigest(inventory),"runtimeResourcesOnly":true]
        }
        var artifacts=runtime["Artifacts"] as! [[String:Any]]
        artifacts[0]["candidate"]="/private/fixture/new-console";artifacts[0]["OldRequirement"]=f.pin("consent","9")
        artifacts.append(["role":"helper","target":"/private/fixture/helper","candidate":"/private/fixture/new-helper","OldRequirement":f.pin("native","8")])
        artifacts.append(["role":"native-host","target":"/private/fixture/native-host","candidate":"/private/fixture/new-host","OldRequirement":f.pin("chrome.nativehost","7")])
        runtime["Artifacts"]=artifacts;plan["runtime"]=runtime
        let frozen=try JSONSerialization.data(withJSONObject:plan,options:[.sortedKeys,.withoutEscapingSlashes])
        package["installPlanBase64"]=frozen.base64EncodedString();package["installPlanSHA256"]=MigrationUpgradeIntent.digest(frozen)
        var observer=package["observer"] as! [String:Any]
        observer.removeValue(forKey:"profileChannel");observer.removeValue(forKey:"browserInstance")
        observer["chromePID"]=42;observer["chromeStart"]="1790000000:1";package["observer"]=observer
        return try JSONSerialization.data(withJSONObject:package,options:[.sortedKeys,.withoutEscapingSlashes])
    }
    func package() throws -> MigrationReviewedUpgradePackage {
        let bytes=try packageData();return try MigrationReviewedUpgradePackage(authenticatedPayload:bytes,expectedSHA256:MigrationUpgradeIntent.digest(bytes))
    }
    func testRuntimeOnlyCaptureUsesSharedShapeAndKeepsTypedFailures() throws {
        let bytes=try packageData(runtimeOnly:true)
        let reviewed=try MigrationReviewedUpgradePackage(authenticatedPayload:bytes,expectedSHA256:MigrationUpgradeIntent.digest(bytes))
        let native=try MigrationRuntimeObserverTests().observation()
        for failure in ["none","image","permission","observation","loaded","mismatch"] {
            let collector=try MigrationRuntimeObserverCollector(intent:reviewed.intent,frozenPlan:reviewed.frozenPlan,profile:"",browser:"",title:"Extensions - Google Chrome",setup:{XCTFail("setup forbidden");throw MigrationConsoleError.unavailable},observe:{_,_,_,_ in
                if failure=="observation" {throw MigrationConsoleError.unavailable};return native
            },document:{_,_,_,_ in if failure=="permission" {throw MigrationObserverReadinessError.accessibilityRequired}},loaded:{_,_,_,_,_ in
                if failure=="loaded" {throw MigrationConsoleError.unavailable}
                return (failure=="mismatch" ? "/wrong/path" : "/private/fixture/extension",Date())
            },stopped:{_ in XCTFail("shutdown forbidden")},console:{_,_ in XCTFail("console operation forbidden")},preservedChrome:reviewed.observerEnrollment.preservedChrome,image:{pid,birth,_,requirement in
                if failure=="image" {throw MigrationConsoleError.unavailable}
                return MigrationShutdownIdentity(pid:pid,uid:getuid(),birth:birth,executable:"/private/fixture/ActualChromeHardlink",requirement:requirement)
            })
            if failure=="none" {XCTAssertNoThrow(try collector.capture())}
            else {XCTAssertThrowsError(try collector.capture()) { error in
                let codes=["image":"chromeIdentity","permission":"accessibilityRequired","observation":"nativeObservation","loaded":"loadedPath","mismatch":"loadedPathMismatch"]
                XCTAssertEqual((error as? MigrationObserverReadinessError)?.rawValue,codes[failure])
            }}
        }
    }
    func testPreservationUsesOnlyNativeDocumentReceiptAndOmitsStorageTrustClaims() throws {
        let reviewed=try package(),native=try MigrationRuntimeObserverTests().observation()
        var setupCalls=0,documentCalls=0,imageCalls=0
        let collector=try MigrationRuntimeObserverCollector(intent:reviewed.intent,frozenPlan:reviewed.frozenPlan,profile:"",browser:"",title:"Extensions - Google Chrome",setup:{setupCalls+=1;throw MigrationConsoleError.unavailable},observe:{_,_,_,_ in native},document:{pid,birth,_,id in documentCalls+=1;XCTAssertEqual(pid,42);XCTAssertEqual(birth,"1790000000:1");XCTAssertEqual(id,String(repeating:"a",count:32))},stopped:{_ in},console:{_,_ in},preservedChrome:reviewed.observerEnrollment.preservedChrome,image:{pid,birth,canonical,requirement in
            imageCalls+=1;XCTAssertEqual(canonical,"/private/fixture/Chrome")
            return MigrationShutdownIdentity(pid:pid,uid:getuid(),birth:birth,executable:"/private/fixture/ActualChromeHardlink",requirement:requirement)
        })
        try collector.capture()
        let request=try MigrationWorkerSession.canonical(["version":1,"nonce":String(repeating:"1",count:64),"session":reviewed.intent.bootstrap.session,"manifestSHA256":reviewed.intent.runtimeManifestSHA256,"deadlineUnixMilliseconds":Int64(Date().addingTimeInterval(2).timeIntervalSince1970*1000),"mode":"preserve-extension-v1"],order:["version","nonce","session","manifestSHA256","deadlineUnixMilliseconds","mode"])
        let response=try collector.response(request,authorizationDeadline:Date().addingTimeInterval(30))
        let fields=try JSONSerialization.jsonObject(with:response) as! [String:Any]
        XCTAssertNil(fields["storageSHA256"]);XCTAssertNil(fields["nativeConnected"]);XCTAssertNil(fields["executorQualified"])
        XCTAssertEqual(fields["mode"] as? String,"preserve-extension-v1")
        XCTAssertEqual(setupCalls,0);XCTAssertEqual(documentCalls,2);XCTAssertEqual(imageCalls,2)
    }
    func testPreservedManifestRejectsWritableExtensionUnknownFilesOverlapAndStorageClaims() throws {
        let reviewed=try package();let root=try JSONSerialization.jsonObject(with:reviewed.frozenPlan) as! [String:Any]
        for mode in ["storage","extension writer","unknown file","digest","overlap","unknown preserved field"] {
            var runtime=root["runtime"] as! [String:Any],preserved=runtime["PreservedExtension"] as! [String:Any]
            switch mode {
            case "storage":runtime["ExtensionStorageSHA256"]=String(repeating:"b",count:64)
            case "extension writer":var artifacts=runtime["Artifacts"] as! [[String:Any]];artifacts.append(["role":"extension"]);runtime["Artifacts"]=artifacts
            case "unknown file":var inventory=preserved["inventory"] as! [String:[String:Any]];inventory["private-profile-data"]=["kind":"file","mode":384,"size":0,"sha256":String(repeating:"b",count:64)];preserved["inventory"]=inventory
            case "digest":preserved["inventorySHA256"]=String(repeating:"b",count:64)
            case "overlap":var artifacts=runtime["Artifacts"] as! [[String:Any]];artifacts[0]["candidate"]="/private/fixture/extension/new";runtime["Artifacts"]=artifacts
            default:preserved["storageUntouched"]=true
            }
            runtime["PreservedExtension"]=preserved
            XCTAssertThrowsError(try MigrationPreservedExtensionManifest(runtime:runtime),mode)
        }
    }
    func testClosedObserverVariantsRejectFullModeChannelClaimsInPreserveMode() throws {
        let data=try packageData();var root=try JSONSerialization.jsonObject(with:data) as! [String:Any]
        var observer=root["observer"] as! [String:Any];observer["profileChannel"]="claimed-profile";root["observer"]=observer
        let changed=try JSONSerialization.data(withJSONObject:root,options:[.sortedKeys,.withoutEscapingSlashes])
        XCTAssertThrowsError(try MigrationReviewedUpgradePackage(authenticatedPayload:changed,expectedSHA256:MigrationUpgradeIntent.digest(changed)))
    }
}

final class MigrationChromeImageFileTests: XCTestCase {
    func testExactHardlinkIdentityDiffersFromCopyAndRejectsSymlinks() throws {
        let root=URL(fileURLWithPath:"/private/tmp/mm-chrome-image-"+UUID().uuidString)
        try FileManager.default.createDirectory(at:root,withIntermediateDirectories:false,attributes:[.posixPermissions:0o700]);defer{try? FileManager.default.removeItem(at:root)}
        let canonical=root.appendingPathComponent("canonical"),clone=root.appendingPathComponent("clone"),copy=root.appendingPathComponent("copy"),alias=root.appendingPathComponent("alias")
        try Data("synthetic executable".utf8).write(to:canonical);try FileManager.default.setAttributes([.posixPermissions:0o700],ofItemAtPath:canonical.path)
        try FileManager.default.linkItem(at:canonical,to:clone);try FileManager.default.copyItem(at:canonical,to:copy)
        try FileManager.default.createSymbolicLink(at:alias,withDestinationURL:canonical)
        let original=try MigrationChromeImageFile(canonical.path),linked=try MigrationChromeImageFile(clone.path),copied=try MigrationChromeImageFile(copy.path)
        XCTAssertTrue(MigrationChromeImageFile.same(original.original,linked.original))
        XCTAssertFalse(MigrationChromeImageFile.same(original.original,copied.original))
        XCTAssertThrowsError(try MigrationChromeImageFile(alias.path))
        try original.revalidate();try linked.revalidate()
        try FileManager.default.removeItem(at:clone)
        XCTAssertThrowsError(try linked.revalidate())
    }
}
