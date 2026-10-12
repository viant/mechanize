import XCTest
@testable import ConsentCore

@MainActor final class MigrationUnifiedUpdateManifestTests:XCTestCase {
    func payload(_ change:String?=nil)throws->Data {
        var package=try JSONSerialization.jsonObject(with:MigrationUnifiedAppManifestTests().payload()) as! [String:Any]
        var plan=try JSONSerialization.jsonObject(with:Data(base64Encoded:package["installPlanBase64"] as! String)!) as! [String:Any]
        var runtime=plan["runtime"] as! [String:Any],bootstrap=package["bootstrap"] as! [String:Any]
        let target=FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Applications/Mechanize.app").path
        var app=(runtime["Artifacts"] as! [[String:Any]])[0],roles=runtime["LegacyArtifacts"] as! [[String:Any]]
        var old=app["New"] as! [String:Any]
        var broker=old["Contents/Helpers/mechanize"] as! [String:Any];broker["sha256"]=String(repeating:"b",count:64);old["Contents/Helpers/mechanize"]=broker
        app["Old"]=old;app["OldDigest"]=try MigrationUnifiedAppManifest.inventoryDigest(old)
        for i in roles.indices {
            let role=roles[i]["role"] as! String
            let relative="Contents/Helpers/"+(role=="helper" ? "mechanize-native" : "mechanize-native-host")
            let view:[String:Any]=role=="console" ? old : [".":old[relative]!]
            roles[i]["Old"]=view;roles[i]["OldDigest"]=try MigrationUnifiedAppManifest.inventoryDigest(view)
            roles[i]["target"]=role=="console" ? target : target+"/"+relative
            if role=="console" {app["OldRequirement"]=roles[i]["OldRequirement"]}
            if role=="helper" {runtime["ActiveHelperPath"]=roles[i]["target"];runtime["ActiveHelperRequirement"]=roles[i]["OldRequirement"];runtime["ActiveHelperSHA256"]=(view["."] as! [String:Any])["sha256"]}
        }
        runtime["ConfigPath"]="/private/fixture/runtime/config.json";runtime["Mode"]="unified-app-update-v3";runtime.removeValue(forKey:"NewBrokerPath");runtime["BrokerPath"]=target+"/Contents/Helpers/mechanize"
        bootstrap.removeValue(forKey:"newCanonicalExecutable");bootstrap["canonicalExecutable"]=runtime["BrokerPath"]
        switch change {
        case "path":runtime["BrokerPath"]=target+"/Contents/Helpers/foreign"
        case "preinstalled":runtime["preinstalledUnifiedApp"]=true
        case "nested":roles[0]["target"]=target+"/unexpected"
        case "oldDigest":app["OldDigest"]=String(repeating:"f",count:64)
        case "pin":runtime["ActiveHelperRequirement"]="broad pin"
        case "overlap":app["candidate"]=target
        default:break
        }
        runtime["Artifacts"]=[app];runtime["LegacyArtifacts"]=roles;plan["runtime"]=runtime;plan["version"]=3
        let raw=try JSONSerialization.data(withJSONObject:plan,options:[.sortedKeys,.withoutEscapingSlashes])
        package["bootstrap"]=bootstrap;package["installPlanBase64"]=raw.base64EncodedString();package["installPlanSHA256"]=MigrationUpgradeIntent.digest(raw)
        return try JSONSerialization.data(withJSONObject:package,options:[.sortedKeys,.withoutEscapingSlashes])
    }
    func testSamePathWholeBundleSelectionAndReadinessContract()throws {
        let raw=try payload();let package=try MigrationReviewedUpgradePackage(authenticatedPayload:raw,expectedSHA256:MigrationUpgradeIntent.digest(raw))
        let manifest=try MigrationRuntimeConsoleManifest(frozenPlan:package.frozenPlan,intent:package.intent)
        XCTAssertNil(package.intent.newCanonicalExecutable)
        XCTAssertEqual(try MigrationManagedShutdownPlan(intent:package.intent,frozenPlan:package.frozenPlan).arguments[3],"/private/fixture/runtime/config.json")
        XCTAssertEqual(package.intent.installedBrokerExecutable,manifest.bundle.appendingPathComponent("Contents/Helpers/mechanize").path)
        XCTAssertNoThrow(try package.makePreservationObserver())
        for mode in ["path","preinstalled","nested","oldDigest","pin","overlap"] {
            let bad=try payload(mode)
            XCTAssertThrowsError(try MigrationReviewedUpgradePackage(authenticatedPayload:bad,expectedSHA256:MigrationUpgradeIntent.digest(bad)),mode)
        }
    }
}
