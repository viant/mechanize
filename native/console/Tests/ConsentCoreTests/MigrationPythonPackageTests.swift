import XCTest
import CryptoKit
@testable import ConsentCore

@MainActor final class MigrationPythonPackageTests: XCTestCase {
    func testProductionPythonApprovingConsoleCompatibilityPayloadDecodes() throws {
        let root=URL(fileURLWithPath:#filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let process=Process(),output=Pipe(),errors=Pipe();process.executableURL=URL(fileURLWithPath:"/usr/bin/env")
        process.arguments=["python3",root.appendingPathComponent("scripts/fixture-unified-reviewed-package.py").path,"--approval-compatibility"]
        process.standardOutput=output;process.standardError=errors;try process.run()
        let bytes=output.fileHandleForReading.readDataToEndOfFile();process.waitUntilExit();XCTAssertEqual(process.terminationStatus,0)
        let package=try MigrationReviewedUpgradePackage(authenticatedPayload:bytes,expectedSHA256:MigrationUpgradeIntent.digest(bytes))
        let plan=try JSONSerialization.jsonObject(with:package.frozenPlan) as! [String:Any],runtime=plan["runtime"] as! [String:Any]
        let original=runtime["OriginalConsoleArtifact"] as! [String:Any],approval=runtime["ApprovalConsole"] as! [String:Any]
        let legacy=(runtime["LegacyArtifacts"] as! [[String:Any]]).first{$0["role"] as? String=="console"}!
        XCTAssertNotEqual(original["requirement"] as? String,approval["requirement"] as? String)
        XCTAssertEqual(legacy["OldRequirement"] as? String,approval["requirement"] as? String)
        XCTAssertEqual(runtime["OldConsoleBirth"] as? String,approval["birth"] as? String)
    }
    func testProductionPythonUnifiedPayloadDecodesAndRejectsPlanVersionConfusion() throws {
        let root=URL(fileURLWithPath:#filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let process=Process(),output=Pipe(),errors=Pipe()
        process.executableURL=URL(fileURLWithPath:"/usr/bin/env")
        process.arguments=["python3",root.appendingPathComponent("scripts/fixture-unified-reviewed-package.py").path]
        process.standardOutput=output;process.standardError=errors
        try process.run()
        let payload=output.fileHandleForReading.readDataToEndOfFile();process.waitUntilExit()
        XCTAssertEqual(process.terminationStatus,0,"synthetic producer failed")
        let key=Curve25519.Signing.PrivateKey()
        let envelope=try MigrationSignedPackageSourceTests().envelope(payload,key:key)
        let source=try MigrationSignedPackageSource(publicKey:key.publicKey.rawRepresentation){envelope}
        let package=try source.selectedPackageSynchronously()
        XCTAssertNotNil(package.intent.newCanonicalExecutable)
        let manifest=try MigrationRuntimeConsoleManifest(frozenPlan:package.frozenPlan,intent:package.intent)
        XCTAssertEqual(manifest.bundle.path,FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Applications/Mechanize.app").path)
        var outer=try JSONSerialization.jsonObject(with:payload) as! [String:Any]
        var plan=try JSONSerialization.jsonObject(with:package.frozenPlan) as! [String:Any]
        XCTAssertEqual(outer["version"] as? Int,1);XCTAssertEqual(plan["version"] as? Int,2)
        plan["version"]=1
        let wrong=try JSONSerialization.data(withJSONObject:plan)
        outer["installPlanBase64"]=wrong.base64EncodedString();outer["installPlanSHA256"]=MigrationUpgradeIntent.digest(wrong)
        let bad=try JSONSerialization.data(withJSONObject:outer)
        XCTAssertThrowsError(try MigrationReviewedUpgradePackage(authenticatedPayload:bad,expectedSHA256:MigrationUpgradeIntent.digest(bad)))
    }
}
