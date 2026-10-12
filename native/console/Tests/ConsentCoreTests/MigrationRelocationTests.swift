import XCTest
@testable import ConsentCore

final class MigrationRelocationTests: XCTestCase {
    func testBootstrapAndIntentBindRelocationWithoutChangingLegacyOptions() throws {
        let legacy = try MigrationNativePreparationTests().intent()
        let o = legacy.options
        let destination = "/fixture/Mechanize.app/Contents/Helpers/mechanize"
        func bootstrap(_ path: String) throws -> MigrationWorkerBootstrap {
            try MigrationWorkerBootstrap(session:legacy.bootstrap.session, configSHA256:legacy.bootstrap.value["configSHA256"] as! String,
                canonicalExecutable:o[0], oldRequirement:o[1], newRequirement:o[2], alias:o[3], service:o[4], account:o[5],
                workerRequirement:legacy.worker.requirement, newCanonicalExecutable:path)
        }
        let relocation = try bootstrap(destination)
        XCTAssertEqual(relocation.value["version"] as? Int, 2)
        XCTAssertEqual(legacy.bootstrap.value["version"] as? Int, 1)
        let intent = try MigrationUpgradeIntent(worker:legacy.worker, bootstrap:relocation, runtimeManifestSHA256:legacy.runtimeManifestSHA256)
        XCTAssertEqual(Array(intent.options.prefix(6)), o)
        XCTAssertEqual(Array(intent.options.suffix(2)), [destination,MigrationUpgradeIntent.relocationDomain])
        XCTAssertNotEqual(intent.optionsSHA256,legacy.optionsSHA256)
        XCTAssertNotEqual(intent.binding,legacy.binding)
        XCTAssertEqual(intent.installedBrokerExecutable,destination)
        let id = String(repeating:"a",count:64), item = String(repeating:"b",count:64)
        XCTAssertNotEqual(try intent.transitionBinding(id:id,itemSHA256:item),try legacy.transitionBinding(id:id,itemSHA256:item))
        XCTAssertEqual(intent.transitionNames.last,"NewCanonicalExecutable")
        let fixture = MigrationNativePreparationTests()
        let packet = try fixture.packet(intent)
        XCTAssertNoThrow(try MigrationNativePreparation.decode(packet,intent:intent,requestID:fixture.hex("1"),validUntil:Date().addingTimeInterval(30)))
        let changed = String(data:packet,encoding:.utf8)!.replacingOccurrences(of:destination,with:destination + "-changed")
        XCTAssertThrowsError(try MigrationNativePreparation.decode(Data(changed.utf8),intent:intent,requestID:fixture.hex("1"),validUntil:Date().addingTimeInterval(30)))
        for malformed in [o[0],"relative", "/fixture/../mechanize", "/fixture/mechanize\n"] {
            XCTAssertThrowsError(try bootstrap(malformed))
        }
    }
}
