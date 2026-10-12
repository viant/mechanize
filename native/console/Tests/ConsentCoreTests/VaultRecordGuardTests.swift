import XCTest
import Darwin
@testable import ConsentCore

final class VaultRecordGuardTests: XCTestCase {
    private var root: URL!
    private var parent: URL { root.appendingPathComponent("private", isDirectory: true) }
    private var directory: URL { parent.appendingPathComponent("console-native-record-guard", isDirectory: true) }
    override func setUpWithError() throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent("record-guard-test-" + UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    }
    override func tearDownWithError() throws { try FileManager.default.removeItem(at: root) }
    private func store() -> VaultRecordGuard { VaultRecordGuard(parent: parent) }
    private func artifact(_ name: String, _ bytes: String, mode: Int = 0o600) throws {
        let url = directory.appendingPathComponent(name)
        try Data(bytes.utf8).write(to: url)
        try FileManager.default.setAttributes([.posixPermissions: mode], ofItemAtPath: url.path)
    }
    func testReadOnlyStartupDoesNotCreateAnything() throws {
        XCTAssertEqual(try store().status(), .init())
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: root.path), [])
    }
    func testRestartRestoresIndependentBarriersAndRecoveryCannotClearMutation() throws {
        let first = store(), generation = try first.beginProtection()
        try first.beginMutation(generation: generation)
        let restarted = store()
        XCTAssertEqual(try restarted.status(), .init(protection: true, mutation: true, generation: generation))
        XCTAssertThrowsError(try restarted.beginProtection())
        try restarted.acknowledgeProtection(generation: generation)
        XCTAssertEqual(try store().status(), .init(mutation: true, generation: generation))
        XCTAssertThrowsError(try store().beginProtection())
        // Only a matching, known operation acknowledgement can clear this bit.
        try restarted.acknowledgeMutation(generation: generation)
        XCTAssertEqual(try store().status(), .init())
    }
    func testMutationAcknowledgementDoesNotImplyProtectionCleanup() throws {
        let guardStore = store(), generation = try guardStore.beginProtection()
        try guardStore.beginMutation(generation: generation)
        try guardStore.acknowledgeMutation(generation: generation)
        XCTAssertEqual(try store().status(), .init(protection: true, generation: generation))
        XCTAssertThrowsError(try guardStore.beginProtection())
        try guardStore.acknowledgeProtection(generation: generation)
        XCTAssertEqual(try store().status(), .init())
    }
    func testStaleAcknowledgementsCannotClearNewGeneration() throws {
        let guardStore = store(), stale = try guardStore.beginProtection()
        try guardStore.acknowledgeProtection(generation: stale)
        let current = try guardStore.beginProtection()
        XCTAssertNotEqual(stale, current)
        XCTAssertThrowsError(try guardStore.beginMutation(generation: stale))
        // A recovery response for the old lease is also stale.
        XCTAssertThrowsError(try guardStore.acknowledgeProtection(generation: stale))
        try guardStore.beginMutation(generation: current)
        XCTAssertThrowsError(try guardStore.acknowledgeMutation(generation: stale))
        XCTAssertEqual(try guardStore.status(), .init(protection: true, mutation: true, generation: current))
    }
    func testDuplicateAdmissionAndMutationAreRefusedAcrossInstances() throws {
        let generation = try store().beginProtection()
        XCTAssertThrowsError(try store().beginProtection())
        try store().beginMutation(generation: generation)
        XCTAssertThrowsError(try store().beginMutation(generation: generation))
    }
    func testMutationRequiresPersistedProtection() throws {
        XCTAssertThrowsError(try store().beginMutation(generation: UUID().uuidString))
        XCTAssertFalse(FileManager.default.fileExists(atPath: directory.appendingPathComponent("status").path))
    }
    func testMarkerContainsOnlyVersionRandomGenerationAndPublicFlags() throws {
        let generation = try store().beginProtection()
        try store().beginMutation(generation: generation)
        let data = try Data(contentsOf: directory.appendingPathComponent("status"))
        XCTAssertEqual(String(data: data, encoding: .utf8), "mechanize-record-guard-v1\n\(generation)\nprotection+mutation\n")
        for url in [parent, directory] {
            XCTAssertEqual(try FileManager.default.attributesOfItem(atPath: url.path)[.posixPermissions] as? Int, 0o700)
        }
        for name in ["status", "lock"] {
            XCTAssertEqual(try FileManager.default.attributesOfItem(atPath: directory.appendingPathComponent(name).path)[.posixPermissions] as? Int, 0o600)
        }
    }
    func testIncompleteWriteAndUnknownArtifactRefuseFurtherDispatchAndAcknowledgement() throws {
        let generation = try store().beginProtection()
        try artifact("pending", "partial")
        XCTAssertThrowsError(try store().status())
        XCTAssertThrowsError(try store().beginMutation(generation: generation))
        XCTAssertThrowsError(try store().acknowledgeProtection(generation: generation))
        XCTAssertTrue(FileManager.default.fileExists(atPath: directory.appendingPathComponent("status").path))
        try FileManager.default.removeItem(at: directory.appendingPathComponent("pending"))
        try artifact("unexpected", "public")
        XCTAssertThrowsError(try store().status())
    }
    func testMalformedMarkerNeverBecomesClean() throws {
        _ = try store().beginProtection()
        for content in ["", "mechanize-record-guard-v1\nprotection\n", "mechanize-record-guard-v2\n", String(repeating: "x", count: 200)] {
            try artifact("status", content)
            XCTAssertThrowsError(try store().status())
            XCTAssertThrowsError(try store().beginProtection())
        }
    }
    func testSymlinkParentAndChildDirectoriesAreRefused() throws {
        try FileManager.default.createSymbolicLink(at: parent, withDestinationURL: root)
        XCTAssertThrowsError(try store().status())
        XCTAssertThrowsError(try store().beginProtection())
        try FileManager.default.removeItem(at: parent)
        try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        try FileManager.default.createSymbolicLink(at: directory, withDestinationURL: root)
        XCTAssertThrowsError(try store().status())
        XCTAssertThrowsError(try store().beginProtection())
    }
    func testSymlinkAndHardlinkedMarkerAreRefused() throws {
        _ = try store().beginProtection()
        let marker = directory.appendingPathComponent("status"), outside = root.appendingPathComponent("public-fixture")
        try FileManager.default.moveItem(at: marker, to: outside)
        try FileManager.default.createSymbolicLink(at: marker, withDestinationURL: outside)
        XCTAssertThrowsError(try store().status())
        try FileManager.default.removeItem(at: marker)
        XCTAssertEqual(link(outside.path, marker.path), 0)
        XCTAssertThrowsError(try store().status())
    }
    func testPermissiveFilesAndDirectoriesAreRefused() throws {
        _ = try store().beginProtection()
        for url in [parent, directory, directory.appendingPathComponent("status"), directory.appendingPathComponent("lock")] {
            let previous = try FileManager.default.attributesOfItem(atPath: url.path)[.posixPermissions] as! Int
            try FileManager.default.setAttributes([.posixPermissions: previous | 0o044], ofItemAtPath: url.path)
            XCTAssertThrowsError(try store().status())
            try FileManager.default.setAttributes([.posixPermissions: previous], ofItemAtPath: url.path)
        }
    }
    func testAcknowledgementPersistenceFailureRemainsBlockedAfterRestart() throws {
        let generation = try store().beginProtection()
        try store().beginMutation(generation: generation)
        try artifact("pending", "simulated-interrupted-write")
        XCTAssertThrowsError(try store().acknowledgeMutation(generation: generation))
        XCTAssertThrowsError(try store().status())
        XCTAssertThrowsError(try store().beginProtection())
    }
    func testNonregularLockIsRefusedWithoutBlocking() throws {
        _ = try store().beginProtection()
        let lockURL = directory.appendingPathComponent("lock")
        try FileManager.default.removeItem(at: lockURL)
        XCTAssertEqual(mkfifo(lockURL.path, mode_t(0o600)), 0)
        let completed = expectation(description: "FIFO guard inspection refuses promptly")
        let guarded = store()
        DispatchQueue.global().async {
            do { _ = try guarded.status(); XCTFail("Nonregular lock was accepted") } catch {}
            completed.fulfill()
        }
        wait(for: [completed], timeout: 1)
    }

}
