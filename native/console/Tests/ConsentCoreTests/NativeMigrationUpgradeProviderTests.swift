import XCTest
@testable import ConsentCore

private final class ProviderCredentialSentinel: EnrollmentCredentialProvider {
    var calls = 0
    func credential() throws -> Data { calls += 1; throw MigrationConsoleError.unavailable }
}

@MainActor final class NativeMigrationUpgradeProviderTests: XCTestCase {
    private func fixture(session: String = String(repeating: "f", count: 64)) throws -> (MigrationUpgradeIntent, Data, MigrationWorkerManifest) {
        let broker = "/Users/fixture/runtime/mechanize"
        let requirement: (String, String) -> String = { role, hash in "identifier \"com.viant.mechanize.\(role)\" and cdhash H\"\(String(repeating: hash, count: 40))\"" }
        let old = requirement("broker", "a"), new = requirement("broker", "b")
        let plan: [String: Any] = ["version": 1, "runtime": [
            "BrokerPath": broker, "OldBrokerRequirement": old, "NewBrokerRequirement": new,
            "Artifacts": [["role": "console", "target": "/Users/fixture/runtime/Mechanize Permissions.app",
                "NewRequirement": requirement("consent", "c"), "New": [
                    ".": ["kind": "directory", "mode": 448],
                    "Contents": ["kind": "directory", "mode": 493],
                    "Contents/MacOS": ["kind": "directory", "mode": 493],
                    "Contents/MacOS/MechanizeConsent": ["kind": "file", "mode": 493, "size": 12, "sha256": String(repeating: "d", count: 64)]
                ]]]]]
        let bytes = try JSONSerialization.data(withJSONObject: plan, options: [.sortedKeys, .withoutEscapingSlashes])
        let worker = try MigrationWorkerManifest(executable: URL(fileURLWithPath: "/Users/fixture/runtime/installer"), requirement: requirement("custody-migration", "e"), sha256: String(repeating: "a", count: 64))
        let bootstrap = try MigrationWorkerBootstrap(session: session, configSHA256: String(repeating: "b", count: 64), canonicalExecutable: broker,
            oldRequirement: old, newRequirement: new, alias: "fixture-alias", service: "com.viant.mechanize.vault", account: "fixture-account", workerRequirement: worker.requirement)
        return (try MigrationUpgradeIntent(worker: worker, bootstrap: bootstrap, runtimeManifestSHA256: MigrationUpgradeIntent.digest(bytes)), bytes, worker)
    }

    func testChangedFrozenPlanRejectedBeforeCredentialLookup() throws {
        let (intent, _, worker) = try fixture(); let credentials = ProviderCredentialSentinel()
        XCTAssertThrowsError(try NativeMigrationUpgradeProvider(intent: intent, frozenPlan: Data("{}".utf8), preparationWorker: worker, credentials: credentials))
        XCTAssertEqual(credentials.calls, 0)
    }

    func testCancellationBeforePreparationNeverLaunchesOrReadsCredential() async throws {
        let (intent, plan, worker) = try fixture(); let credentials = ProviderCredentialSentinel()
        let provider = try NativeMigrationUpgradeProvider(intent: intent, frozenPlan: plan, preparationWorker: worker, credentials: credentials)
        await provider.cancel(nil)
        do { _ = try await provider.prepare(intent); XCTFail("cancelled provider admitted preparation") }
        catch { XCTAssertEqual(credentials.calls, 0) }
    }

    func testDifferentIntentRejectedBeforePreparation() async throws {
        let (intent, plan, worker) = try fixture(); let credentials = ProviderCredentialSentinel()
        let (other, _, _) = try fixture(session: String(repeating: "a", count: 64))
        let provider = try NativeMigrationUpgradeProvider(intent: intent, frozenPlan: plan, preparationWorker: worker, credentials: credentials)
        do { _ = try await provider.prepare(other); XCTFail("substituted intent admitted") }
        catch { XCTAssertEqual(credentials.calls, 0) }
    }
}
