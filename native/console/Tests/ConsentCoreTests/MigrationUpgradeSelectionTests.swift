import XCTest
@testable import ConsentCore

private final class SelectionCredentials: EnrollmentCredentialProvider {
    var reads = 0
    func credential() throws -> Data { reads += 1; throw MigrationConsoleError.unavailable }
}
@MainActor private final class SelectionSource: MigrationUpgradePackageSource {
    var package: MigrationReviewedUpgradePackage
    var reads = 0
    var pauseAt = 0
    var continuation: CheckedContinuation<Void, Never>?
    init(_ package: MigrationReviewedUpgradePackage) { self.package = package }
    func selectedPackage() async throws -> MigrationReviewedUpgradePackage {
        reads += 1
        if reads == pauseAt { await withCheckedContinuation { continuation = $0 } }
        return package
    }
    func resume() { continuation?.resume(); continuation = nil }
}
private final class SelectionPreparation: MigrationUpgradePreparationProvider {
    var preparations = 0
    func prepare(_ intent: MigrationUpgradeIntent) async throws -> MigrationNativePreparation {
        preparations += 1; throw MigrationUpgradeError.unavailable
    }
    func restartAndVerifyRuntime(_ preparation: MigrationNativePreparation, terminal: MigrationInstallerReply) async throws { XCTFail("unexpected runtime start") }
    func cancel(_ preparation: MigrationNativePreparation?) async {}
}

@MainActor final class MigrationUpgradeSelectionTests: XCTestCase {
    func payload(title: String = "Reviewed runtime update") throws -> Data {
        let f = MigrationNativePreparationTests(), original = try f.intent()
        let plan: [String: Any] = ["version": 1, "readiness": ["launchd": ["path": "/private/fixture/broker.plist", "sha256": f.hex("9")], "listen": "127.0.0.1:4987"], "runtime": [
            "BrokerPath": original.options[0], "OldBrokerRequirement": original.options[1], "NewBrokerRequirement": original.options[2],
            "Artifacts": [["role": "console", "target": "/private/fixture/Mechanize Permissions.app", "NewRequirement": f.pin("consent", "5"), "New": [
                ".": ["kind": "directory", "mode": 448], "Contents": ["kind": "directory", "mode": 493], "Contents/MacOS": ["kind": "directory", "mode": 493],
                "Contents/MacOS/MechanizeConsent": ["kind": "file", "mode": 493, "size": 12, "sha256": f.hex("d")]
            ]]]]]
        let bytes = try JSONSerialization.data(withJSONObject: plan, options: [.sortedKeys, .withoutEscapingSlashes])
        var bootstrap = original.bootstrap.value; bootstrap.removeValue(forKey: "version"); bootstrap.removeValue(forKey: "op")
        return try JSONSerialization.data(withJSONObject: ["version": 1, "title": title,
            "preparationWorker": ["executable": "/private/fixture/preparation", "requirement": f.pin("custody-migration", "6"), "sha256": f.hex("7")],
            "installerWorker": ["executable": original.worker.executable.path, "requirement": original.worker.requirement, "sha256": original.worker.sha256],
            "observer": ["consentBinding": ["sessionID":"fixture-session","purpose":"inspect management"], "port": 4987, "brokerPID": 42, "brokerStart": "1790000000:1", "brokerRequirement": original.options[1],
                "credentialURL": "/private/fixture/observer/read-token", "credentialSHA256": f.hex("8"),
                "profileChannel": "fixture-profile", "browserInstance": "fixture-browser", "windowTitle": "Extensions - Google Chrome"],
            "bootstrap": bootstrap, "installPlanBase64": bytes.base64EncodedString(), "installPlanSHA256": MigrationUpgradeIntent.digest(bytes)], options: [.sortedKeys, .withoutEscapingSlashes])
    }
    func package(title: String = "Reviewed runtime update") throws -> MigrationReviewedUpgradePackage {
        let bytes = try payload(title: title)
        return try MigrationReviewedUpgradePackage(authenticatedPayload: bytes, expectedSHA256: MigrationUpgradeIntent.digest(bytes))
    }
    func testMalformedAndSubstitutedPackagesFailClosed() throws {
        let valid = try payload(), digest = MigrationUpgradeIntent.digest(valid)
        _ = try MigrationReviewedUpgradePackage(authenticatedPayload: valid, expectedSHA256: digest)
        XCTAssertThrowsError(try MigrationReviewedUpgradePackage(authenticatedPayload: payload(title: "Substituted"), expectedSHA256: digest))
        let text = String(data: valid, encoding: .utf8)!
        for bytes in [Data((text + "{}").utf8), Data(text.replacingOccurrences(of: "\"version\":1", with: "\"version\":1,\"version\":1").utf8)] {
            XCTAssertThrowsError(try MigrationReviewedUpgradePackage(authenticatedPayload: bytes, expectedSHA256: MigrationUpgradeIntent.digest(bytes)))
        }
        for change in ["approval", "plan", "worker", "bootstrap", "path", "sameWorker", "boolVersion"] {
            var root = try JSONSerialization.jsonObject(with: valid) as! [String: Any]
            switch change {
            case "approval": root["approved"] = true
            case "plan": root["installPlanBase64"] = Data("{}".utf8).base64EncodedString()
            case "worker": var worker = root["installerWorker"] as! [String: Any]; worker["requirement"] = MigrationNativePreparationTests().pin("broker", "1"); root["installerWorker"] = worker
            case "bootstrap": var bootstrap = root["bootstrap"] as! [String: Any]; bootstrap["workerRequirement"] = MigrationNativePreparationTests().pin("custody-migration", "8"); root["bootstrap"] = bootstrap
            case "path": var worker = root["preparationWorker"] as! [String: Any]; worker["executable"] = "/private/fixture/../unreviewed"; root["preparationWorker"] = worker
            case "sameWorker": root["preparationWorker"] = root["installerWorker"]
            default: root["version"] = true
            }
            let bytes = try JSONSerialization.data(withJSONObject: root, options: [.sortedKeys, .withoutEscapingSlashes])
            XCTAssertThrowsError(try MigrationReviewedUpgradePackage(authenticatedPayload: bytes, expectedSHA256: MigrationUpgradeIntent.digest(bytes)), change)
        }
    }
    func testUnavailableSourceAndMissingCredentialsNeverLookUpSecrets() async throws {
        let credentials = SelectionCredentials()
        let unavailable = MigrationUpgradeSelection(credentials: credentials)
        XCTAssertFalse(unavailable.canSelect); XCTAssertFalse(unavailable.canUpgrade)
        do { try await unavailable.selectReviewedPackage(); XCTFail("missing source selected") } catch {}
        do { try await unavailable.approveSelectedUpgrade(); XCTFail("missing source approved") } catch {}
        let source = SelectionSource(try package())
        let missingCredential = MigrationUpgradeSelection(source: source)
        do { try await missingCredential.selectReviewedPackage(); XCTFail("missing credential route selected") } catch {}
        XCTAssertEqual(source.reads, 0); XCTAssertEqual(credentials.reads, 0)
    }
    func testSelectionDoesNotPrepareAndSubstitutionCannotUseApproval() async throws {
        let source = SelectionSource(try package()); var factories = 0
        let action = MigrationUpgradeSelection(source: source) { _ in factories += 1; return MigrationUpgradeCoordinator() }
        try await action.selectReviewedPackage()
        XCTAssertTrue(action.canUpgrade); XCTAssertEqual(factories, 0)
        source.package = try package(title: "Different reviewed update")
        do { try await action.approveSelectedUpgrade(); XCTFail("substituted selected package approved") } catch {}
        XCTAssertEqual(factories, 0); XCTAssertFalse(action.canUpgrade); XCTAssertFalse(action.canSelect)
    }
    func testExplicitActionIsConsumedBeforePreparationAndCannotRepeat() async throws {
        let source = SelectionSource(try package()), provider = SelectionPreparation()
        var factories = 0
        let action = MigrationUpgradeSelection(source: source) { _ in
            factories += 1
            return MigrationUpgradeCoordinator(backend: provider) { _, _ in throw MigrationUpgradeError.unavailable }
        }
        try await action.selectReviewedPackage()
        XCTAssertEqual(provider.preparations, 0)
        do { try await action.approveSelectedUpgrade(); XCTFail("fixture preparation should fail") } catch {}
        do { try await action.approveSelectedUpgrade(); XCTFail("approval replayed") } catch {}
        XCTAssertEqual(provider.preparations, 1); XCTAssertEqual(factories, 1)
    }
    func testCancellationWhileRevalidatingPreventsFactoryAndDuplicateAction() async throws {
        let source = SelectionSource(try package()); source.pauseAt = 2
        var factories = 0
        let action = MigrationUpgradeSelection(source: source) { _ in factories += 1; return MigrationUpgradeCoordinator() }
        try await action.selectReviewedPackage()
        let attempt = Task { try await action.approveSelectedUpgrade() }
        while source.continuation == nil { await Task.yield() }
        do { try await action.approveSelectedUpgrade(); XCTFail("concurrent approval admitted") } catch {}
        action.cancel(); source.resume()
        do { try await attempt.value; XCTFail("cancelled action continued") } catch {}
        XCTAssertEqual(action.state, .cancelled); XCTAssertEqual(factories, 0); XCTAssertEqual(source.reads, 2)
    }
    func testUnavailableCoordinatorCannotReachPreparation() async throws {
        let source = SelectionSource(try package())
        let action = MigrationUpgradeSelection(source: source) { _ in MigrationUpgradeCoordinator() }
        try await action.selectReviewedPackage()
        do { try await action.approveSelectedUpgrade(); XCTFail("unavailable provider admitted") } catch {}
        XCTAssertEqual(action.state, .failed); XCTAssertFalse(action.canUpgrade)
    }
    func testProductionCompositionSelectionAndCancellationReadNoCredential() async throws {
        let credentials = SelectionCredentials(), source = SelectionSource(try package())
        let action = MigrationUpgradeSelection(source: source, credentials: credentials)
        XCTAssertEqual(source.reads, 0); XCTAssertEqual(credentials.reads, 0)
        try await action.selectReviewedPackage()
        XCTAssertEqual(source.reads, 1); XCTAssertEqual(credentials.reads, 0)
        XCTAssertTrue(action.canUpgrade)
        action.cancel()
        do { try await action.approveSelectedUpgrade(); XCTFail("cancelled selection approved") } catch {}
        XCTAssertEqual(credentials.reads, 0); XCTAssertEqual(source.reads, 1)
    }
    func testCancellationDuringSelectionCannotPublishLatePackage() async throws {
        let source = SelectionSource(try package()); source.pauseAt = 1
        let action = MigrationUpgradeSelection(source: source) { _ in XCTFail("selection prepared upgrade"); return MigrationUpgradeCoordinator() }
        let selecting = Task { try await action.selectReviewedPackage() }
        while source.continuation == nil { await Task.yield() }
        action.cancel(); source.resume()
        do { try await selecting.value; XCTFail("late selection survived cancellation") } catch {}
        XCTAssertEqual(action.state, .cancelled); XCTAssertNil(action.selectedTitle); XCTAssertFalse(action.canUpgrade)
    }

    func testObserverEnrollmentIsClosedBoundedAndBoundToOldBroker() throws {
        let valid = try payload()
        for mode in ["missing", "credentialValue", "boolPort", "fractionalPID", "invalidBirth", "newBroker", "path", "digest", "emptyProfile", "unknownField"] {
            var root = try JSONSerialization.jsonObject(with: valid) as! [String: Any]
            var observer = root["observer"] as! [String: Any]
            switch mode {
            case "missing": root.removeValue(forKey: "observer")
            case "credentialValue": observer["credential"] = "must-not-be-accepted"
            case "boolPort": observer["port"] = true
            case "fractionalPID": observer["brokerPID"] = 42.5
            case "invalidBirth": observer["brokerStart"] = "01790000000:1"
            case "newBroker": observer["brokerRequirement"] = (root["bootstrap"] as! [String: Any])["newRequirement"]
            case "path": observer["credentialURL"] = "/private/fixture/../token"
            case "digest": observer["credentialSHA256"] = "not-a-digest"
            case "emptyProfile": observer["profileChannel"] = ""
            default: observer["quiescent"] = true
            }
            if mode != "missing" { root["observer"] = observer }
            let bytes = try JSONSerialization.data(withJSONObject: root, options: [.sortedKeys, .withoutEscapingSlashes])
            XCTAssertThrowsError(try MigrationReviewedUpgradePackage(authenticatedPayload: bytes, expectedSHA256: MigrationUpgradeIntent.digest(bytes)), mode)
        }
    }
    func testObserverSubstitutionCannotReusePackageDigest() throws {
        let valid = try payload(), digest = MigrationUpgradeIntent.digest(valid)
        var root = try JSONSerialization.jsonObject(with: valid) as! [String: Any]
        var observer = root["observer"] as! [String: Any]
        observer["brokerPID"] = 43; root["observer"] = observer
        let changed = try JSONSerialization.data(withJSONObject: root, options: [.sortedKeys, .withoutEscapingSlashes])
        XCTAssertThrowsError(try MigrationReviewedUpgradePackage(authenticatedPayload: changed, expectedSHA256: digest))
    }
    func testProductionCompositionConstructsBoundCollectorWithoutIO() async throws {
        let reviewed = try package(), credentials = SelectionCredentials()
        let observer = try reviewed.makeObserver(credentials: credentials)
        XCTAssertEqual(observer.intentBinding, reviewed.intent.binding)
        XCTAssertEqual(reviewed.observerEnrollment.reader.brokerPID, 42)
        XCTAssertEqual(reviewed.observerEnrollment.reader.brokerRequirement, reviewed.intent.options[1])
        XCTAssertEqual(reviewed.observerEnrollment.profileChannel, "fixture-profile")
        let provider = try reviewed.makeProvider(credentials: credentials)
        await provider.cancel(nil)
        do { _ = try await provider.prepare(reviewed.intent); XCTFail("cancelled provider started collection") } catch {}
        XCTAssertEqual(credentials.reads, 0)
    }

}
