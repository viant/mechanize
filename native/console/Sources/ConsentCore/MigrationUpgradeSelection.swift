import Foundation
import Combine

/// An authenticated package is selection metadata, never human authorization.
/// A production source must obtain its expected digest from the existing signed
/// installation/review channel, not from the selected file or a worker challenge.
/// No production source is installed until that channel has been qualified.
@MainActor public protocol MigrationUpgradePackageSource: AnyObject {
    func selectedPackage() async throws -> MigrationReviewedUpgradePackage
}

/// Digest-covered references only. The actual broker peer and private resource
/// are independently checked when the approved action collects observations.
struct MigrationReviewedObserverEnrollment {
    let reader: MigrationObserverReaderEnrollment
    let profileChannel: String, browserInstance: String, windowTitle: String
    let preservedChrome: MigrationInstallerRuntime?
    init(_ raw: Any?, intent: MigrationUpgradeIntent, frozenPlan: Data) throws {
        guard let root = try JSONSerialization.jsonObject(with: frozenPlan) as? [String:Any], let runtime = root["runtime"] as? [String:Any] else { throw MigrationUpgradeError.invalidPreparation }
        let preserve = ["preserve-extension-v1","unified-app-v2","unified-app-update-v3"].contains(runtime["Mode"] as? String ?? "")
        let scopeKeys = preserve ? ["chromePID", "chromeStart"] : ["profileChannel", "browserInstance"]
        guard let fields = raw as? [String: Any],
              Set(fields.keys) == Set(["port", "brokerPID", "brokerStart", "brokerRequirement", "credentialURL", "credentialSHA256", "windowTitle", "consentBinding"] + scopeKeys),
              let port = MigrationRuntimeConsoleManifest.integer(fields["port"]), port > 0, port <= Int(UInt16.max),
              let pid = MigrationRuntimeConsoleManifest.integer(fields["brokerPID"]), pid > 0, pid <= Int(Int32.max),
              let birth = fields["brokerStart"] as? String,
              let requirement = fields["brokerRequirement"] as? String, requirement == intent.options[1],
              let resource = fields["credentialURL"] as? String, MigrationRuntimeConsoleManifest.path(resource),
              let digest = fields["credentialSHA256"] as? String, MigrationAuthorizationRecord.digest(digest) else {
            throw MigrationUpgradeError.invalidPreparation
        }
        // Reuse strict canonical PID/birth parsing; booleans, fractional IDs,
        // oversized values and alternate birth-token encodings are rejected.
        _ = try MigrationInstallerRuntime(brokerPID: Int32(pid), brokerStartToken: birth)
        func text(_ key: String, maximum: Int) throws -> String {
            guard let value = fields[key] as? String, !value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
                  value.utf8.count <= maximum,
                  !value.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else {
                throw MigrationUpgradeError.invalidPreparation
            }
            return value
        }
        reader = try MigrationObserverReaderEnrollment(port: UInt16(port), brokerPID: Int32(pid), brokerStart: birth,
            brokerRequirement: requirement, credentialURL: URL(fileURLWithPath: resource), credentialSHA256: digest, consentBinding: try MigrationObserverConsentBinding(fields["consentBinding"]))
        if preserve {
            if intent.newCanonicalExecutable != nil || runtime["Mode"] as? String == "unified-app-update-v3" { _ = try MigrationUnifiedAppManifest(runtime:runtime,intent:intent) }
            else { _ = try MigrationPreservedExtensionManifest(runtime: runtime) }
            guard let pid = MigrationRuntimeConsoleManifest.integer(fields["chromePID"]), pid > 0, pid <= Int(Int32.max),
                  let birth = fields["chromeStart"] as? String, let requirement = runtime["ChromeRequirement"] as? String, !requirement.isEmpty,
                  runtime["ExtensionStorageSHA256"] == nil, runtime["PreservedExtension"] is [String:Any] else { throw MigrationUpgradeError.invalidPreparation }
            preservedChrome = try MigrationInstallerRuntime(brokerPID: Int32(pid), brokerStartToken: birth)
            profileChannel = ""; browserInstance = ""
        } else {
            guard runtime["Mode"] == nil, runtime["PreservedExtension"] == nil else { throw MigrationUpgradeError.invalidPreparation }
            preservedChrome = nil
            profileChannel = try text("profileChannel", maximum: 128)
            browserInstance = try text("browserInstance", maximum: 128)
        }
        windowTitle = try text("windowTitle", maximum: 1024)
    }
}

/// No public JSON initializer: only the qualified native source in ConsentCore
/// may decode a package against an independently reviewed digest. Worker pins are
/// checked again by the existing signed launcher; the Go installer owns complete
/// install-plan validation, placement, ACL policy and durable recovery.
public final class MigrationReviewedUpgradePackage: CustomStringConvertible, CustomDebugStringConvertible {
    public let title: String
    public let digest: String
    let intent: MigrationUpgradeIntent
    let preparationWorker: MigrationWorkerManifest
    let frozenPlan: Data
    let observerEnrollment: MigrationReviewedObserverEnrollment
    public var description: String { "Reviewed runtime upgrade package" }
    public var debugDescription: String { description }

    init(authenticatedPayload data: Data, expectedSHA256: String) throws {
        guard !data.isEmpty, data.count <= 2_000_000, MigrationAuthorizationRecord.digest(expectedSHA256),
              MigrationUpgradeIntent.digest(data) == expectedSHA256 else { throw MigrationUpgradeError.invalidPreparation }
        try MigrationReadinessJSON.validate(data)
        guard let root = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(root.keys) == Set(["version", "title", "preparationWorker", "installerWorker", "bootstrap", "installPlanBase64", "installPlanSHA256", "observer"]),
              MigrationRuntimeConsoleManifest.integer(root["version"]) == 1,
              let title = root["title"] as? String, !title.isEmpty, title.utf8.count <= 120,
              !title.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }),
              let encodedPlan = root["installPlanBase64"] as? String, let plan = Data(base64Encoded: encodedPlan),
              plan.base64EncodedString() == encodedPlan, !plan.isEmpty, plan.count <= 1_048_576,
              let planSHA = root["installPlanSHA256"] as? String, MigrationUpgradeIntent.digest(plan) == planSHA,
              let raw = root["bootstrap"] as? [String: Any],
              Set(raw.keys) == Set(["session", "configSHA256", "canonicalExecutable", "oldRequirement", "newRequirement", "alias", "service", "account", "workerRequirement"] + (raw["newCanonicalExecutable"] == nil ? [] : ["newCanonicalExecutable"])) else { throw MigrationUpgradeError.invalidPreparation }
        func manifest(_ value: Any?) throws -> MigrationWorkerManifest {
            guard let fields = value as? [String: Any], Set(fields.keys) == Set(["executable", "requirement", "sha256"]),
                  let path = fields["executable"] as? String, MigrationRuntimeConsoleManifest.path(path),
                  let requirement = fields["requirement"] as? String, let sha = fields["sha256"] as? String else { throw MigrationUpgradeError.invalidPreparation }
            return try MigrationWorkerManifest(executable: URL(fileURLWithPath: path), requirement: requirement, sha256: sha)
        }
        func text(_ key: String) throws -> String {
            guard let value = raw[key] as? String, !value.isEmpty,
                  !value.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else { throw MigrationUpgradeError.invalidPreparation }
            return value
        }
        let preparation = try manifest(root["preparationWorker"]), installer = try manifest(root["installerWorker"])
        guard preparation.executable != installer.executable, preparation.requirement != installer.requirement,
              preparation.sha256 != installer.sha256,
              try text("workerRequirement") == installer.requirement,
              MigrationRuntimeConsoleManifest.path(try text("canonicalExecutable")) else { throw MigrationUpgradeError.invalidPreparation }
        let bootstrap = try MigrationWorkerBootstrap(session: text("session"), configSHA256: text("configSHA256"), canonicalExecutable: text("canonicalExecutable"), oldRequirement: text("oldRequirement"), newRequirement: text("newRequirement"), alias: text("alias"), service: text("service"), account: text("account"), workerRequirement: text("workerRequirement"), newCanonicalExecutable: raw["newCanonicalExecutable"] == nil ? nil : text("newCanonicalExecutable"))
        let intent = try MigrationUpgradeIntent(worker: installer, bootstrap: bootstrap, runtimeManifestSHA256: planSHA)
        _ = try MigrationRuntimeConsoleManifest(frozenPlan: plan, intent: intent)
        observerEnrollment = try MigrationReviewedObserverEnrollment(root["observer"], intent: intent, frozenPlan: plan)
        self.title = title; digest = expectedSHA256; self.intent = intent
        preparationWorker = preparation; frozenPlan = plan
    }
    func makePreservationObserver() throws -> MigrationRuntimeObserverCollector {
        guard let chrome = observerEnrollment.preservedChrome else { throw MigrationUpgradeError.invalidPreparation }
        return try MigrationRuntimeObserverCollector(preservingExtensionIntent: intent, frozenPlan: frozenPlan, enrollment: observerEnrollment.reader,
            chromePID: chrome.brokerPID, chromeStart: chrome.brokerStartToken, windowTitle: observerEnrollment.windowTitle)
    }
    func makeObserver(credentials: any EnrollmentCredentialProvider) throws -> MigrationRuntimeObserverCollector {
        if let chrome = observerEnrollment.preservedChrome {
            return try MigrationRuntimeObserverCollector(preservingExtensionIntent: intent, frozenPlan: frozenPlan, enrollment: observerEnrollment.reader,
                chromePID: chrome.brokerPID, chromeStart: chrome.brokerStartToken, windowTitle: observerEnrollment.windowTitle)
        }
        return try MigrationRuntimeObserverCollector(intent: intent, frozenPlan: frozenPlan, enrollment: observerEnrollment.reader,
            credentials: credentials, profileChannel: observerEnrollment.profileChannel,
            browserInstance: observerEnrollment.browserInstance, windowTitle: observerEnrollment.windowTitle)
    }
    @MainActor func makeProvider(credentials: any EnrollmentCredentialProvider) throws -> NativeMigrationUpgradeProvider {
        let collector = try makeObserver(credentials: credentials)
        return try NativeMigrationUpgradeProvider(intent: intent, frozenPlan: frozenPlan,
            preparationWorker: preparationWorker, credentials: credentials, runtimeObserver: collector)
    }
}

public enum MigrationUpgradeSelectionState: String { case unavailable, selecting, selected, starting, consumed, cancelled, failed }

/// Main-window composition root. Selection performs no credential lookup or
/// preparation. Only the Upgrade button calls approveSelectedUpgrade(). Neither
/// app launch nor a package's fields can create the original human approval.
@MainActor public final class MigrationUpgradeSelection: ObservableObject {
    @Published public private(set) var state: MigrationUpgradeSelectionState = .unavailable
    @Published public private(set) var selectedTitle: String?
    @Published public private(set) var coordinator = MigrationUpgradeCoordinator()
    public var relocationSource: String? { selected?.intent.newCanonicalExecutable == nil ? nil : selected?.intent.options[0] }
    public var relocationDestination: String? { selected?.intent.newCanonicalExecutable }
    public var canSelect: Bool { source != nil && factory != nil && !inFlight && !actionConsumed }
    public var canUpgrade: Bool { state == .selected && selected != nil && !inFlight && !actionConsumed }
    private let source: (any MigrationUpgradePackageSource)?
    private let factory: ((MigrationReviewedUpgradePackage) throws -> MigrationUpgradeCoordinator)?
    private var selected: MigrationReviewedUpgradePackage?
    private var inFlight = false, actionConsumed = false
    private var revision: UInt64 = 0

    public init(source: (any MigrationUpgradePackageSource)? = nil, credentials: (any EnrollmentCredentialProvider)? = nil) {
        self.source = source
        if source != nil, let credentials {
            factory = { package in
                let provider = try package.makeProvider(credentials: credentials)
                return MigrationUpgradeCoordinator(backend: provider, credentials: credentials)
            }
        } else { factory = nil }
    }
    // Fixture seam; never reachable through package metadata or IPC.
    init(source: any MigrationUpgradePackageSource, factory: @escaping (MigrationReviewedUpgradePackage) throws -> MigrationUpgradeCoordinator) {
        self.source = source; self.factory = factory
    }
    public func selectReviewedPackage() async throws {
        guard canSelect, let source else { throw MigrationUpgradeError.unavailable }
        revision &+= 1; let held = revision
        state = .selecting; inFlight = true; selected = nil; selectedTitle = nil
        defer { inFlight = false }
        do {
            let package = try await source.selectedPackage()
            guard revision == held, !Task.isCancelled else { throw MigrationUpgradeError.cancelled }
            selected = package; selectedTitle = package.title; state = .selected
        } catch {
            if revision == held { state = .failed }
            throw error
        }
    }
    public func approveSelectedUpgrade() async throws {
        guard canUpgrade, let original = selected, let source, let factory else { throw MigrationUpgradeError.unavailable }
        // Consume before awaiting source revalidation, so a double click cannot
        // start a second preparation or exchange an approved package for another.
        actionConsumed = true; inFlight = true; state = .starting
        let held = revision
        defer { inFlight = false }
        do {
            let current = try await source.selectedPackage()
            guard revision == held, !Task.isCancelled else { throw MigrationUpgradeError.cancelled }
            guard current.digest == original.digest, current.intent.binding == original.intent.binding else { throw MigrationUpgradeError.invalidPreparation }
            let running = try factory(original)
            guard running.state == .ready else { throw MigrationUpgradeError.unavailable }
            coordinator = running
            try await running.startApprovedUpgrade(original.intent)
            state = .consumed
        } catch {
            if revision == held { state = .failed }
            throw error
        }
    }
    public func cancel() {
        revision &+= 1
        selected = nil; selectedTitle = nil; actionConsumed = true
        coordinator.cancel()
        state = .cancelled
    }
}
