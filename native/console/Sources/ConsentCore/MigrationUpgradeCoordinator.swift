import Foundation
import Combine
import CryptoKit

public enum MigrationUpgradeError: Error { case unavailable, busy, consumedIntent, invalidPreparation, cancelled, recoveryRequired }
public enum MigrationUpgradeState: String {
    case unavailable, ready, preparing, startingWorker, verifyingPreparation, recordingRecovery,
         changingCustody, placingArtifacts, closingWorker, placingConsole, complete, cancelled, failed, recoveryRequired
    public var message: String {
        switch self {
        case .unavailable: return "Upgrade preparation is not connected to the installed runtime."
        case .ready: return "Ready to prepare the selected upgrade."
        case .preparing: return "Checking the selected upgrade and current custody."
        case .startingWorker: return "Starting the verified private upgrade worker."
        case .verifyingPreparation: return "Verifying the exact prepared transition."
        case .recordingRecovery: return "Saving recovery evidence before the change."
        case .changingCustody: return "Applying the approved custody transition."
        case .placingArtifacts: return "Installing and verifying runtime artifacts."
        case .closingWorker: return "Confirming the worker has finished."
        case .placingConsole: return "Completing the console update and final verification."
        case .complete: return "The upgrade was independently verified."
        case .cancelled: return "The upgrade was cancelled before custody changed."
        case .failed: return "The upgrade stopped before custody changed."
        case .recoveryRequired: return "Recovery evidence must be inspected before any further change."
        }
    }
}

/// Frozen, reviewed public metadata selected by the main window before its
/// existing Upgrade action. Not Codable and never reconstructed from a challenge.
public struct MigrationUpgradeIntent: CustomStringConvertible, CustomDebugStringConvertible {
    let worker: MigrationWorkerManifest
    let bootstrap: MigrationWorkerBootstrap
    let runtimeManifestSHA256: String
    public let binding: String
    let optionsSHA256: String
    let options: [String]
    static let relocationDomain = "mechanize-custody-relocation-v2"
    var newCanonicalExecutable: String? { bootstrap.value["newCanonicalExecutable"] as? String }
    var installedBrokerExecutable: String { newCanonicalExecutable ?? options[0] }
    var transitionNames: [String] {
        let legacy = ["ID", "CanonicalExecutable", "OldRequirement", "NewRequirement", "Alias", "Service", "Account", "ItemReferenceSHA256", "Binding"]
        return newCanonicalExecutable == nil ? legacy : legacy + ["NewCanonicalExecutable"]
    }
    public var description: String { "Frozen upgrade intent" }
    public var debugDescription: String { description }
    public init(worker: MigrationWorkerManifest, bootstrap: MigrationWorkerBootstrap, runtimeManifestSHA256: String) throws {
        guard MigrationAuthorizationRecord.digest(runtimeManifestSHA256), !bootstrap.reconciliation,
              bootstrap.value["workerRequirement"] as? String == worker.requirement else { throw MigrationUpgradeError.invalidPreparation }
        let keys = ["canonicalExecutable", "oldRequirement", "newRequirement", "alias", "service", "account"]
        var values = keys.compactMap { bootstrap.value[$0] as? String }
        guard values.count == keys.count else { throw MigrationUpgradeError.invalidPreparation }
        if let path = bootstrap.value["newCanonicalExecutable"] as? String { values += [path, Self.relocationDomain] }
        options = values; self.worker = worker; self.bootstrap = bootstrap; self.runtimeManifestSHA256 = runtimeManifestSHA256
        optionsSHA256 = try Self.arrayDigest(values)
        binding = try Self.arrayDigest(["mechanize-main-window-upgrade-v1", worker.executable.path, worker.requirement, worker.sha256,
            bootstrap.session, bootstrap.value["configSHA256"] as? String ?? "", runtimeManifestSHA256, optionsSHA256])
    }
    static func digest(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
    static func arrayDigest(_ values: [String]) throws -> String {
        // Reuse Go-compatible escaping; remove the known one-field wrapper.
        let wrapper = try MigrationWorkerSession.canonical(["v": values], order: ["v"])
        return digest(wrapper.dropFirst(5).dropLast())
    }
    func transitionBinding(id: String, itemSHA256: String) throws -> String {
        let names = transitionNames
        let values = [id] + Array(options.prefix(6)) + [itemSHA256, ""] + (newCanonicalExecutable.map { [$0] } ?? [])
        return Self.digest(try MigrationWorkerSession.canonical(Dictionary(uniqueKeysWithValues: zip(names, values)), order: names))
    }
}

/// Produced by independently trusted native preparation under its held placement
/// lease, before worker launch. No worker challenge can construct this record.
public final class MigrationUpgradePreparation: CustomStringConvertible, CustomDebugStringConvertible {
    public let intentBinding: String
    public let transitionID: String
    let itemReferenceSHA256: String
    let transitionBinding: String
    let validUntil: Date
    public var description: String { "Private prepared upgrade" }
    public var debugDescription: String { description }
    public init(intent: MigrationUpgradeIntent, itemReferenceSHA256: String, transitionID: String,
                transitionBinding: String, validUntil: Date) throws {
        guard MigrationAuthorizationRecord.digest(itemReferenceSHA256), MigrationAuthorizationRecord.digest(transitionID),
              transitionBinding == (try intent.transitionBinding(id: transitionID, itemSHA256: itemReferenceSHA256)),
              validUntil > Date(), validUntil.timeIntervalSinceNow <= 240 else { throw MigrationUpgradeError.invalidPreparation }
        intentBinding = intent.binding; self.itemReferenceSHA256 = itemReferenceSHA256; self.transitionID = transitionID
        self.transitionBinding = transitionBinding; self.validUntil = validUntil
    }
    func authorization(_ intent: MigrationUpgradeIntent) throws -> MigrationAuthorizationRecord {
        guard intent.binding == intentBinding, validUntil > Date() else { throw MigrationUpgradeError.invalidPreparation }
        let o = intent.options
        return try MigrationAuthorizationRecord(workerSession: intent.bootstrap.session, optionsSHA256: intent.optionsSHA256,
            helperRequirement: intent.worker.requirement, itemReferenceSHA256: itemReferenceSHA256, transitionID: transitionID,
            canonicalExecutable: o[0], oldRequirement: o[1], newRequirement: o[2], alias: o[3], service: o[4], account: o[5],
            transitionBinding: transitionBinding, validUntil: validUntil, newCanonicalExecutable: intent.newCanonicalExecutable)
    }
}

/// Preparation authenticates the frozen intent; final readiness observes the
/// installed runtime. The Go installer exclusively owns placement and journals.
public protocol MigrationUpgradePreparationProvider: AnyObject {
    func prepare(_ intent: MigrationUpgradeIntent) async throws -> MigrationNativePreparation
    func quiesce(_ preparation: MigrationNativePreparation) async throws
    @MainActor var lifecycleMayHaveChanged: Bool { get }
    func restartAndVerifyRuntime(_ preparation: MigrationNativePreparation, terminal: MigrationInstallerReply) async throws
    func cancel(_ preparation: MigrationNativePreparation?) async
}

extension MigrationUpgradePreparationProvider {
    public func quiesce(_ preparation: MigrationNativePreparation) async throws { throw MigrationUpgradeError.unavailable }
    @MainActor public var lifecycleMayHaveChanged: Bool { false }
}

@MainActor public final class MigrationUpgradeCoordinator: ObservableObject {
    @Published public private(set) var state: MigrationUpgradeState
    @Published public private(set) var isRunning = false
    @Published public private(set) var failureCode: String?
    public var canInspectRecovery: Bool { state == .recoveryRequired && worker?.canReconcile == true && !isRunning }
    private let backend: (any MigrationUpgradePreparationProvider)?
    private let launch: ((MigrationUpgradeIntent, MigrationNativePreparation) throws -> any MigrationInstallerSession)?
    private var consumed: Set<String> = []
    private var worker: (any MigrationInstallerSession)?
    private var prepared: MigrationNativePreparation?
    private var cancellationRequested = false
    private var executionAttempted = false

    public init(backend: (any MigrationUpgradePreparationProvider)? = nil, credentials: (any EnrollmentCredentialProvider)? = nil) {
        self.backend = backend
        if let credentials, backend != nil {
            launch = { intent, prepared in try NativeMigrationInstallerClient.launch(intent:intent, prepared:prepared, credentials:credentials) }
            state = .ready
        } else { launch = nil; state = .unavailable }
    }
    init(backend: any MigrationUpgradePreparationProvider, launch: @escaping (MigrationUpgradeIntent, MigrationNativePreparation) throws -> any MigrationInstallerSession) {
        self.backend = backend; self.launch = launch; state = .ready
    }
    deinit {
        if let retained = worker {
            let provider = backend; let preparation = prepared
            Task.detached { retained.cancel(); await provider?.cancel(preparation) }
        }
    }
    private func checkCancellation() throws {
        if cancellationRequested || Task.isCancelled { throw MigrationUpgradeError.cancelled }
        if let prepared, prepared.preparation.validUntil <= Date() { throw MigrationUpgradeError.recoveryRequired }
    }
    public func startApprovedUpgrade(_ approvedIntent: MigrationUpgradeIntent) async throws {
        guard !isRunning else { throw MigrationUpgradeError.busy }
        guard state != .recoveryRequired else { throw MigrationUpgradeError.recoveryRequired }
        guard let backend, let launch else { state = .unavailable; throw MigrationUpgradeError.unavailable }
        guard !consumed.contains(approvedIntent.binding) else { throw MigrationUpgradeError.consumedIntent }
        consumed.insert(approvedIntent.binding); prepared = nil; worker = nil
        failureCode = nil
        UserDefaults.standard.removeObject(forKey:"MechanizeRuntimeUpgradeFailureCode")
        cancellationRequested = false; executionAttempted = false; isRunning = true
        defer { isRunning = false }
        do {
            state = .preparing
            let preparation = try await backend.prepare(approvedIntent)
            guard preparation.preparation.intentBinding == approvedIntent.binding,
                  MigrationUpgradeIntent.digest(preparation.itemIdentity) == preparation.preparation.itemReferenceSHA256 else { throw MigrationUpgradeError.invalidPreparation }
            prepared = preparation
            try checkCancellation()
            try await backend.quiesce(preparation)
            executionAttempted = executionAttempted || backend.lifecycleMayHaveChanged
            try checkCancellation()
            state = .startingWorker
            let running = try await Task.detached(priority:.userInitiated) { try launch(approvedIntent, preparation) }.value
            worker = running
            try checkCancellation()
            state = .changingCustody
            let reply = try await Task.detached(priority:.userInitiated) { try running.execute() }.value
            executionAttempted = running.executionMayHaveDispatched
            guard reply.status == "verified" else { state = .recoveryRequired; return }
            guard reply.scope == "custody-broker-config", reply.transitionID == prepared?.preparation.transitionID,
                  reply.runtime == nil else { throw MigrationUpgradeError.recoveryRequired }
            try await finishVerifiedCustody()
        } catch {
            // Only a closed observer code may reach the UI. Backend errors can
            // contain private OS/resource details and must never be displayed.
            failureCode = (error as? MigrationObserverReadinessError)?.rawValue
            if let failureCode {
                UserDefaults.standard.set(failureCode,forKey:"MechanizeRuntimeUpgradeFailureCode")
            } else {
                UserDefaults.standard.removeObject(forKey:"MechanizeRuntimeUpgradeFailureCode")
            }
            await handleFailure()
            throw state == .recoveryRequired ? MigrationUpgradeError.recoveryRequired : (cancellationRequested ? MigrationUpgradeError.cancelled : MigrationUpgradeError.unavailable)
        }
    }
    private func finishVerifiedCustody() async throws {
        guard let backend, let prepared, let worker else { throw MigrationUpgradeError.unavailable }
        try checkCancellation()
        state = .placingConsole
        let receipt = try await Task.detached(priority:.userInitiated) { try worker.finalize() }.value
        guard receipt.status == "verified", receipt.scope == "runtime-artifacts",
              receipt.transitionID == prepared.preparation.transitionID, receipt.runtime != nil else { throw MigrationUpgradeError.recoveryRequired }
        executionAttempted = executionAttempted || worker.executionMayHaveDispatched
        self.worker = nil
        try checkCancellation()
        state = .placingArtifacts
        try await backend.restartAndVerifyRuntime(prepared, terminal:receipt)
        try checkCancellation()
        state = .complete
    }
    /// Only the retained exact session can reconcile; never relaunch or replay.
    public func inspectRecovery() async throws {
        guard !isRunning, state == .recoveryRequired, let worker, worker.canReconcile else { throw MigrationUpgradeError.recoveryRequired }
        isRunning = true; defer { isRunning = false }
        do {
            try checkCancellation()
            let reply = try await Task.detached(priority:.userInitiated) { try worker.reconcile() }.value
            guard reply.status == "verified" else { state = .recoveryRequired; return }
            guard reply.scope == "custody-broker-config", reply.transitionID == prepared?.preparation.transitionID,
                  reply.runtime == nil else { throw MigrationUpgradeError.recoveryRequired }
            try await finishVerifiedCustody()
        } catch { await handleFailure(); throw MigrationUpgradeError.recoveryRequired }
    }
    public func cancel() {
        guard isRunning || worker != nil else { return }
        cancellationRequested = true
        let retained = worker
        executionAttempted = executionAttempted || retained?.executionMayHaveDispatched == true || backend?.lifecycleMayHaveChanged == true
        worker = nil
        if let retained { Task.detached { retained.cancel() } }
        if !isRunning {
            state = executionAttempted ? .recoveryRequired : .cancelled
            let preparation = prepared
            Task { await backend?.cancel(preparation) }
        }
    }
    private func handleFailure() async {
        let retained = worker
        executionAttempted = executionAttempted || retained?.executionMayHaveDispatched == true || backend?.lifecycleMayHaveChanged == true
        if let retained { await Task.detached { retained.cancel() }.value }
        worker = nil
        await backend?.cancel(prepared)
        state = executionAttempted ? .recoveryRequired : (cancellationRequested || Task.isCancelled ? .cancelled : .failed)
    }
}
