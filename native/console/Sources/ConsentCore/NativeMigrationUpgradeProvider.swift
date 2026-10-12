import Foundation

/// Concrete main-window provider. The signed preparation reader owns metadata
/// collection; the single Go installer owns placement and launchd startup. The
/// probe independently checks the final process without reading credential bytes.
@MainActor public final class NativeMigrationUpgradeProvider: MigrationUpgradePreparationProvider,
    CustomStringConvertible, CustomDebugStringConvertible {
    nonisolated public var description: String { "Native runtime upgrade provider" }
    nonisolated public var debugDescription: String { description }
    private let binding: String
    private let intent: MigrationUpgradeIntent
    private let reader: NativeMigrationPreparationReader
    private let runtimeObserver: MigrationRuntimeObserverCollector?
    private let probe: MigrationRuntimeReadinessProbe
    private var preparationTask: Task<MigrationNativePreparation, Error>?
    private var retained: MigrationNativePreparation?
    private var attempted = false
    private var cancelled = false
    private var readinessAttempted = false
    private var brokerLifecycle: (any MigrationBrokerLifecycleRoute)?
    private var shutdown: MigrationRuntimeShutdown?
    private var shutdownAttempted = false
    public var lifecycleMayHaveChanged: Bool { shutdown?.mayHaveChanged == true }
    // The existing managed SIGTERM route is built from frozen readiness
    // metadata; no package or wire field can supply a cleanup-success claim.
    public func quiesce(_ preparation: MigrationNativePreparation) async throws {
        guard !cancelled, !shutdownAttempted, retained === preparation,
              preparation.preparation.intentBinding == binding, let runtimeObserver, let brokerLifecycle else {
            throw MigrationUpgradeError.unavailable
        }
        shutdownAttempted = true
        let stage = try runtimeObserver.makeShutdown(route: brokerLifecycle)
        shutdown = stage
        let originalBinding = binding
        try await Task.detached { try stage.quiesce(intentBinding: originalBinding, preparationDeadline: preparation.preparation.validUntil) }.value
        guard !cancelled, !Task.isCancelled else { throw MigrationUpgradeError.recoveryRequired }
    }

    public init(intent: MigrationUpgradeIntent, frozenPlan: Data,
                preparationWorker: MigrationWorkerManifest,
                credentials: any EnrollmentCredentialProvider, runtimeObserver: MigrationRuntimeObserverCollector? = nil) throws {
        let manifest = try MigrationRuntimeConsoleManifest(frozenPlan: frozenPlan, intent: intent)
        guard runtimeObserver == nil || runtimeObserver?.intentBinding == intent.binding else { throw MigrationUpgradeError.invalidPreparation }
        self.runtimeObserver = runtimeObserver
        if runtimeObserver != nil {
            brokerLifecycle = MigrationManagedBrokerShutdown(plan: try MigrationManagedShutdownPlan(intent: intent, frozenPlan: frozenPlan))
        }
        binding = intent.binding
        self.intent = intent
        reader = NativeMigrationPreparationReader(preparationWorker: preparationWorker, credentials: credentials)
        probe = MigrationRuntimeReadinessProbe(manifest: manifest)
    }

    public func prepare(_ intent: MigrationUpgradeIntent) async throws -> MigrationNativePreparation {
        guard !attempted, !cancelled, intent.binding == binding else { throw MigrationUpgradeError.invalidPreparation }
        attempted = true
        guard let runtimeObserver, brokerLifecycle != nil else { throw MigrationUpgradeError.unavailable }
        try await Task.detached { try runtimeObserver.capture() }.value
        guard !cancelled, !Task.isCancelled else { throw MigrationUpgradeError.cancelled }
        let reader = self.reader
        let task = Task { try await reader.prepare(intent) }
        preparationTask = task
        defer { preparationTask = nil }
        let result = try await task.value
        guard !cancelled, !Task.isCancelled, result.preparation.intentBinding == binding,
              result.preparation.validUntil > Date() else { throw MigrationUpgradeError.invalidPreparation }
        result.runtimeObserver = runtimeObserver
        retained = result
        return result
    }

    public func restartAndVerifyRuntime(_ preparation: MigrationNativePreparation,
                                        terminal: MigrationInstallerReply) async throws {
        guard !cancelled, !readinessAttempted, retained === preparation,
              preparation.preparation.intentBinding == binding,
              preparation.preparation.validUntil > Date(), terminal.status == "verified",
              terminal.scope == "runtime-artifacts",
              terminal.transitionID == preparation.preparation.transitionID,
              terminal.runtime != nil else { throw MigrationUpgradeError.recoveryRequired }
        readinessAttempted = true
        // The installer already started its exact preserved launchd job. Do not
        // issue a second kickstart, relaunch on timeout, or infer readiness from it.
        try await probe.verify(intent: intent, preparation: preparation, terminal: terminal)
        guard !cancelled, !Task.isCancelled else { throw MigrationUpgradeError.recoveryRequired }
    }

    public func cancel(_ preparation: MigrationNativePreparation?) async {
        if let preparation, retained !== preparation { return }
        cancelled = true
        shutdown?.cancel()
        preparationTask?.cancel()
        // Keep the original preparation and installer journals for recovery.
        // Cancellation never clears a durable unknown or replaces a Vault key.
    }
}
