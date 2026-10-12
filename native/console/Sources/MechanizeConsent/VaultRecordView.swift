import SwiftUI
import ConsentCore

@MainActor final class VaultRecordsModel: ObservableObject {
    @Published var entries: [VaultRecordMetadata] = []
    @Published var state = VaultRecordState()
    @Published var message = "Refresh to check generic record availability."
    @Published var entryError: String?
    private var entry: VaultRecordWindow?
    private let factory: @Sendable () throws -> SocketConsentBroker
    private let durableGuard: any VaultRecordGuardStore
    init(factory: @escaping @Sendable () throws -> SocketConsentBroker = { try MechanizeConsentApp.nativeVaultBroker() },
         durableGuard: any VaultRecordGuardStore = VaultRecordGuard()) {
        self.factory = factory; self.durableGuard = durableGuard
        state.busy = true
        Task {
            do {
                let status = try await Task.detached { try durableGuard.status() }.value
                state.restoreGuard(status)
                if status.mutation { message = "The previous operation remains unconfirmed. Further changes are blocked." }
                else if status.protection { message = "Recover protection to confirm cleanup." }
            } catch {
                state.guardFailed(); message = "The durable safety guard is unavailable. Further changes are blocked."
            }
            state.busy = false
        }
    }
    func refresh() async {
        guard !state.busy, !state.entryOpen else { return }
        state.busy = true; defer { state.busy = false }
        let make = factory
        do {
            let result = try await Task.detached {
                let client = try make(); try client.connectFromUserAction()
                let ready = try client.nativeRecordReady()
                return (ready, ready ? try client.nativeRecordInventory() : [])
            }.value
            entries = result.1; state.refreshed(ready: result.0)
            message = state.guardUnavailable ? "The durable safety guard is unavailable. Further changes are blocked." : state.cleanupRequired ? "Recover protection to confirm cleanup." : state.outcomeUnconfirmed ? "The previous operation remains unconfirmed. Further changes are blocked; refreshing does not establish its outcome." : (result.0 ? "Keys and named fields stay encrypted. Only opaque record references appear here." : "Generic records are unavailable. Set up the local Vault key or update the runtime.")
        } catch {
            state.keyReady = nil; entries = []
            message = "Generic records need an updated runtime. Connect or update the signed Mechanize installation."
        }
    }
    func recover() async {
        guard !state.busy, !state.entryOpen else { return }
        state.busy = true
        let make = factory, storage = durableGuard
        do {
            try await Task.detached {
                let observed = try storage.status()
                let client = try make(); try client.connectFromUserAction(); try client.recoverNativeVaultEntry()
                if observed.protection, let generation = observed.generation {
                    try storage.acknowledgeProtection(generation: generation)
                }
            }.value
            state.recovered(); state.busy = false
            // Recovery confirms protection only. Keep an unknown mutation blocked
            // until operation-specific reconciliation establishes the outcome.
            message = state.outcomeUnconfirmed ? "Protection recovered. The previous operation remains unconfirmed; further changes are blocked." : "Protection recovered. Refresh records to check readiness."
        } catch {
            state.busy = false; state.recoveryFailed()
            message = "Protection recovery could not be confirmed. Observation remains blocked until the broker verifies cleanup."
        }
    }
    func open(_ mode: VaultRecordWindow.Mode, record: VaultRecordMetadata? = nil) async {
        guard state.beginEntry() else { return }
        entryError = nil; message = "Preparing secure entry…"
        do {
            let make = factory
            let lifecycle = try await Task.detached { try make() }.value
            let panel = VaultRecordWindow(mode: mode, record: record, lifecycle: lifecycle, durableGuard: durableGuard, transaction: factory) { [weak self] result in self?.finished(result) }
            entry = panel; try await panel.present()
        } catch {
            // present reports its own terminal state once. A factory failure
            // before presentation has no lease but still needs fresh readiness.
            if state.entryOpen {
                entry = nil; state.finish(.cancelled); state.keyReady = nil
                message = "Secure entry could not start. Refresh records to check Vault readiness."
                entryError = message
            }
        }
    }
    private func finished(_ result: VaultRecordState.Completion) {
        entry = nil; state.finish(result)
        switch result {
        case .entryUnavailable:
            message = "Secure entry could not open. Refresh records to check Vault readiness."
            entryError = message
        case .entryStartFailed:
            message = "Secure entry could not open because its protection could not be confirmed. Check Mechanize Accessibility access, then choose Recover protection."
            entryError = message
        case .saved: message = "Secret saved."; refreshAfterAcknowledgement()
        case .deleted: message = "Secret deleted."; refreshAfterAcknowledgement()
        case .cancelled: message = "Secure entry closed."
        case .guardUnavailable: message = "Secure entry could not open because its local protection state is unavailable. Further changes are blocked."; entryError = message
        case .operationUnconfirmed: message = "Operation could not be confirmed. Further changes are blocked. No input was replayed."
        case .cleanupUnconfirmed: message = "Secure entry is closed locally. Recover protection to confirm cleanup."
        case .savedCleanupUnconfirmed: message = "Secret saved. Recover protection to confirm cleanup."
        case .deletedCleanupUnconfirmed: message = "Secret deleted. Recover protection to confirm cleanup."
        case .operationAndCleanupUnconfirmed: message = "Operation and cleanup could not be confirmed. Recover protection; further changes remain blocked."
        }
    }
    private func refreshAfterAcknowledgement() {
        Task { let outcome = message; await refresh(); if state.keyReady == true && !state.cleanupRequired { message = outcome } }
    }
}

@MainActor struct VaultRecordsSection: View {
    @ObservedObject var model: VaultRecordsModel
    let openPermissions: () -> Void
    // Closures read the other model at action time, including two queued clicks.
    let otherBusy: () -> Bool
    let otherCleanup: () -> Bool
    private var canEdit: Bool { model.state.canEdit && !otherBusy() && !otherCleanup() }
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Divider()
            HStack {
                Label("Generic secrets", systemImage: "lock.doc").font(.title2.bold())
                Spacer()
                Button("Create secret", systemImage: "plus") {
                    Task { guard !otherBusy(), !otherCleanup() else { return }; await model.open(.create) }
                }.disabled(!canEdit).accessibilityIdentifier("mechanize.vault.records.create")
            }
            Text(model.message).foregroundStyle(.secondary)
            HStack {
                Button("Refresh records") {
                    Task { guard !otherBusy() else { return }; await model.refresh() }
                }.disabled(model.state.busy || model.state.entryOpen || otherBusy())
                    .accessibilityIdentifier("mechanize.vault.records.refresh")
                if model.state.cleanupRequired {
                    Button("Recover protection") {
                        Task { guard !otherBusy() else { return }; await model.recover() }
                    }.disabled(model.state.busy || model.state.entryOpen || otherBusy())
                        .accessibilityIdentifier("mechanize.vault.records.recover")
                }
                if model.state.busy || model.state.entryOpen { ProgressView().controlSize(.small) }
            }
            if model.state.cleanupRequired { Button("Go to Permissions", action: openPermissions) }
            if model.state.keyReady == true && model.entries.isEmpty { Text("No generic secrets saved.").foregroundStyle(.secondary) }
            ForEach(model.entries, id: \.id) { row in
                VStack(alignment: .leading, spacing: 8) {
                    Text("Reference: " + row.id).font(.caption).textSelection(.enabled)
                    HStack {
                        Button("Replace") {
                            Task { guard !otherBusy(), !otherCleanup() else { return }; await model.open(.update, record: row) }
                        }.disabled(!canEdit)
                        Button("Delete", role: .destructive) {
                            Task { guard !otherBusy(), !otherCleanup() else { return }; await model.open(.delete, record: row) }
                        }.disabled(!canEdit)
                    }
                }.padding(14).frame(maxWidth: .infinity, alignment: .leading)
                    .background(.background, in: RoundedRectangle(cornerRadius: 10))
            }
            Text("Secret keys and field names are entered only in the protected native window. Replacing a record requires its complete contents.")
                .font(.caption).foregroundStyle(.secondary)
        }
        .alert("Unable to open secure entry", isPresented: Binding(
            get: { model.entryError != nil },
            set: { if !$0 { model.entryError = nil } }
        )) {
            Button("OK", role: .cancel) { model.entryError = nil }
        } message: {
            Text(model.entryError ?? "Secure entry is unavailable.")
        }
    }
}
