import SwiftUI
import ConsentCore

@MainActor final class VaultModel: ObservableObject {
    @Published var entries: [VaultInventoryEntry] = []
    @Published var keyReady: Bool?
    @Published var busy = false
    @Published var message = "Connect to inspect Vault readiness."
    @Published var entryOpen = false
    @Published var cleanupRequired = false
    @Published var importedID: String?
    private var entry: VaultEntryWindow?
    private let factory: @Sendable () throws -> SocketConsentBroker
    init(factory: @escaping @Sendable () throws -> SocketConsentBroker = { try MechanizeConsentApp.nativeVaultBroker() }) { self.factory = factory }
    var canEdit: Bool { keyReady == true && !busy && !entryOpen && !cleanupRequired }
    func refresh() async {
        guard !busy, !entryOpen else { return }
        busy = true; defer { busy = false }
        let make = factory
        do {
            let result = try await Task.detached {
                let client = try make(); try client.connectFromUserAction()
                let ready = try client.nativeVaultKeyReady()
                return (ready, ready ? try client.nativeVaultInventory() : [])
            }.value
            keyReady = result.0; entries = result.1
            message = cleanupRequired ? "Protection cleanup needs confirmation. Close secure entry windows, then recover protection." : (result.0 ? "Vault key is ready. Entry protection is checked before each operation." : "Set up the local encryption key to begin.")
        } catch {
            keyReady = nil; entries = []
            message = "Vault is unavailable. Connect or update the signed Mechanize installation and enable its native Vault service."
        }
    }
    func setup() async {
        guard !busy, !entryOpen, keyReady == false, !cleanupRequired else { return }
        busy = true
        let make = factory
        do {
            try await Task.detached { let client = try make(); try client.connectFromUserAction(); try client.setupNativeVaultKey() }.value
            busy = false; await refresh()
        } catch {
            busy = false; keyReady = nil
            message = "Key setup could not be confirmed. Refresh readiness before another setup attempt."
        }
    }
    func recover() async {
        guard !busy, !entryOpen else { return }
        busy = true; let make = factory
        do {
            try await Task.detached { let client = try make(); try client.connectFromUserAction(); try client.recoverNativeVaultEntry() }.value
            cleanupRequired = false; busy = false; await refresh()
        } catch {
            busy = false; cleanupRequired = true
            message = "Protection recovery could not be confirmed. Observation remains blocked until the broker verifies cleanup."
        }
    }
    func open(_ mode: VaultEntryWindow.Mode, existing: VaultInventoryEntry? = nil) async {
        guard canEdit else { return }
        entryOpen = true
        let request = existing?.request() ?? VaultEntryRequest(id: UUID().uuidString,
            origin: "https://vault.mechanize.invalid", accountAlias: "account-" + UUID().uuidString.lowercased(),
            expiresAt: Date().addingTimeInterval(240))
        do {
            let panel = VaultEntryWindow(request: request, mode: mode, revision: existing?.revision, sourceReference: existing?.resourceURL,
                lifecycle: try factory(), transaction: factory) { [weak self] result in self?.finished(result) }
            entry = panel
            try await panel.present()
        } catch {
            entry = nil; entryOpen = false; cleanupRequired = true
            message = "Secure entry could not start. Check Accessibility in Permissions, close any secure entry windows, then choose Recover protection."
        }
    }
    private func finished(_ result: VaultEntryWindow.Completion) {
        entry = nil; entryOpen = false
        switch result {
        case .saved:
            message = "Credential saved."; reloadAfterCompletion()
        case .imported(let record):
            importedID=record.id;message="Credential imported. Original retained. Select the new generic record when approving private sign-in.";reloadAfterCompletion()
        case .importedCleanupUnconfirmed(let record):
            importedID=record.id;cleanupRequired=true;message="Credential imported; original retained. Recover protection before continuing."
        case .deleted:
            message = "Credential deleted."; reloadAfterCompletion()
        case .cancelled: message = "Secure entry closed."
        case .saveUnconfirmed:
            keyReady = nil; message = "Operation could not be confirmed. Refresh Vault and inspect its inventory before another attempt."
        case .cleanupUnconfirmed:
            cleanupRequired = true; message = "Entry closed locally. Recover protection to confirm cleanup."
        case .savedCleanupUnconfirmed:
            cleanupRequired = true; message = "Credential saved. Recover protection to confirm cleanup."
        case .deletedCleanupUnconfirmed:
            cleanupRequired = true; message = "Credential deleted. Recover protection to confirm cleanup."
        case .saveAndCleanupUnconfirmed:
            cleanupRequired = true; keyReady = nil
            message = "Operation and cleanup could not be confirmed. Recover protection, then inspect Vault before another attempt."
        }
    }
    private func reloadAfterCompletion() {
        Task { let outcome = message; await refresh(); if keyReady == true && !cleanupRequired { message = outcome } }
    }
}

struct VaultTab: View {
    let openPermissions: () -> Void
    @StateObject private var model = VaultModel()
    @StateObject private var records = VaultRecordsModel()
    private var recordsBusy: Bool { records.state.busy || records.state.entryOpen }
    private var recordsBlocked: Bool { records.state.blocksOtherEntry }
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                HStack {
                    Label("Credentials", systemImage: "key.horizontal").font(.title2.bold())
                    Spacer()
                    Button("Create credential", systemImage: "plus") { Task { guard !recordsBlocked else { return }; await model.open(.create) } }
                        .accessibilityIdentifier("mechanize.vault.create").disabled(!model.canEdit || recordsBlocked)
                }
                VStack(alignment: .leading, spacing: 12) {
                    Label(model.keyReady == true ? "Local encryption key ready" : "Vault setup", systemImage: "lock.shield").font(.headline)
                    Text(model.message).foregroundStyle(.secondary)
                    HStack {
                        Button("Refresh Vault") { Task { guard !recordsBusy else { return }; await model.refresh() } }.disabled(model.busy || model.entryOpen || recordsBusy)
                            .accessibilityIdentifier("mechanize.vault.refresh")
                        if model.keyReady == false {
                            Button("Set up or repair Vault") { Task { guard !recordsBlocked else { return }; await model.setup() } }.disabled(model.busy || model.entryOpen || model.cleanupRequired || recordsBlocked)
                                .accessibilityIdentifier("mechanize.vault.setup")
                                .help("Create a local encryption key, or repair access to the existing key without replacing it.")
                        }
                        Button("Recover protection") { Task { guard !recordsBusy else { return }; await model.recover() } }.disabled(model.busy || model.entryOpen || recordsBusy)
                            .accessibilityIdentifier("mechanize.vault.recover")
                            .help("Close any secure entry windows first. The broker independently verifies cleanup.")
                        if model.busy || model.entryOpen { ProgressView().controlSize(.small) }
                    }
                }.padding(16).frame(maxWidth: .infinity, alignment: .leading)
                    .background(.background, in: RoundedRectangle(cornerRadius: 10))
                if model.cleanupRequired { Button("Go to Permissions", action: openPermissions) }
                if model.keyReady == true && model.entries.isEmpty { Text("No saved credentials.").foregroundStyle(.secondary) }
                ForEach(model.entries) { row in
                    VStack(alignment: .leading, spacing: 8) {
                        Text(row.origin).font(.headline)
                        Text("Reference: " + row.accountAlias).font(.caption).foregroundStyle(.secondary)
                        Text(row.resourceURL).font(.caption2).textSelection(.enabled).lineLimit(2)
                        HStack {
                            Button("Import for private sign-in") { Task { guard !recordsBlocked else { return }; await model.open(.importCredential, existing:row) } }.disabled(!model.canEdit || recordsBlocked)
                            Button("Modify") { Task { guard !recordsBlocked else { return }; await model.open(.modify, existing: row) } }.disabled(!model.canEdit || recordsBlocked)
                            Button("Delete", role: .destructive) { Task { guard !recordsBlocked else { return }; await model.open(.delete, existing: row) } }.disabled(!model.canEdit || recordsBlocked)
                        }
                    }.padding(14).frame(maxWidth: .infinity, alignment: .leading)
                        .background(.background, in: RoundedRectangle(cornerRadius: 10))
                }
                Text("Credential values stay in native secure entry. Vault lists only websites and opaque references.")
                    .font(.caption).foregroundStyle(.secondary)
                VaultRecordsSection(model: records, openPermissions: openPermissions, otherBusy: { model.busy || model.entryOpen }, otherCleanup: { model.cleanupRequired })
            }.padding(.vertical, 16)
        }.task { await model.refresh() }.onChange(of:model.importedID) { _,_ in Task {await records.refresh()} }
    }
}
