import AppKit
import SwiftUI
import ConsentCore

/// Owns a dedicated native window. The lifecycle connection is independent of
/// each one-shot binary transaction. All broker calls run off the main thread:
/// blocking that thread would prevent the independent AX verifier responding.
/// This controller is not exposed as MCP and is awaiting installed qualification.
@MainActor final class VaultEntryWindow: NSObject, NSWindowDelegate, VaultSecureInputAdapter {
    enum Completion {
        case saved(String), imported(VaultRecordMetadata), importedCleanupUnconfirmed(VaultRecordMetadata), deleted, cancelled, saveUnconfirmed, cleanupUnconfirmed
        case savedCleanupUnconfirmed(String), deletedCleanupUnconfirmed, saveAndCleanupUnconfirmed
    }
    private var request: VaultEntryRequest
    private let mode: Mode
    enum Mode { case create, modify, delete, importCredential }
    private let revision: String?
    private let sourceReference: String?
    private let lifecycle: SocketConsentBroker
    private let transaction: @Sendable () throws -> SocketConsentBroker
    private let completed: (Completion) -> Void
    private var window: NSWindow?
    private var entryID: String?
    private var armed = false
    private var closing = false
    private var saving = false
    private var cleanupTask: Task<Void, Error>?
    private var expiryTask: Task<Void, Never>?
    var secureCaptureSuppressionConfirmed: Bool { armed && !closing && window != nil }

    init(request: VaultEntryRequest, mode: Mode = .modify, revision: String? = nil, sourceReference: String? = nil, lifecycle: SocketConsentBroker,
         transaction: @escaping @Sendable () throws -> SocketConsentBroker,
         completed: @escaping (Completion) -> Void) {
        self.request = request; self.mode = mode; self.revision = revision; self.sourceReference = sourceReference; self.lifecycle = lifecycle
        self.transaction = transaction; self.completed = completed
    }
    func present() async throws {
        guard request.isValid, window == nil, entryID == nil else { throw VaultInputError.expired }
        let client = lifecycle, target = request
        let id = try await Task.detached {
            try client.connectFromUserAction()
            guard try client.nativeVaultKeyReady() else { throw VaultInputError.disconnected }
            return try client.beginNativeVaultEntry(request: target)
        }.value
        entryID = id
        do {
            try Task.checkCancellation()
            let panel = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 480, height: 400),
                                 styleMask: [.titled, .closable], backing: .buffered, defer: false)
            // Fixed public marker only: never place website/account/credentials
            // in the native window title. The opaque marker is hidden visually.
            panel.title = "Mechanize Secure Entry " + id
            panel.titleVisibility = .hidden
            panel.isReleasedWhenClosed = false
            panel.sharingType = .none // Additional layer; the broker gate is mandatory.
            panel.delegate = self
            panel.contentView = NSHostingView(rootView: Text("Preparing protected entry…").padding(24))
            window = panel; panel.center(); panel.makeKeyAndOrderFront(nil)
            await Task.yield()
            try await Task.detached { try client.confirmNativeVaultEntry(entryID: id) }.value
            try Task.checkCancellation()
            guard !closing, window === panel, request.isValid else { throw VaultInputError.expired }
            armed = true
            expiryTask = Task { [weak self] in
                while !Task.isCancelled {
                    do { try await Task.sleep(for: .seconds(1)) } catch { return }
                    guard let self, !self.closing else { return }
                    // An admitted one-shot save owns its bounded transaction;
                    // never interrupt it into a replayable or false-clean state.
                    if !self.request.isValid && !self.saving {
                        self.destroyFieldsAndWindow()
                        do { try await self.closeProtection(); self.completed(.cancelled) }
                        catch { self.completed(.cleanupUnconfirmed) }
                        return
                    }
                }
            }
            switch mode {
            case .create:
                panel.contentView = NSHostingView(rootView: VaultOriginEntry(controller: self))
            case .modify:
                panel.contentView = NSHostingView(rootView: VaultSecureEntry(request: request, adapter: self))
            case .importCredential:
                panel.contentView = NSHostingView(rootView: VaultImportEntry(controller: self))
            case .delete:
                panel.contentView = NSHostingView(rootView: VaultDeleteEntry(request: request, controller: self))
            }
        } catch {
            destroyFieldsAndWindow()
            do { try await closeProtection() } catch { completed(.cleanupUnconfirmed) }
            throw error
        }
    }
    func bind(origin: String) async throws {
        guard mode == .create, !saving, secureCaptureSuppressionConfirmed, let id = entryID,
              let canonical = VaultOrigin.canonical(origin), request.isValid else { throw VaultInputError.expired }
        saving = true
        let client = lifecycle
        do {
            try await Task.detached { try client.bindNativeVaultEntry(entryID: id, origin: canonical) }.value
            guard !closing, let panel = window else { throw VaultInputError.expired }
            request = VaultEntryRequest(id: request.id, origin: canonical, accountAlias: request.accountAlias, expiresAt: request.expiresAt)
            saving = false
            panel.contentView = NSHostingView(rootView: VaultSecureEntry(request: request, adapter: self))
        } catch {
            saving = false; destroyFieldsAndWindow()
            do { try await closeProtection(); completed(.cancelled) }
            catch { completed(.cleanupUnconfirmed) }
            throw VaultNativeChannelError.protectionUnknown
        }
    }
    func cancelCurrent() async { try? await cancel(requestID: request.id) }
    func delete() async {
        guard mode == .delete, !saving, request.isValid, secureCaptureSuppressionConfirmed,
              let id = entryID, let revision else { return }
        saving = true
        let factory = transaction, target = request
        do {
            try await Task.detached {
                let client = try factory(); try client.connectFromUserAction()
                try client.deleteNativeVault(request: target, entryID: id, revision: revision)
            }.value
        } catch {
            saving = false; destroyFieldsAndWindow()
            do { try await closeProtection(); completed(.saveUnconfirmed) }
            catch { completed(.saveAndCleanupUnconfirmed) }
            return
        }
        saving = false; destroyFieldsAndWindow()
        do { try await closeProtection(); completed(.deleted) }
        catch { completed(.deletedCleanupUnconfirmed) }
    }
    func importCredential(inspect: Bool) async {
        guard mode == .importCredential, !saving, request.isValid, secureCaptureSuppressionConfirmed,
              let id=entryID, let revision, let sourceReference else { return }
        saving=true
        let factory=transaction, target=request
        let result:VaultRecordMetadata
        do {
            result=try await Task.detached {
                let client=try factory();try client.connectFromUserAction()
                return try client.importNativeVaultCredential(request:target,entryID:id,resourceURL:sourceReference,revision:revision,inspect:inspect)
            }.value
        } catch {
            saving=false;destroyFieldsAndWindow()
            do {try await closeProtection();completed(.saveUnconfirmed)}
            catch {completed(.saveAndCleanupUnconfirmed)}
            return
        }
        saving=false;destroyFieldsAndWindow()
        do {try await closeProtection();completed(.imported(result))}
        catch {completed(.importedCleanupUnconfirmed(result))}
    }
    func windowShouldClose(_ sender: NSWindow) -> Bool { !saving }
    func windowWillClose(_ notification: Notification) {
        destroyFieldsAndWindow()
        Task {
            do { try await closeProtection(); completed(.cancelled) }
            catch { completed(.cleanupUnconfirmed) }
        }
    }
    func submit(request submitted: VaultEntryRequest, username: Data, password: Data) async throws {
        guard (mode == .create || mode == .modify), submitted == request, request.isValid, secureCaptureSuppressionConfirmed,
              !saving, let id = entryID else { throw VaultInputError.expired }
        saving = true
        let factory = transaction, target = request, expectedRevision = revision
        let reference: String
        do {
            reference = try await Task.detached {
                let client = try factory()
                try client.connectFromUserAction()
                return try client.submitNativeVault(request: target, entryID: id, revision: expectedRevision,
                                                    username: username, password: password)
            }.value
        } catch {
            saving = false; destroyFieldsAndWindow()
            do { try await closeProtection(); completed(.saveUnconfirmed) }
            catch { completed(.saveAndCleanupUnconfirmed) }
            // Window is removed, so the view cannot offer a secret-input replay.
            throw VaultNativeChannelError.outcomeUnknown
        }
        saving = false; destroyFieldsAndWindow()
        do { try await closeProtection(); completed(.saved(reference)) }
        catch { completed(.savedCleanupUnconfirmed(reference)); throw VaultNativeChannelError.protectionUnknown }
    }
    func cancel(requestID: String) async throws {
        guard requestID == request.id, !saving else { throw VaultInputError.expired }
        destroyFieldsAndWindow()
        do { try await closeProtection(); completed(.cancelled) }
        catch { completed(.cleanupUnconfirmed); throw VaultNativeChannelError.protectionUnknown }
    }
    private func destroyFieldsAndWindow() {
        expiryTask?.cancel(); expiryTask = nil
        armed = false; closing = true
        // Detach the hosting view before closure/cleanup RPC. Native Swift/Cocoa
        // memory copies are not claimed to be securely erased by this operation.
        let panel = window; window = nil
        panel?.contentView = nil; panel?.delegate = nil; panel?.close()
    }
    private func closeProtection() async throws {
        if let cleanupTask { return try await cleanupTask.value }
        guard let id = entryID else { throw VaultNativeChannelError.protectionUnknown }
        let client = lifecycle
        let cleanup = Task<Void, Error> {
            await Task.yield()
            try await Task.detached { try client.closeNativeVaultEntry(entryID: id) }.value
        }
        cleanupTask = cleanup
        try await cleanup.value
    }
}

/// Website metadata is itself collected inside the protected boundary so pasted
/// URL userinfo can never be exposed to observation before local rejection.
@MainActor private struct VaultOriginEntry: View {
    let controller: VaultEntryWindow
    @State private var origin = ""
    @State private var busy = false
    @State private var message = ""
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Choose website").font(.title2)
            Text("Enter the HTTPS website origin, such as https://example.com. The account reference is generated automatically.")
            SecureField("HTTPS website origin", text: $origin).privacySensitive()
            if !message.isEmpty { Text(message).foregroundStyle(.secondary) }
            HStack {
                Button("Cancel") { origin = ""; Task { await controller.cancelCurrent() } }.disabled(busy)
                Button("Continue") {
                    guard let value = VaultOrigin.canonical(origin) else {
                        origin = ""; message = "Enter an HTTPS origin without an account, password, path, query, or fragment."; return
                    }
                    origin = ""; busy = true
                    Task { try? await controller.bind(origin: value); busy = false }
                }.disabled(busy || origin.isEmpty)
            }
        }.padding(24).frame(width: 460).onDisappear { origin = "" }
    }
}
@MainActor private struct VaultDeleteEntry: View {
    let request: VaultEntryRequest
    let controller: VaultEntryWindow
    @State private var busy = false
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Delete credential?").font(.title2)
            Text(request.origin).font(.headline)
            Text("Reference: " + request.accountAlias).font(.caption)
            Text("The saved credential for this reference will be permanently removed.")
            HStack {
                Button("Cancel") { Task { await controller.cancelCurrent() } }.disabled(busy)
                Button("Delete credential", role: .destructive) { busy = true; Task { await controller.delete() } }.disabled(busy)
            }
        }.padding(24).frame(width: 460)
    }
}

@MainActor private struct VaultImportEntry: View {
    let controller: VaultEntryWindow
    @State private var busy=false
    var body: some View {
        VStack(alignment:.leading,spacing:16) {
            Text("Import selected credential").font(.title2)
            Text("Copy this exact saved revision into a generic record for private sign-in. The original stays unchanged. Values remain inside the encrypted Vault service and are never shown here.")
            Text("If a previous result was uncertain, inspect it first. A reserved import is never copied again automatically.").font(.caption)
            HStack {
                Button("Cancel") {Task {await controller.cancelCurrent()}}.disabled(busy)
                Button("Inspect prior import") {busy=true;Task {await controller.importCredential(inspect:true)}}.disabled(busy)
                Button("Import selected") {busy=true;Task {await controller.importCredential(inspect:false)}}.disabled(busy)
            }
        }.padding(24).frame(width:460)
    }
}
