import AppKit
import SwiftUI
import ConsentCore

/// Independent lifecycle connection owns protection. One-shot transaction
/// connections own mutations; no secret bytes travel in lifecycle messages.
@MainActor final class VaultRecordWindow: NSObject, NSWindowDelegate {
    enum Mode { case create, update, delete }
    private let request: VaultEntryRequest
    private let mode: Mode
    private let record: VaultRecordMetadata?
    private let lifecycle: SocketConsentBroker
    private let durableGuard: any VaultRecordGuardStore
    private let transaction: @Sendable () throws -> SocketConsentBroker
    private let completed: (VaultRecordState.Completion) -> Void
    private var window: NSWindow?
    private var entryID: String?
    private var guardGeneration: String?
    private var armed = false
    private var closing = false
    private var saving = false
    private var didComplete = false
    private var cleanupTask: Task<Void, Error>?
    private var expiryTask: Task<Void, Never>?
    // Retained by the controller so every close path clears fields synchronously.
    private let input = VaultRecordInput()
    var protected: Bool { armed && !closing && window != nil && request.isValid }

    init(mode: Mode, record: VaultRecordMetadata?, lifecycle: SocketConsentBroker,
         durableGuard: any VaultRecordGuardStore,
         transaction: @escaping @Sendable () throws -> SocketConsentBroker,
         completed: @escaping (VaultRecordState.Completion) -> Void) {
        self.mode = mode; self.record = record; self.lifecycle = lifecycle
        self.transaction = transaction; self.completed = completed; self.durableGuard = durableGuard
        request = VaultEntryRequest(id: UUID().uuidString, origin: "https://vault.mechanize.invalid",
            accountAlias: "account-" + UUID().uuidString.lowercased(), expiresAt: Date().addingTimeInterval(240))
    }
    func present() async throws {
        guard request.isValid, window == nil, entryID == nil,
              (mode == .create) == (record == nil) else { throw VaultInputError.expired }
        let client = lifecycle, target = request, storage = durableGuard
        // Readiness is read-only and cannot create a lease. Do not leave a
        // durable protection barrier behind when this preflight fails.
        do {
            try await Task.detached {
                try client.connectFromUserAction()
                guard try client.nativeRecordReady() else { throw VaultInputError.disconnected }
            }.value
        } catch { destroyFieldsAndWindow(); finish(.entryUnavailable); throw error }
        // Persist protection uncertainty before sending even Begin. A console
        // crash or lost Begin response must remain blocked after restart.
        do { guardGeneration = try await Task.detached { try storage.beginProtection() }.value }
        catch { destroyFieldsAndWindow(); finish(.guardUnavailable); throw error }
        do {
            let id = try await Task.detached {
                return try client.beginNativeVaultEntry(request: target)
            }.value
            entryID = id
            try Task.checkCancellation()
            let panel = NSWindow(contentRect: NSRect(origin: .zero, size: VaultRecordLayout.size(forDeletion: mode == .delete)),
                                 styleMask: [.titled, .closable], backing: .buffered, defer: false)
            panel.title = "Mechanize Secure Entry " + id
            panel.titleVisibility = .hidden; panel.sharingType = .none
            panel.isReleasedWhenClosed = false; panel.delegate = self
            VaultRecordLayout.install(Text("Preparing protected entry…").padding(24), in: panel, forDeletion: mode == .delete)
            window = panel; panel.center(); panel.makeKeyAndOrderFront(nil)
            await Task.yield()
            try await Task.detached { try client.confirmNativeVaultEntry(entryID: id) }.value
            try Task.checkCancellation()
            guard !closing, window === panel, request.isValid else { throw VaultInputError.expired }
            armed = true
            // Secret controls are constructed only after exact-window admission.
            VaultRecordLayout.install(VaultRecordForm(controller: self, input: input, mode: mode), in: panel, forDeletion: mode == .delete)
            expiryTask = Task { [weak self] in
                while !Task.isCancelled {
                    do { try await Task.sleep(for: .seconds(1)) } catch { return }
                    guard let self, !self.closing else { return }
                    if !self.request.isValid && !self.saving { await self.cancel(); return }
                }
            }
        } catch {
            destroyFieldsAndWindow()
            if entryID != nil {
                do { try await closeProtection(); finish(.entryUnavailable) }
                catch { finish(.entryStartFailed) }
            } else {
                // A lost Begin acknowledgement may leave a lease at the broker.
                finish(.entryStartFailed)
            }
            throw error
        }
    }
    func save(frame: VaultRecordFrame) async {
        guard mode != .delete, !saving, protected, let id = entryID, let generation = guardGeneration else { frame.destroy(); return }
        saving = true
        let make = transaction, target = request, replacing = record, storage = durableGuard
        do { try await Task.detached { try storage.beginMutation(generation: generation) }.value }
        catch {
            frame.destroy(); saving = false
            await end(confirmed: .guardUnavailable, cleanupFailed: .guardUnavailable); return
        }
        do {
            _ = try await Task.detached {
                defer { frame.destroy() }
                let client = try make(); try client.connectFromUserAction()
                let response = try client.submitNativeRecord(request: target, entryID: id, replacing: replacing, frame: frame)
                try storage.acknowledgeMutation(generation: generation)
                return response
            }.value
        } catch {
            saving = false; await end(confirmed: .operationUnconfirmed, cleanupFailed: .operationAndCleanupUnconfirmed); return
        }
        saving = false; await end(confirmed: .saved, cleanupFailed: .savedCleanupUnconfirmed)
    }
    func delete() async {
        guard mode == .delete, !saving, protected, let id = entryID, let generation = guardGeneration, let record else { return }
        saving = true
        let make = transaction, target = request, storage = durableGuard
        do { try await Task.detached { try storage.beginMutation(generation: generation) }.value }
        catch {
            saving = false; await end(confirmed: .guardUnavailable, cleanupFailed: .guardUnavailable); return
        }
        do {
            try await Task.detached {
                let client = try make(); try client.connectFromUserAction()
                try client.deleteNativeRecord(request: target, entryID: id, record: record)
                try storage.acknowledgeMutation(generation: generation)
            }.value
        } catch {
            saving = false; await end(confirmed: .operationUnconfirmed, cleanupFailed: .operationAndCleanupUnconfirmed); return
        }
        saving = false; await end(confirmed: .deleted, cleanupFailed: .deletedCleanupUnconfirmed)
    }
    func cancel() async {
        guard !saving, !closing else { return }
        await end(confirmed: .cancelled, cleanupFailed: .cleanupUnconfirmed)
    }
    func windowShouldClose(_ sender: NSWindow) -> Bool { !saving }
    func windowWillClose(_ notification: Notification) {
        guard !saving, !closing else { return }
        destroyFieldsAndWindow()
        Task {
            do { try await closeProtection(); finish(.cancelled) }
            catch { finish(.cleanupUnconfirmed) }
        }
    }
    private func end(confirmed: VaultRecordState.Completion, cleanupFailed: VaultRecordState.Completion) async {
        destroyFieldsAndWindow()
        do { try await closeProtection(); finish(confirmed) }
        catch { finish(cleanupFailed) }
    }
    private func finish(_ result: VaultRecordState.Completion) {
        guard !didComplete else { return }; didComplete = true; completed(result)
    }
    private func destroyFieldsAndWindow() {
        input.clear()
        expiryTask?.cancel(); expiryTask = nil; armed = false; closing = true
        let panel = window; window = nil
        panel?.contentView = nil; panel?.delegate = nil; panel?.close()
    }
    private func closeProtection() async throws {
        if let cleanupTask { return try await cleanupTask.value }
        guard let id = entryID, let generation = guardGeneration else { throw VaultNativeChannelError.protectionUnknown }
        let client = lifecycle, storage = durableGuard
        let task = Task<Void, Error> {
            await Task.yield()
            try await Task.detached {
                try client.closeNativeVaultEntry(entryID: id)
                try storage.acknowledgeProtection(generation: generation)
            }.value
        }
        cleanupTask = task; try await task.value
    }
}

enum VaultRecordSecretType: String, CaseIterable, Identifiable {
    // Mirrors viant/scy/cmd/option.go -t choices; certificate/x509 are aliases.
    case raw, basic, sha1, aws, ssh, generic, jwt, oauth2, key, certificate, x509
    var id:String {rawValue}
}

@MainActor enum VaultRecordLayout {
    static let viewportHeight:CGFloat = 280
    static func size(forDeletion:Bool)->NSSize {forDeletion ? NSSize(width:520,height:240) : NSSize(width:560,height:620)}
    static func install<Content:View>(_ content:Content,in panel:NSWindow,forDeletion:Bool) {
        let size=size(forDeletion:forDeletion),host=NSHostingView(rootView:content)
        // The preparation label must not shrink the window to its intrinsic size.
        host.sizingOptions=[];host.frame=NSRect(origin:.zero,size:size)
        host.autoresizingMask=[.width,.height];panel.contentView=host;panel.setContentSize(size)
    }
}

@MainActor final class VaultRecordInput: ObservableObject {
    @Published private(set) var type:VaultRecordSecretType = .raw
    @Published var key=""
    @Published var secret=""
    @Published var username=""
    @Published var password=""
    @Published var endpoint=""
    @Published var email=""
    @Published var keyName=""
    @Published var keySecret=""
    @Published var payload=""
    func selectType(_ next:VaultRecordSecretType) {guard next != type else{return};clear();type=next}
    func clear() {key="";secret="";username="";password="";endpoint="";email="";keyName="";keySecret="";payload=""}
    var complete:Bool {
        guard !key.isEmpty else{return false}
        switch type {case .raw:return !secret.isEmpty;case .basic:return !username.isEmpty && !password.isEmpty;case .key:return !keyName.isEmpty && !keySecret.isEmpty;default:return !payload.isEmpty}
    }
    func takeFrame() throws -> VaultRecordFrame {
        defer{clear()}
        guard complete else{throw VaultRecordFrameError.invalidInput}
        var pairs:[(String,String)]=[("$scy.type",type.rawValue)]
        switch type {
        case .raw:pairs.append(("secret",secret))
        case .basic:
            pairs += [("username",username),("password",password)]
            if !endpoint.isEmpty{pairs.append(("endpoint",endpoint))};if !email.isEmpty{pairs.append(("email",email))}
        case .key:pairs += [("Key",keyName),("Secret",keySecret)]
        default:
            guard payload.utf8.count<=60_000,let data=payload.data(using:.utf8),
                  let value=try? JSONSerialization.jsonObject(with:data),value is [String:Any] else{throw VaultRecordFrameError.invalidInput}
            pairs.append(("$scy.payload",payload))
        }
        var keyBytes=Data(key.utf8),values=pairs.map{(name:Data($0.0.utf8),value:Data($0.1.utf8))}
        return try VaultRecordFrame(key:&keyBytes,fields:&values)
    }
}

@MainActor struct VaultRecordFields:View {
    @ObservedObject var input:VaultRecordInput
    var body:some View {
        VStack(alignment:.leading,spacing:12) {
            Picker("Secret type",selection:Binding(get:{input.type},set:{input.selectType($0)})) {
                ForEach(VaultRecordSecretType.allCases){type in Text(type.rawValue).tag(type)}
            }.pickerStyle(.menu)
            ScrollView {
                VStack(alignment:.leading,spacing:14) {
                    secure("Record name",hint:"Name for this encrypted record",text:$input.key)
                    switch input.type {
                    case .raw:secure("Secret",hint:"Secret value",text:$input.secret)
                    case .basic:
                        secure("Username",hint:"Username",text:$input.username)
                        secure("Password",hint:"Password",text:$input.password)
                        secure("Endpoint (optional)",hint:"Endpoint",text:$input.endpoint)
                        secure("Email (optional)",hint:"Email",text:$input.email)
                    case .key:
                        secure("Key",hint:"Key name",text:$input.keyName)
                        secure("Secret",hint:"Secret value",text:$input.keySecret)
                    default:
                        secure("Structured payload",hint:"Paste a JSON object",text:$input.payload)
                        Text("Enter a JSON object for this Scy type. The payload stays masked.").font(.caption).foregroundStyle(.secondary)
                    }
                }.textFieldStyle(.roundedBorder).padding(.horizontal,2).padding(.vertical,4).frame(maxWidth:.infinity,alignment:.leading)
            }.frame(height:VaultRecordLayout.viewportHeight).id(input.type)
            Text("Changing the type clears all input. Names and values are encrypted; storing a record grants no website access.").font(.caption).foregroundStyle(.secondary)
        }
    }
    private func secure(_ label:String,hint:String,text:Binding<String>)->some View {
        VStack(alignment:.leading,spacing:4){Text(label).font(.caption);SecureField(hint,text:text).privacySensitive().accessibilityLabel(label+", secure entry")}
    }
}

@MainActor struct VaultRecordForm: View {
    let controller: VaultRecordWindow
    @ObservedObject var input: VaultRecordInput
    let mode: VaultRecordWindow.Mode
    @State private var busy = false
    @State private var message = ""
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(mode == .delete ? "Delete secret?" : mode == .update ? "Replace secret" : "Create secret").font(.title2)
            if mode == .delete {
                Text("The selected encrypted record will be permanently deleted.")
            } else {
                Text(mode == .update ? "Choose the Scy type and enter the complete replacement. Existing values are never revealed." : "Choose a Scy secret type and enter its values.")
                VaultRecordFields(input:input)
            }
            Text(message).font(.caption).foregroundStyle(.secondary).frame(height:44,alignment:.topLeading)
            HStack {
                Button("Cancel") { input.clear(); Task { await controller.cancel() } }.disabled(busy)
                if mode == .delete {
                    Button("Delete secret", role: .destructive) { busy = true; Task { await controller.delete() } }.disabled(busy || !controller.protected)
                } else {
                    Button("Encrypt and save") { save() }.disabled(busy || !controller.protected || !input.complete)
                }
            }
        }.padding(24).frame(maxWidth:.infinity,maxHeight:.infinity,alignment:.topLeading).disabled(busy)
            .onDisappear { input.clear() }
    }
    private func save() {
        guard !busy, controller.protected else { input.clear(); return }
        do {
            let frame = try input.takeFrame(); busy = true
            Task { await controller.save(frame: frame) }
        } catch {
            message = "Input cleared. Complete the required fields, use a record name up to 1,024 UTF-8 bytes, and keep the record under 64 KiB. Structured types require a JSON object."
        }
    }
}
