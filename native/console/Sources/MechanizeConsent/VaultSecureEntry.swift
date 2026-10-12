import SwiftUI
import AppKit
import ConsentCore

/// Mounted only after the native window coordinator obtains exact-window
/// confirmation. No reveal control exists without platform authorization.
@MainActor struct VaultSecureEntry: View {
    let request: VaultEntryRequest
    let adapter: any VaultSecureInputAdapter
    @State private var username = ""
    @State private var password = ""
    @State private var submitting = false
    @State private var status = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Save credential in Vault").font(.title2)
            Text(request.origin).font(.headline).textSelection(.enabled)
            Text("Account alias: \(request.accountAlias)")
            Text("This credential is encrypted locally for this exact site and account.")
            SecureField("Username", text: $username)
                .privacySensitive().accessibilityLabel("Username, secure entry")
                .disabled(submitting || !adapter.secureCaptureSuppressionConfirmed)
            Button("Paste username locally") { pasteLocally(usernameField: true) }.disabled(submitting || !adapter.secureCaptureSuppressionConfirmed)
            SecureField("Password", text: $password)
                .privacySensitive().accessibilityLabel("Password, secure entry")
                .disabled(submitting || !adapter.secureCaptureSuppressionConfirmed)
            Button("Paste password locally") { pasteLocally(usernameField: false) }.disabled(submitting || !adapter.secureCaptureSuppressionConfirmed)
            if !adapter.secureCaptureSuppressionConfirmed {
                Text("Secure capture protection is unavailable. Credential entry is disabled.").foregroundStyle(.secondary)
            }
            if !status.isEmpty { Text(status).foregroundStyle(.secondary) }
            HStack {
                Button("Cancel") {
                    clearFields()
                    Task { try? await adapter.cancel(requestID: request.id) }
                }.disabled(submitting)
                Button("Encrypt and save") { submit() }
                    .disabled(submitting || username.isEmpty || password.isEmpty || !request.isValid || !adapter.secureCaptureSuppressionConfirmed)
            }
        }
        .padding(24).frame(width: 460)
        .onChange(of: adapter.secureCaptureSuppressionConfirmed) { _, protected in
            if !protected { clearFields() }
        }
        .onDisappear { clearFields() }
    }
    private func clearFields() { username = ""; password = "" }
    private func pasteLocally(usernameField: Bool) {
        let result = VaultClipboard.importLocally(source: NativeVaultClipboard(),
            secureCaptureSuppressionConfirmed: adapter.secureCaptureSuppressionConfirmed,
            requestValid: request.isValid, submitting: submitting) { bytes in
                guard let text = String(data: bytes, encoding: .utf8) else { throw VaultInputError.expired }
                if usernameField { username = text } else { password = text }
            }
        status = result == .imported ? "Imported locally. Clipboard cleared if unchanged." : "Local clipboard import unavailable."
    }
    private func submit() {
        guard request.isValid, adapter.secureCaptureSuppressionConfirmed else { clearFields(); status = "Credential request is no longer available."; return }
        // Strings remain native UI state only. Swift/Cocoa may retain copies;
        // clearing fields limits lifetime but is not a secure-memory guarantee.
        var userBytes = Data(username.utf8)
        var passwordBytes = Data(password.utf8)
        clearFields(); submitting = true
        Task {
            defer {
                userBytes.resetBytes(in: 0..<userBytes.count)
                passwordBytes.resetBytes(in: 0..<passwordBytes.count)
                submitting = false
            }
            do { try await adapter.submit(request: request, username: userBytes, password: passwordBytes); status = "Credential saved." }
            catch { status = "Save could not be confirmed. Inspect Vault before another attempt." }
        }
    }
}

private struct NativeVaultClipboard: VaultClipboardSource {
    var changeCount: Int { NSPasteboard.general.changeCount }
    func readUTF8() -> Data? { NSPasteboard.general.string(forType: .string).map { Data($0.utf8) } }
    func clear(ifUnchanged revision: Int) {
        if NSPasteboard.general.changeCount == revision { NSPasteboard.general.clearContents() }
    }
}
