import SwiftUI
import ConsentCore

/// Deliberately unwired until the signed broker and secure-window capture
/// suppression are qualified. No reveal control exists without platform auth.
struct VaultSecureEntry: View {
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
            Text("This credential is used only for this exact site and account. Saving resumes the waiting workflow after the browser document is checked again.")
            SecureField("Username", text: $username)
                .privacySensitive().accessibilityLabel("Username, secure entry")
            SecureField("Password", text: $password)
                .privacySensitive().accessibilityLabel("Password, secure entry")
            if !adapter.secureCaptureSuppressionConfirmed {
                Text("Secure capture protection is unavailable. Credential entry is disabled.").foregroundStyle(.secondary)
            }
            if !status.isEmpty { Text(status).foregroundStyle(.secondary) }
            HStack {
                Button("Cancel") {
                    clearFields()
                    Task { try? await adapter.cancel(requestID: request.id) }
                }.disabled(submitting)
                Button("Encrypt, save and resume") { submit() }
                    .disabled(submitting || username.isEmpty || password.isEmpty || !request.isValid || !adapter.secureCaptureSuppressionConfirmed)
            }
        }
        .padding(24).frame(width: 460)
        .disabled(!adapter.secureCaptureSuppressionConfirmed)
        .onDisappear { clearFields() }
    }
    private func clearFields() { username = ""; password = "" }
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
            do { try await adapter.submit(request: request, username: userBytes, password: passwordBytes); status = "Credential saved. Workflow continuation requested." }
            catch { status = "Credential could not be saved or resumed. Check the local connection and site." }
        }
    }
}
