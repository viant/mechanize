import SwiftUI
import ConsentCore

@MainActor final class BrowserControllersModel: ObservableObject {
    @Published var state: BrowserControllerState?
    @Published var enabled = false
    @Published var origins = BrowserControllerPolicy.suggestedOrigins.joined(separator: "\n")
    @Published var busy = false
    @Published var message = "Load controller access to review this browser connection."
    var policy: BrowserControllerPolicy {
        BrowserControllerPolicy(enabled: enabled, origins: origins.split(whereSeparator: \.isNewline).map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty })
    }
    func perform(_ action: BrowserControllerAction, broker: SocketConsentBroker?, profile: String, browser: String, session: String? = nil) async {
        guard !busy, let broker else { message = "Connect to the local broker first."; return }
        busy = true; defer { busy = false }
        do {
            let reply = try await broker.manageBrowserControllers(profileChannel: profile, browserInstance: browser, action: action, policy: action == .configure ? policy : nil, controllerSessionID: session)
            state = reply; enabled = reply.policy.enabled
            origins = (reply.policy.origins.isEmpty && action == .status ? BrowserControllerPolicy.suggestedOrigins : reply.policy.origins).joined(separator: "\n")
            message = reply.connected ? "Controller access loaded." : "Browser disconnected. Trusted-origin connections resume after reconnect."
        } catch { state = nil; message = "Controller access unavailable. Refresh to inspect current access before making another change." }
    }
}

struct BrowserControllersView: View {
    let broker: SocketConsentBroker?
    let profile: String
    let browser: String
    @StateObject private var model = BrowserControllersModel()
    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Divider()
            Text("Trusted controller websites").font(.headline)
            Text("These websites may request control through Mechanize. Target website access above is a separate permission.").font(.caption).foregroundStyle(.secondary)
            Toggle("Enable trusted connections", isOn: $model.enabled)
            Text("Trusted origins · one per line").font(.caption)
            TextEditor(text: $model.origins).font(.system(.body, design: .monospaced)).frame(height: 64).border(Color.secondary.opacity(0.3))
            Text("Use an exact HTTPS or HTTP loopback origin without a path. localhost:* trusts only localhost on any HTTP/HTTPS port; scheme-specific localhost patterns are also supported. Enabled trusted origins connect and automate within your allowed applications and websites without another Mechanize approval. Changing this list revokes existing sessions. Trust survives broker restarts; macOS permissions, client tool policies and credential protections still apply.").font(.caption).foregroundStyle(.secondary)
            HStack {
                Button("Save trusted origins") { perform(.configure) }.disabled(model.state == nil || !model.policy.isValid)
                Button("Refresh connections") { perform(.status) }
            }
            Text(model.message).font(.caption).foregroundStyle(.secondary)
            if let state = model.state {
                if state.sessions.isEmpty { Text("No controller sessions.").font(.caption) }
                ForEach(state.sessions) { session in
                    HStack {
                        VStack(alignment: .leading) {
                            Text(session.origin).font(.callout)
                            Text("Tab \(session.tabId) · \(session.approved ? "Connected" : "Connecting") · expires \(session.expiresAt.formatted(date: .omitted, time: .shortened))").font(.caption).foregroundStyle(.secondary)
                        }
                        Spacer()

                        Button(session.approved ? "Revoke" : "Dismiss") { perform(.revoke, session.id) }
                    }
                }
            }
        }.disabled(model.busy || broker == nil)
        .task { await model.perform(.status, broker: broker, profile: profile, browser: browser) }
    }
    private func perform(_ action: BrowserControllerAction, _ session: String? = nil) {
        Task { await model.perform(action, broker: broker, profile: profile, browser: browser, session: session) }
    }
}
