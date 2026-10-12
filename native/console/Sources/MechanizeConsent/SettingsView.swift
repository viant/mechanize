import SwiftUI
import ConsentCore

struct SettingsTab: View {
    @ObservedObject var model: ConsoleModel
    @State private var settings: RuntimeSettingsSnapshot?
    @State private var port = ""
    @State private var busy = false
    @State private var message = ""
    private var selectedPort: Int? {
        guard !port.isEmpty, port.utf8.allSatisfy({ (48...57).contains($0) }), let value = Int(port), (1...65535).contains(value) else { return nil }
        return value
    }
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Label("Settings", systemImage: "gearshape").font(.title2.bold())
                VStack(alignment: .leading, spacing: 12) {
                    Text("MCP connection").font(.headline)
                    if let settings {
                        if settings.transport == "http" {
                            LabeledContent("Current address", value: settings.currentAddress).textSelection(.enabled)
                            HStack {
                                Text("MCP port")
                                TextField("Port", text: $port).textFieldStyle(.roundedBorder).frame(width: 100)
                                    .accessibilityIdentifier("mechanize.settings.mcp-port")
                            }
                            Text("Use a port from 1 to 65535. Connections remain local and authenticated.").font(.caption).foregroundStyle(.secondary)
                            Button("Save port for restart") { Task { await save() } }
                                .accessibilityIdentifier("mechanize.settings.save-port")
                                .disabled(busy || selectedPort == nil || selectedPort == settings.savedPort)
                            if settings.restartRequired {
                                Label("Port \(settings.savedPort) is saved. Restart Mechanize, then reconnect MCP clients.", systemImage: "arrow.clockwise")
                                    .font(.callout)
                            } else {
                                Text("A port change takes effect after restart.").font(.caption).foregroundStyle(.secondary)
                            }
                        } else {
                            Text("This broker uses stdio. There is no HTTP port to configure.").foregroundStyle(.secondary)
                        }
                    } else {
                        Text(model.connected ? "Loading connection settings…" : "Connect to Mechanize to load settings.").foregroundStyle(.secondary)
                    }
                    if !message.isEmpty { Text(message).font(.callout).foregroundStyle(.secondary) }
                    Button("Refresh settings") { Task { await refresh() } }.disabled(busy || !model.connected)
                }.padding(16).frame(maxWidth: .infinity, alignment: .leading)
                    .background(.background, in: RoundedRectangle(cornerRadius: 10))
            }.padding(.vertical, 16)
        }.task { await refresh() }
    }
    @MainActor private func refresh() async {
        guard model.connected, !busy else { return }; busy = true; defer { busy = false }
        do { let value = try await model.host.runtimeSettings(); settings = value; port = String(value.savedPort); message = "" }
        catch { settings = nil; message = "Settings are unavailable. Reconnect or update Mechanize." }
    }
    @MainActor private func save() async {
        guard let settings, let selectedPort, !busy else { return }; busy = true; defer { busy = false }
        do { let value = try await model.host.updateRuntimePort(expectedRevision: settings.revision, port: selectedPort); self.settings = value; port = String(value.savedPort); message = "Port saved." }
        catch { message = "Save could not be confirmed. Refresh settings before trying again." }
    }
}
