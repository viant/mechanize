import SwiftUI
import ConsentCore

struct BrowsersTab: View {
    @ObservedObject var model: ConsoleModel
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                HStack {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("Browser connections").font(.title2).bold()
                        Text("Browser readiness is separate from the console’s local broker connection.").foregroundStyle(.secondary)
                    }
                }
                if let status = model.browserStatus {
                    if status.processQualificationFailed {
                        Label("Chrome verification required", systemImage: "exclamationmark.shield").font(.headline)
                        Text("The Chrome extension connection is disabled. Native administration and separately authorized native controls remain available. Review verified browser enrollment and explicitly reload configuration before restarting the bridge. Existing unknown effects must be preserved.").foregroundStyle(.secondary)
                    } else if !status.available || status.channels.isEmpty {
                        Label("Chrome enrollment required", systemImage: "puzzlepiece.extension").font(.headline)
                        Text("Load Mechanize in the Chrome profile you want to use, then complete its local connection setup.").foregroundStyle(.secondary)
                    }
                    ForEach(Array(status.channels.enumerated()), id: \.offset) { index, channel in
                        VStack(alignment: .leading, spacing: 12) {
                            HStack {
                                Label("Chrome connection \(index + 1)", systemImage: "globe").font(.headline)
                                Spacer()
                                Text(channel.readiness).font(.callout).foregroundStyle(channel.ready ? Color.green : Color.secondary)
                            }
                            Text(channel.trustScope == "desktop" ? "Desktop scope · profile isolation is not claimed" : "Profile scope")
                                .font(.caption).foregroundStyle(.secondary)
                            Text(channel.websiteAccessDescription).font(.callout)
                            HStack(spacing: 24) {
                                Label(channel.connected ? "Transport connected" : "Transport disconnected", systemImage: channel.connected ? "link" : "link.badge.plus")
                                Text("\(channel.documentCount) observed documents")
                            }.font(.callout)
                            if channel.unknownCount > 0 {
                                Text("Inspect and reconcile unknown effects before reconnecting or changing setup.").foregroundStyle(.secondary)
                            } else if !channel.connected {
                                Text("Open the extension’s connection page in the intended Chrome profile. Website permission alone does not connect the local host.").foregroundStyle(.secondary)
                            } else if !channel.ready {
                                Text("The connection has not passed all readiness checks. Open an approved website and refresh status.").foregroundStyle(.secondary)
                            }
                            if let profile = channel.profileChannel, let browser = channel.browserInstance {
                                BrowserControllersView(broker: model.host as? SocketConsentBroker, profile: profile, browser: browser)
                                    .id(profile + "\u{0}" + browser)
                            }
                            if let code = channel.attentionCode, !code.isEmpty { Text("Attention: \(code)").font(.caption).foregroundStyle(.secondary) }
 if let explanation = channel.reconnectExplanation { Text(explanation).font(.callout).foregroundStyle(.secondary) }
                        }.padding(18).background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 12))
                    }
                } else {
                    ContentUnavailableView("Browser status unavailable", systemImage: "globe", description: Text(model.browserStatusMessage))
                }
                Text("Controller changes apply to the selected browser connection. Website permissions are managed separately.")
                    .font(.caption).foregroundStyle(.secondary)
            }.padding(22)
        }
    }
}
