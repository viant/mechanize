import SwiftUI
import ConsentCore

/// Explicit native selection and approval stay in the existing main window.
/// Without the authenticated package source the action is visibly inactive.
struct RuntimeUpgradeSelectionView: View {
    @ObservedObject var selection: MigrationUpgradeSelection
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                if let title = selection.selectedTitle {
                    Text(title).font(.callout)
                } else {
                    Text(selection.state == .unavailable ? "No authenticated upgrade package is available." : selection.state == .cancelled ? "Upgrade cancelled." : selection.state == .failed ? "Upgrade could not proceed. Check its status before retrying." : "Select a reviewed runtime upgrade.").font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                Button("Select upgrade") { Task { try? await selection.selectReviewedPackage() } }
                    .disabled(!selection.canSelect).accessibilityIdentifier("mechanize.upgrade.select")
                Button("Upgrade") { Task { try? await selection.approveSelectedUpgrade() } }
                    .disabled(!selection.canUpgrade).accessibilityIdentifier("mechanize.upgrade.approve")
                if selection.state == .selected || selection.state == .selecting || selection.state == .starting {
                    Button("Cancel") { selection.cancel() }.accessibilityIdentifier("mechanize.upgrade.cancel")
                }
            }
            if let source = selection.relocationSource, let destination = selection.relocationDestination {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Move runtime into Mechanize.app").font(.headline)
                    Text("From: \(source)")
                    Text("To: \(destination)")
                    Text("Existing components remain until the replacement is independently verified.").foregroundStyle(.secondary)
                }.font(.caption).textSelection(.enabled)
            }
            RuntimeUpgradeStatusView(coordinator: selection.coordinator)
        }
    }
}

struct RuntimeUpgradeStatusView: View {
    @ObservedObject var coordinator: MigrationUpgradeCoordinator

    private var failureMessage: String? {
        guard let code = coordinator.failureCode else { return nil }
        switch code {
        case "accessibilityRequired": return "Enable Accessibility for Mechanize before updating."
        case "managementDocument": return "Keep Mechanize’s extension details page open in Chrome."
        case "nativeObservation": return "Mechanize could not read Chrome’s extension details."
        case "loadedPath": return "Chrome’s extension location could not be verified."
        case "loadedPathMismatch": return "Chrome is using a different Mechanize extension folder."
        case "chromeIdentity", "googleIdentity", "chromeIdentityChanged": return "Chrome changed during the update check."
        default: return "The installed extension could not be verified for this update."
        }
    }

    var body: some View {
        if coordinator.state != .unavailable && coordinator.state != .ready {
            VStack(alignment: .leading, spacing: 6) {
              HStack(spacing: 10) {
                if coordinator.isRunning {
                    ProgressView().controlSize(.small)
                }
                Text(coordinator.state.message).font(.callout)
                    .accessibilityIdentifier("mechanize.upgrade.status")
                Spacer()
                if coordinator.canInspectRecovery {
                    Button("Inspect recovery") {
                        Task { try? await coordinator.inspectRecovery() }
                    }
                    .accessibilityIdentifier("mechanize.upgrade.inspectRecovery")
                }
              }
              if let failureMessage {
                  Text(failureMessage).font(.caption).foregroundStyle(.secondary)
                      .accessibilityIdentifier("mechanize.upgrade.failureReason")
              }
            }
            .padding(12)
            .background(.background, in: RoundedRectangle(cornerRadius: 10))
        }
    }
}
