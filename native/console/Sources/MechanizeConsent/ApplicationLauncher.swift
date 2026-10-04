import AppKit
import Foundation

@MainActor
final class ApplicationLauncher: ObservableObject {
    @Published private(set) var isLaunching = false
    @Published private(set) var message = ""
    @Published private(set) var lastLaunchSucceeded = false

    func open(url: URL, expectedBundleID: String) async {
        guard !isLaunching else { return }
        guard url.isFileURL,
              url.pathExtension.lowercased() == "app",
              let values = try? url.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey]),
              values.isDirectory == true, values.isSymbolicLink != true,
              let actualBundleID = Bundle(url: url)?.bundleIdentifier,
              actualBundleID == expectedBundleID,
              ApplicationInventory.isValidBundleID(expectedBundleID) else {
            lastLaunchSucceeded = false
            message = "This application is unavailable or its identity changed. Refresh the application list and try again."
            return
        }

        isLaunching = true
        message = "Opening \(url.deletingPathExtension().lastPathComponent)…"
        defer { isLaunching = false }
        do {
            _ = try await NSWorkspace.shared.openApplication(at: url, configuration: NSWorkspace.OpenConfiguration())
            lastLaunchSucceeded = true
            message = "Opened \(url.deletingPathExtension().lastPathComponent)."
        } catch {
            lastLaunchSucceeded = false
            message = "Could not open \(url.deletingPathExtension().lastPathComponent): \(error.localizedDescription)"
        }
    }
}
