import AppKit

// A disposable, inert target for explicit native keyboard session qualification.
final class FixtureDelegate: NSObject, NSApplicationDelegate {
    private var window: NSWindow!
    private var status: NSTextField!

    func applicationDidFinishLaunching(_ notification: Notification) {
        window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 360, height: 150),
            styleMask: [.titled, .closable, .miniaturizable],
            backing: .buffered,
            defer: false
        )
        window.title = "Mechanize Keyboard Fixture"
        window.isReleasedWhenClosed = false

        let button = NSButton(title: "Choose folder", target: self, action: #selector(chooseFolder))
        button.bezelStyle = .rounded
        button.setAccessibilityIdentifier("choose-folder")
        button.translatesAutoresizingMaskIntoConstraints = false

        status = NSTextField(labelWithString: "Ready")
        status.setAccessibilityIdentifier("fixture-status")
        status.translatesAutoresizingMaskIntoConstraints = false

        let content = window.contentView!
        content.addSubview(button)
        content.addSubview(status)
        NSLayoutConstraint.activate([
            button.centerXAnchor.constraint(equalTo: content.centerXAnchor),
            button.topAnchor.constraint(equalTo: content.topAnchor, constant: 32),
            status.centerXAnchor.constraint(equalTo: content.centerXAnchor),
            status.topAnchor.constraint(equalTo: button.bottomAnchor, constant: 20)
        ])

        window.center()
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    @objc private func chooseFolder() {
        let panel = NSOpenPanel()
        panel.title = "Choose folder"
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.allowsMultipleSelection = false
        panel.canCreateDirectories = false
        panel.beginSheetModal(for: window) { [weak self] response in
            // Deliberately do not read, retain, display, or log the selected URL.
            self?.status.stringValue = response == .OK ? "Selected" : "Cancelled"
        }
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        true
    }
}

let application = NSApplication.shared
let delegate = FixtureDelegate()
application.setActivationPolicy(.regular)
application.delegate = delegate
application.run()
