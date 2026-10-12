import SwiftUI
import AppKit
import ConsentCore
import Security

@main struct MechanizeConsentApp: App {
    @StateObject private var model: ConsoleModel
    private let helperLauncher: ConsoleHelperLaunchService?

    init() {
        if CommandLine.arguments.dropFirst().contains("--trust-localhost-controllers") {
            let args = Array(CommandLine.arguments.dropFirst())
            let report: BrowserControllerLocalhostReport
            if args != BrowserControllerLocalhostCLI.arguments {
                report = .init(stage: "setup", errorCode: "invalidArguments")
            } else if SecKeychainSetUserInteractionAllowed(false) != errSecSuccess {
                report = .init(stage: "connection", errorCode: "interactionPolicyUnavailable")
            } else if let configuration = Self.provisionedConfiguration() {
                report = BrowserControllerLocalhostCLI.runFromExplicitCLI(arguments: args, transport: configuration.transport, credentials: configuration.credentials)
            } else {
                report = .init(stage: "setup", errorCode: "setupUnavailable")
            }
            var output = report.json(); output.append(10)
            try? FileHandle.standardOutput.write(contentsOf: output)
            exit(report.succeeded ? 0 : 1)
        }
        if CommandLine.arguments.dropFirst().contains("--check-runtime-upgrade") {
            let report = MigrationRuntimeUpgradeDiagnostics.runCLI(arguments: Array(CommandLine.arguments.dropFirst()))
            var output = report.json(); output.append(10)
            try? FileHandle.standardOutput.write(contentsOf: output)
            exit(report.qualified ? 0 : 1)
        }
        let launcher = CommandLine.arguments.count == 1 ? (try? ConsoleHelperLaunchService.startEnrolled()) : nil
        helperLauncher = launcher
        let launchUnavailable = CommandLine.arguments.count == 1 && Bundle.main.object(forInfoDictionaryKey: "MechanizeHelperLaunchTransport") != nil && launcher == nil
        let configuration = Self.provisionedConfiguration()
        let broker: any ConsentHostAdapter = configuration.map { SocketConsentBroker(transport: $0.transport, credentials: $0.credentials) } ?? DisconnectedHostAdapter()
        let upgrade = MigrationUpgradeSelection(source: MigrationSignedPackageSource.enrolled(),
            credentials: configuration?.credentials)
        _model = StateObject(wrappedValue: ConsoleModel(broker: broker, runtimeUpgrade: upgrade, helperLaunchUnavailable: launchUnavailable))
        if CommandLine.arguments.dropFirst().contains("--enroll-credential") {
            let report = ConsoleOwnedEnrollment.runCLI(arguments: Array(CommandLine.arguments.dropFirst()))
            var output = report.json(); output.append(10)
            try? FileHandle.standardOutput.write(contentsOf: output)
            exit(report.exitCode)
        }
        if CommandLine.arguments.dropFirst().contains("--check-vault") {
            let report: VaultDiagnosticReport
            if Array(CommandLine.arguments.dropFirst()).contains("--broker-pid") {
                report = MigrationVaultReadiness.runCLI(arguments: Array(CommandLine.arguments.dropFirst()))
            } else if Array(CommandLine.arguments.dropFirst()) != ["--check-vault"] {
                report = VaultDiagnosticReport(stage: "setup", errorCode: "invalidArguments")
            } else if SecKeychainSetUserInteractionAllowed(false) != errSecSuccess {
                report = VaultDiagnosticReport(stage: "connection", errorCode: "interactionPolicyUnavailable")
            } else if let configuration = Self.provisionedConfiguration() {
                report = VaultDiagnostics.runFromExplicitCLI(transport: configuration.transport, credentials: configuration.credentials)
            } else {
                report = VaultDiagnosticReport(stage: "setup", errorCode: "setupUnavailable")
            }
            var output = report.json(); output.append(10)
            try? FileHandle.standardOutput.write(contentsOf: output)
            exit(report.succeeded ? 0 : 1)
        }
        if CommandLine.arguments.count == 1 {
            Task { @MainActor in PersistentAutomationPointer.shared.start() }
            return
        }
        guard CommandLine.arguments.dropFirst().contains("--check-connection") else { return }
        // LAContext's interaction policy does not cover legacy Keychain ACL
        // prompts. The explicit diagnostic must never start a SecurityAgent UI.
        guard SecKeychainSetUserInteractionAllowed(false) == errSecSuccess else {
            let report = ConnectionDiagnosticReport(stage: "credential", errorCode: "interactionPolicyUnavailable")
            var output = report.json(); output.append(10)
            try? FileHandle.standardOutput.write(contentsOf: output)
            exit(1)
        }
        let report: ConnectionDiagnosticReport
        if Array(CommandLine.arguments.dropFirst()) != ["--check-connection"] {
            report = ConnectionDiagnosticReport(stage: "setup", errorCode: "invalidArguments")
        } else if let configuration = Self.provisionedConfiguration() {
            report = ConnectionDiagnostics.runFromExplicitCLI(transport: configuration.transport, credentials: configuration.credentials)
        } else {
            report = ConnectionDiagnosticReport(stage: "setup", errorCode: "setupUnavailable")
        }
        var output = report.json(); output.append(10)
        try? FileHandle.standardOutput.write(contentsOf: output)
        exit(report.succeeded ? 0 : 1)
    }
    nonisolated private static func provisionedConfiguration() -> (transport: UnixBrokerTransport, credentials: KeychainEnrollment)? {
        guard Bundle.main.bundleIdentifier == "com.viant.mechanize.consent",
              let requirement = Bundle.main.object(forInfoDictionaryKey: "MechanizeBrokerRequirement") as? String,
              !requirement.isEmpty,
              let peer = try? SignedBrokerPeer(designatedRequirement: requirement, expectedUID: getuid()) else { return nil }
        let configuredAccount = Bundle.main.object(forInfoDictionaryKey: "MechanizeEnrollmentAccount")
        guard configuredAccount == nil || configuredAccount is String else { return nil }
        return (UnixBrokerTransport(authenticator: peer), KeychainEnrollment(trustedBundleID: "com.viant.mechanize.consent", uid: getuid(), enrolledAccount: configuredAccount as? String))
    }
    private static func provisionedBroker() -> any ConsentHostAdapter {
        guard let configuration = provisionedConfiguration() else { return DisconnectedHostAdapter() }
        return SocketConsentBroker(transport: configuration.transport, credentials: configuration.credentials)
    }
    nonisolated static func nativeVaultBroker() throws -> SocketConsentBroker {
        guard let configuration = provisionedConfiguration() else { throw BrokerTransportError.unavailable }
        return SocketConsentBroker(transport: configuration.transport, credentials: configuration.credentials)
    }
    private static func menuBarIcon() -> NSImage? {
        guard let path = Bundle.main.path(forResource: "MechanizeMenu", ofType: "png"),
              let image = NSImage(contentsOfFile: path) else { return nil }
        // MenuBarExtra can use the AppKit image's intrinsic size rather than
        // a SwiftUI frame. Set its logical point size before supplying it.
        image.size = NSSize(width: 16, height: 16)
        image.isTemplate = false
        return image
    }
    var body: some Scene {
        Window("Mechanize", id: "main") { ConsentView(model: model) }
            .defaultSize(width: 760, height: 620)
        MenuBarExtra { MenuBarPanel(model: model) } label: {
            if let icon = Self.menuBarIcon() {
                Image(nsImage: icon).renderingMode(.original).accessibilityLabel("Mechanize")
            } else { Image(systemName: "v.circle").accessibilityLabel("Mechanize") }
        }
    }
}

@MainActor final class ConsoleModel: ObservableObject {
    @Published var requests: [ConsentRequest] = []
    @Published var grants: [ConsentGrant] = []
    @Published var message = "Connecting to Mechanize…"
    @Published var busy = false
    private var nextReconnectAt = Date.distantPast
    private var reconnectDelay: TimeInterval = 2
    let helperLaunchUnavailable: Bool
    @Published var browserStatus: BrowserConnectionStatus?
    @Published var browserStatusMessage = "Connect to the local broker to inspect browser readiness."
    @Published var doctor: [HelperPermissionStatus] = []
    @Published var installedApplications: [InstalledApplication] = []
    @Published var applicationAccess: ApplicationAccessSnapshot?
    @Published var applicationPolicyAvailable = false
    @Published var applicationPolicyMessage = "Loading application access…"
    let host: any ConsentHostAdapter
    let runtimeUpgrade: MigrationUpgradeSelection
    @Published var revokeStatuses: [String: RevokeStatus] = [:]
    let controller: ConsentController
    init(broker: any ConsentHostAdapter = DisconnectedHostAdapter(), runtimeUpgrade: MigrationUpgradeSelection? = nil, helperLaunchUnavailable: Bool = false) {
        self.helperLaunchUnavailable = helperLaunchUnavailable
        host = broker
        self.runtimeUpgrade = runtimeUpgrade ?? MigrationUpgradeSelection()
        controller = ConsentController(broker: broker)
        installedApplications = ApplicationInventory.scan()
    }
    var connected: Bool { controller.isConnected }
    var activeGrants: [ConsentGrant] { grants.filter { $0.isActive(at: Date()) } }
    func refreshConnection() async {
        guard !busy else { return }
        if connected { reconnectDelay = 2; await refresh(); return }
        guard Date() >= nextReconnectAt, let broker = host as? SocketConsentBroker else { return }
        nextReconnectAt = Date().addingTimeInterval(reconnectDelay)
        reconnectDelay = min(30, reconnectDelay * 2)
        busy = true
        do {
            let restored = try await Task.detached { try broker.reconnectPreviouslyRequested() }.value
            busy = false
            if restored { reconnectDelay = 2; await refresh() }
        } catch { busy = false; doctor = [] }
    }
    func connect() async {
        guard !busy else { return }
        if connected { await refresh(); return }
        guard let broker = host as? SocketConsentBroker else { message = "Setup is incomplete. Mechanize needs a trusted installation before you can grant access."; return }
        busy = true
        do { try await Task.detached { try broker.connectFromUserAction() }.value; busy = false; await refresh() }
        catch {
            busy = false; doctor = []; message = error.localizedDescription
            applicationPolicyAvailable = false
            applicationPolicyMessage = "Connection unavailable. Use Retry connection above; switches stay disabled until access is confirmed."
        }
    }
    func refresh() async {
        guard !busy, connected else { return }
        busy = true; defer { busy = false }
        do {
            try await controller.refresh(); sync()
            do {
                applicationAccess = try await host.applicationAccess()
                applicationPolicyAvailable = true
                applicationPolicyMessage = applicationAccess?.policy.desktopWide == true
                    ? "Desktop-wide access is enabled. Per-application entries with no modes remain denied."
                    : "Only applications with listed modes are permitted by this policy."
            } catch {
                applicationPolicyAvailable = false
                applicationPolicyMessage = "Could not load application access: \(error.localizedDescription) Use Refresh to retry."
            }
            do { browserStatus = try await host.browserStatus(); browserStatusMessage = "" }
            catch { browserStatus = nil; browserStatusMessage = "Browser status unavailable. Refresh after the broker supports browser diagnostics." }
            doctor = (try? await host.helperPermissionDoctor()) ?? []
            message = "Local broker connected. Review requests below and stop access at any time."
        } catch { doctor = []; browserStatus = nil; browserStatusMessage = "Local broker unavailable. Retry connection above."; message = error.localizedDescription }
    }
    var applicationRows: [ApplicationAccessListRow] {
        let rules = Dictionary((applicationAccess?.policy.applications ?? []).map { ($0.bundleID, $0) }, uniquingKeysWith: { _, newer in newer })
        var rows = installedApplications.map { app -> ApplicationAccessListRow in
            let rule = rules[app.bundleID]
            let allowed = rule.map { !$0.modes.isEmpty } ?? (applicationAccess?.policy.desktopWide == true)
            return ApplicationAccessListRow(bundleID: app.bundleID, displayName: rule?.displayName ?? app.displayName,
                modes: rule?.modes ?? [], enabled: allowed,
                source: rule == nil ? (applicationAccess?.policy.desktopWide == true ? "Allowed by desktop-wide policy" : "Installed · no application policy entry") : (rule?.modes.isEmpty == true ? "Denied by application policy" : "Allowed by application policy"), installedURL: app.url)
        }
        let installedIDs = Set(installedApplications.map(\.bundleID))
        rows += (applicationAccess?.policy.applications ?? []).filter { !installedIDs.contains($0.bundleID) }.map { rule in
            ApplicationAccessListRow(bundleID: rule.bundleID, displayName: rule.displayName, modes: rule.modes,
                enabled: !rule.modes.isEmpty, source: rule.modes.isEmpty ? "Denied by application policy · application not found in scanned folders" : "Allowed by application policy · application not found in scanned folders")
        }
        return rows.sorted { $0.displayName.localizedCaseInsensitiveCompare($1.displayName) == .orderedAscending }
    }
    func setApplicationAccess(_ row: ApplicationAccessListRow, enabled: Bool) async {
        guard connected, applicationPolicyAvailable, !busy, let current = applicationAccess else { return }
        busy = true; defer { busy = false }
        let oldRule = current.policy.applications.first { $0.bundleID == row.bundleID }
        let modes: [ConsentMode]
        if enabled {
            var selected: [ConsentMode] = [.observe, .control]
            if oldRule?.modes.contains(.record) == true { selected.append(.record) }
            modes = selected
        } else { modes = [] }
        var rules = current.policy.applications.filter { $0.bundleID != row.bundleID }
        rules.append(ApplicationAccessRule(bundleID: row.bundleID, displayName: row.displayName, modes: modes))
        do {
            applicationAccess = try await host.updateApplicationAccess(expectedRevision: current.revision,
                policy: ApplicationAccessPolicy(desktopWide: current.policy.desktopWide, applications: rules))
            applicationPolicyMessage = "Application policy saved and confirmed by Mechanize."
        } catch { message = "Application policy was not changed: \(error.localizedDescription)" }
    }
    func decide(_ request: ConsentRequest, _ decision: ConsentDecision) async { busy = true; defer { busy = false }; do { try await controller.decide(request, decision: decision); sync(); message = decision == .deny ? "Access denied." : "Access allowed for the scope shown. macOS permissions must also be ready." } catch { message = error.localizedDescription } }
    func revoke(_ grant: ConsentGrant) async { busy = true; defer { busy = false }; do { let status = try await controller.revoke(grant); revokeStatuses[grant.id] = status; sync(); message = stopDescription(status) } catch { message = error.localizedDescription } }
    func stopAllActive() async { for grant in activeGrants { await revoke(grant) } }
    func openSettings(_ permission: HelperPermission) async { do { try await host.openSystemPermissionSettings(permission) } catch { message = error.localizedDescription } }
    func sync() { requests = controller.requests; grants = controller.grants }
    func stopDescription(_ status: RevokeStatus) -> String {
        switch status {
        case .requested: return "Stop requested. Waiting for running actions to finish safely."
        case .stopping: return "Stopping access…"
        case .revoked: return "Access stopped."
        case .cleanupUnknown: return "Access has been withdrawn. Mechanize could not confirm that every running action stopped."
        }
    }
}

struct ConsentView: View {
    @ObservedObject var model: ConsoleModel
    @AppStorage("mechanize.selectedTab") private var selectedTab = "requests"
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("Mechanize").font(.title2.bold())
                Spacer()
                if model.connected {
                    Label("Connected", systemImage: "checkmark.circle")
                        .font(.callout).foregroundStyle(.secondary)
                        .accessibilityIdentifier("mechanize.connectionStatus")
                    Button("Refresh") { Task { await model.refresh() } }.disabled(model.busy)
                } else {
                    Button("Connect") { Task { await model.connect() } }
                        .accessibilityIdentifier("mechanize.connect").disabled(model.busy)
                }
                if model.busy { ProgressView().controlSize(.small) }
            }
            Text(model.message).font(.caption).foregroundStyle(model.connected ? .primary : .secondary).lineLimit(2).textSelection(.enabled)
            RuntimeUpgradeSelectionView(selection: model.runtimeUpgrade)
            TabView(selection: $selectedTab) {
                RequestsTab(model: model).tabItem { Label("Requests", systemImage: "hand.raised") }.tag("requests")
                BrowsersTab(model: model).tabItem { Label("Browsers", systemImage: "globe") }.tag("browsers")
                ApplicationsTab(model: model).tabItem { Label("Applications", systemImage: "app.badge") }.tag("applications")
                ActivityTab(model: model).tabItem { Label("Activity", systemImage: "clock.arrow.circlepath") }.tag("activity")
                PermissionsTab(model: model).tabItem { Label("Permissions", systemImage: "lock.shield") }.tag("permissions")
                VaultTab(openPermissions: { selectedTab = "permissions" }).tabItem { Label("Vault", systemImage: "key.horizontal") }.tag("vault")
                SettingsTab(model: model).tabItem { Label("Settings", systemImage: "gearshape") }.tag("settings")
            }
        }
        .padding(16)
        .task {
            await model.connect()
            while !Task.isCancelled {
                do { try await Task.sleep(nanoseconds: 2_000_000_000) } catch { break }
                await model.refreshConnection()
            }
        }
    }
}

private struct RequestsTab: View {
    @ObservedObject var model: ConsoleModel
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                if model.requests.isEmpty { Text(model.connected ? "No new access requests. Trusted tools can continue automatically." : "Connect to see requests from verified tools.").foregroundStyle(.secondary) }
                ForEach(model.requests) { request in
                    VStack(alignment: .leading, spacing: 7) {
                        Text("\(request.verifiedClient.displayName) wants access").font(.headline)
                        consentDetails(scope: request.scope, modes: request.modes, purpose: request.purpose, seconds: request.durationSeconds)
                        Text("Decide before \(request.expiresAt.formatted())").font(.caption)
                        HStack {
                            Button("Allow once") { Task { await model.decide(request, .allowOnce) } }
                            Button("Allow for session") { Task { await model.decide(request, .allowSession) } }
                            if request.verifiedClient.verification == .verified && request.isValid(at: Date()) {
                                Button("Trust until revoked") { Task { await model.decide(request, .allowUntilRevoked) } }
                            }
                            Button("Deny", role: .destructive) { Task { await model.decide(request, .deny) } }
                        }.disabled(!model.connected || model.busy || !request.isValid(at: Date()))
                        Text("Trust until revoked has no time limit and remains active across tool sessions and Mechanize restarts, until you stop access.").font(.caption).foregroundStyle(.secondary)
                        DisclosureGroup("Verified tool identity") { Text("\(request.verifiedClient.id) · \(request.verifiedClient.verification.rawValue)").font(.caption).textSelection(.enabled) }
                    }.padding(12).frame(maxWidth: .infinity, alignment: .leading).background(.background, in: RoundedRectangle(cornerRadius: 10))
                }
            }.padding(.vertical, 10)
        }
    }
}

private struct ApplicationsTab: View {
    @ObservedObject var model: ConsoleModel
    var body: some View {
        ScrollView {
            ApplicationAccessListView(rows: model.applicationRows, connected: model.connected,
                policyAvailable: model.applicationPolicyAvailable, busy: model.busy, message: model.applicationPolicyMessage) { row, enabled in
                    Task { await model.setApplicationAccess(row, enabled: enabled) }
                }
                .padding(.vertical, 10)
                .padding(.leading, 12)
                // Keep controls clear of both overlay and legacy scrollbars.
                .padding(.trailing, 28)
        }
    }
}

private struct ActivityTab: View {
    @ObservedObject var model: ConsoleModel
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                if model.grants.isEmpty { Text("No access has been granted.").foregroundStyle(.secondary) }
                ForEach(model.grants) { grant in
                    VStack(alignment: .leading, spacing: 6) {
                        Text("\(grant.clientID) · \(grant.permanent ? "Until revoked" : (grant.decision == .allowOnce ? "Once" : "Session")) · \(grant.isActive(at: Date()) ? "Active" : (grant.state == .active ? "Expired" : grant.state.rawValue))").font(.headline)
                        consentDetails(scope: grant.scope, modes: grant.modes, purpose: grant.purpose, seconds: grant.durationSeconds, permanent: grant.permanent)
                        if grant.permanent { Text("No time limit · remains active across sessions and restarts until revoked").font(.caption) }
                        else { Text("Expires \(grant.expiresAt.formatted()) · Remaining \(max(0, Int(grant.expiresAt.timeIntervalSinceNow))) seconds").font(.caption) }
                        Button("Stop access", role: .destructive) { Task { await model.revoke(grant) } }.disabled(!model.connected || model.busy || !grant.isActive(at: Date()))
                        if let status = model.revokeStatuses[grant.id] { Text(model.stopDescription(status)).font(.caption) }
                    }.padding(12).frame(maxWidth: .infinity, alignment: .leading).background(.background, in: RoundedRectangle(cornerRadius: 10))
                }
            }.padding(.vertical, 10)
        }
    }
}

private func permissionLabel(_ permission: HelperPermission) -> String {
    switch permission {
    case .accessibility: return "Accessibility"
    case .screenRecording: return "Screen Recording"
    case .inputMonitoring: return "Input Monitoring"
    }
}

private func permissionStatusDetail(_ status: HelperPermissionStatus) -> String {
    switch status.detail.components(separatedBy: ":").first {
    case "observationHelperCleanupUnconfirmed":
        return "The previous automation helper did not finish closing. Mechanize needs a clean runtime restart to check this permission."
    case "observationHelperUnavailable":
        return "The automation helper could not be reached. This does not mean macOS denied permission."
    case "observationHelperCheckInterrupted":
        return "The permission check was interrupted. Mechanize will check again automatically."
    case "observationHelperReplyInvalid":
        return "The automation helper returned an incomplete permission check. Mechanize will check again automatically."
    default:
        return status.state == .unknown ? "The automation helper could not verify this permission. Mechanize will check again automatically." : "Verified by the automation runtime."
    }
}

private struct PermissionsTab: View {
    @ObservedObject var model: ConsoleModel
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                AccessibilitySetupTile()
                if model.helperLaunchUnavailable { Text("Mechanize could not start its private automation service. Quit and reopen the app. If the problem persists, reinstall the signed app.").foregroundStyle(.red) }
                if model.doctor.isEmpty { Text(model.connected ? "Permission status has not been checked yet." : "Connect to Mechanize to check permission status.").font(.caption).foregroundStyle(.secondary) }
                ForEach(model.connected ? model.doctor : [], id: \.permission) { status in
                    VStack(alignment: .leading, spacing: 5) {
                        Text("\(permissionLabel(status.permission)) — \(status.state == .unknown ? "could not check" : status.state.rawValue)").font(.headline)
                            .accessibilityIdentifier("mechanize.permission.\(status.permission.rawValue).state")
                        Text(permissionStatusDetail(status)).font(.caption).foregroundStyle(status.state == .unknown ? .secondary : .primary)
                        Button("Open System Settings for \(status.permission.rawValue)") { Task { await model.openSettings(status.permission) } }.disabled(!model.connected)
                    }.padding(12).frame(maxWidth: .infinity, alignment: .leading).background(.background, in: RoundedRectangle(cornerRadius: 10))
                }
                Text("macOS permissions are separate from access grants. A single Mechanize app contains runtime components, but macOS can require separate permission entries for the broker, automation helper, or upgrade observer.").font(.caption).foregroundStyle(.secondary)
            }.padding(.vertical, 10)
        }
    }
}

private struct MenuBarPanel: View {
    @ObservedObject var model: ConsoleModel
    @Environment(\.openWindow) private var openWindow
    @AppStorage(PersistentAutomationPointer.preferenceKey) private var showPointer = true
    var body: some View {
        Text(model.connected ? "Connected · \(model.activeGrants.count) active grants" : "Not connected")
            .font(.caption).foregroundStyle(.secondary)
        Button("Open Mechanize") {
            NSApp.unhide(nil)
            openWindow(id: "main")
            NSApp.activate(ignoringOtherApps: true)
        }
        Toggle("Show automation pointer", isOn: $showPointer)
            .onChange(of: showPointer) { _, value in PersistentAutomationPointer.shared.enabled = value }
        Button("Stop Access") { Task { await model.stopAllActive() } }.disabled(!model.connected || model.activeGrants.isEmpty || model.busy)
        Divider()
        Button("Quit Mechanize") { NSApp.terminate(nil) }
    }
}

@ViewBuilder private func consentDetails(scope: ConsentScope, modes: [ConsentMode], purpose: String, seconds: Int, permanent: Bool = false) -> some View {
    VStack(alignment: .leading, spacing: 4) {
        Text(scope.exactDescription).textSelection(.enabled)
        ForEach(modes, id: \.self) { mode in
            switch mode {
            case .observe: Text("View: read screen content and interface elements.")
            case .control: Text("Control: click, type, and change content.")
            case .record: Text("Record: capture interactions to build an automation.")
            }
        }
        Text("Why: \(purpose)").textSelection(.enabled)
        if !permanent { Text("For up to \(seconds) seconds") }
    }.font(.callout)
}

/// macOS setup is available before connecting; it never grants broker consent.
struct AccessibilitySetupTile: View {
    @State private var installation: HelperInstallation?
    @State private var unavailable = "Checking the installed Mechanize runtime…"
    @State private var actionMessage: String?
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 10) {
                Image(systemName: "hand.raised.fill").foregroundStyle(.blue)
                Text("Set up Accessibility").font(.headline)
                Spacer()
            }
            Text(installation?.appOwnsAutomation == true ? "Open Accessibility settings and enable Mechanize.app below. This app launches the automation helper; runtime checks confirm whether access is available." : "Open Accessibility settings and enable the verified broker below. Keep existing Mechanize entries until the replacement runtime is verified. The automation helper may require its own entry.")
                .font(.subheadline).foregroundStyle(.secondary)
            if let installation {
                HStack(spacing: 14) {
                    Image(nsImage: NSWorkspace.shared.icon(forFile: installation.permissionDisplayURL.path))
                        .resizable().scaledToFit().frame(width: 52, height: 52)
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Drag Mechanize into Accessibility").font(.subheadline.weight(.semibold))
                        Text(installation.appOwnsAutomation ? "Mechanize.app" : "mechanize · automation broker").font(.caption).foregroundStyle(.secondary)
                        Text(installation.permissionDisplayURL.path).font(.caption2).foregroundStyle(.secondary).textSelection(.enabled)
                    }
                    Spacer()
                    Image(systemName: "arrow.up.right").foregroundStyle(.secondary)
                }
                .padding(16).background(.blue.opacity(0.07), in: RoundedRectangle(cornerRadius: 12))
                .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(.blue.opacity(0.22), style: StrokeStyle(lineWidth: 1, dash: [5, 4])))
                .contentShape(RoundedRectangle(cornerRadius: 12))
                .onDrag {
                    do { return try installation.makeItemProvider() }
                    catch { self.installation = nil; unavailable = error.localizedDescription; return NSItemProvider() }
                }
                .accessibilityLabel("Drag Mechanize into Accessibility")
            } else {
                Label(unavailable, systemImage: "exclamationmark.triangle").font(.subheadline).foregroundStyle(.secondary)
            }
            HStack {
                Button("Open Accessibility Settings") {
                    if !NSWorkspace.shared.open(HelperInstallation.accessibilitySettingsURL) {
                        actionMessage = "Accessibility settings could not be opened. Open System Settings → Privacy & Security → Accessibility."
                    }
                }.buttonStyle(.borderedProminent)
                Button("Show in Finder") {
                    do {
                        guard let installation else { return }
                        NSWorkspace.shared.activateFileViewerSelecting([try installation.verifiedAppURL()])
                    } catch { self.installation = nil; unavailable = error.localizedDescription }
                }.disabled(installation == nil)
            }
            if let actionMessage { Text(actionMessage).font(.caption).foregroundStyle(.secondary) }
            Text("You enable this permission in macOS. Tools still need your separate approval in Mechanize.")
                .font(.caption).foregroundStyle(.secondary)
        }
        .padding(16).background(.quaternary.opacity(0.3), in: RoundedRectangle(cornerRadius: 14))
        .task { refreshInstallation() }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in refreshInstallation() }
    }
    private func refreshInstallation() {
        do { installation = try HelperInstallation.installed(); actionMessage = nil }
        catch { installation = nil; unavailable = error.localizedDescription }
    }
}
