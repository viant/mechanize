import SwiftUI
import AppKit
import ConsentCore

struct ApplicationAccessListRow: Identifiable {
    let bundleID: String
    let displayName: String
    let modes: [ConsentMode]
    let enabled: Bool
    let source: String
    var installedURL: URL? = nil
    var id: String { bundleID }
}

struct ApplicationAccessListView: View {
    let rows: [ApplicationAccessListRow]
    let connected: Bool
    let policyAvailable: Bool
    let busy: Bool
    let message: String
    let onToggle: (ApplicationAccessListRow, Bool) -> Void
    @State private var query = ""
    @State private var page = 0
    @StateObject private var launcher = ApplicationLauncher()
    private let pageSize = 20

    private var filteredRows: [ApplicationAccessListRow] {
        let needle = query.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !needle.isEmpty else { return rows }
        return rows.filter { $0.displayName.localizedCaseInsensitiveContains(needle) || $0.bundleID.localizedCaseInsensitiveContains(needle) }
    }
    private var pageCount: Int { max(1, (filteredRows.count + pageSize - 1) / pageSize) }
    private var visibleRows: [ApplicationAccessListRow] {
        let start = min(page * pageSize, max(0, filteredRows.count - 1))
        return Array(filteredRows.dropFirst(start).prefix(pageSize))
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Installed applications").font(.title2.weight(.semibold))
            Text("Switching an application on updates Mechanize's confirmed access policy. It does not grant consent for a pending tool request or change macOS permissions.")
                .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            if !message.isEmpty {
                Label(message, systemImage: policyAvailable ? "info.circle" : "exclamationmark.triangle")
                    .font(.callout).foregroundStyle(policyAvailable ? Color.secondary : Color.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }
            TextField("Search applications", text: $query)
                .textFieldStyle(.roundedBorder).accessibilityLabel("Search installed applications by name or bundle ID")
                .accessibilityIdentifier("applications.search")
            if !launcher.message.isEmpty {
                Label(launcher.message, systemImage: launcher.lastLaunchSucceeded ? "checkmark.circle" : "exclamationmark.triangle")
                    .font(.callout).foregroundStyle(launcher.lastLaunchSucceeded ? Color.secondary : Color.orange)
                    .fixedSize(horizontal: false, vertical: true)
                    .accessibilityIdentifier("applications.launchStatus")
            }
            if filteredRows.isEmpty {
                ContentUnavailableView("No applications found", systemImage: "app.dashed",
                                       description: Text(query.isEmpty ? "Mechanize scans Applications folders for app metadata." : "Try another application name or bundle ID."))
                    .frame(maxWidth: .infinity, minHeight: 140)
            } else {
                VStack(spacing: 0) {
                    ForEach(visibleRows) { row in
                        HStack(spacing: 12) {
                            Button {
                                guard let url = row.installedURL else { return }
                                Task { await launcher.open(url: url, expectedBundleID: row.bundleID) }
                            } label: {
                                HStack(spacing: 9) {
                                    if let url = row.installedURL {
                                        Image(nsImage: NSWorkspace.shared.icon(forFile: url.path))
                                            .resizable().frame(width: 24, height: 24).accessibilityHidden(true)
                                    } else {
                                        Image(systemName: "app.fill").foregroundStyle(.secondary).accessibilityHidden(true)
                                    }
                                    Text(row.displayName).font(.headline)
                                }
                            }
                            .buttonStyle(.plain)
                            .help("Open")
                            .accessibilityLabel(row.installedURL == nil ? "\(row.displayName), unavailable" : "Open \(row.displayName)")
                            .accessibilityIdentifier("applications.open.\(row.bundleID)")
                            .disabled(row.installedURL == nil || launcher.isLaunching)
                            VStack(alignment: .leading, spacing: 3) {
                                Text(row.bundleID).font(.caption.monospaced()).foregroundStyle(.secondary).textSelection(.enabled)
                                Text(row.enabled && !row.modes.isEmpty ? "Allowed · \(modeLabels(row.modes))" : row.source)
                                    .font(.caption).foregroundStyle(.secondary)
                            }
                            Spacer(minLength: 8)
                            Toggle("Allow \(row.displayName)", isOn: Binding(
                                get: { row.enabled }, set: { onToggle(row, $0) }
                            )).labelsHidden().accessibilityLabel("Allow \(row.displayName)")
                                .fixedSize()
                                .padding(.trailing, 4)
                                .accessibilityIdentifier("applications.allow.\(row.bundleID)")
                                .disabled(!connected || !policyAvailable || busy)
                        }.padding(.vertical, 8)
                        if row.id != visibleRows.last?.id { Divider() }
                    }
                }
                HStack {
                    Text("\(filteredRows.count) applications · Page \(page + 1) of \(pageCount)").font(.caption).foregroundStyle(.secondary)
                        .accessibilityIdentifier("applications.pageStatus")
                    Spacer()
                    Button("Previous") { page = max(0, page - 1) }.accessibilityIdentifier("applications.previousPage").disabled(page == 0)
                    Button("Next") { page = min(pageCount - 1, page + 1) }.accessibilityIdentifier("applications.nextPage").disabled(page + 1 >= pageCount)
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .onChange(of: query) { _, _ in page = 0 }
        .onChange(of: rows.map(\.id)) { _, _ in page = min(page, max(0, (filteredRows.count - 1) / pageSize)) }
    }

    private func modeLabels(_ modes: [ConsentMode]) -> String {
        modes.map { mode in
            switch mode { case .observe: "View"; case .control: "Control"; case .record: "Record" }
        }.joined(separator: ", ")
    }
}
