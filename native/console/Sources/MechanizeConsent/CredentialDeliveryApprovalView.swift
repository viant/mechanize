import SwiftUI
import ConsentCore

struct CredentialDeliveryApprovalView: View {
    @ObservedObject var model: CredentialDeliveryApprovalModel
    let connected: Bool
    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            if !model.requests.isEmpty {
                Label("Sign-in requests", systemImage: "key.horizontal").font(.headline)
                Text("Choose a saved credential. Its values stay on this Mac.").font(.caption).foregroundStyle(.secondary)
                ForEach(model.requests) { request in
                    CredentialRequestCard(model: model, request: request, connected: connected)
                }
            }
            if !model.message.isEmpty { Text(model.message).font(.caption).foregroundStyle(.secondary) }
        }
    }
}
private struct CredentialRequestCard: View {
    @ObservedObject var model: CredentialDeliveryApprovalModel
    let request: NativeCredentialRequest
    let connected: Bool
    @State private var selected = ""
    private var record: VaultRecordMetadata? { model.records.first { $0.id == selected } }
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(request.origin).font(.headline)
            Text(request.purpose).font(.callout)
            Picker("Saved credential", selection: $selected) {
                Text("Select from Vault").tag("")
                ForEach(model.records, id: \.id) { record in
                    Text("Credential · \(record.id.suffix(8))").tag(record.id)
                }
            }
            Text("Credential IDs match the Vault list. The selected record must contain username and password fields.").font(.caption).foregroundStyle(.secondary)
            HStack {
                Button("Approve credential use") {
                    if let record { Task { await model.bind(request, record: record) } }
                }.buttonStyle(.borderedProminent).tint(Color(red: 0.78, green: 0.08, blue: 0.12))
                    .disabled(!connected || !model.canBind(request, record: record))
                Button("Refresh") { Task { await model.refresh() } }.disabled(model.busy || !connected)
                Button("Cancel", role: .destructive) { Task { await model.cancel(request) } }.disabled(model.busy || !connected)
            }
            Text("Request expires \(request.expiresAt.formatted(date: .omitted, time: .shortened))").font(.caption).foregroundStyle(.secondary)
        }.padding(12).frame(maxWidth: .infinity, alignment: .leading)
            .background(.background, in: RoundedRectangle(cornerRadius: 10))
    }
}
