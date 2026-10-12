import SwiftUI
import ConsentCore

/// Public guides are part of the signed console, so viewing them needs no grant.
enum ConsoleSkills {
    static let catalog = ApplicationSkillCatalog.load(from: Bundle.main.url(forResource: "ApplicationSkills", withExtension: "json"))
}

struct ApplicationSkillsView: View {
    let bundleID: String
    @State private var selectedDocument: String?
    private var skills: [ApplicationSkill] { ConsoleSkills.catalog.skills(for: bundleID) }
    private var documents: [(id: String, title: String, document: ApplicationSkillDocument)] {
        skills.flatMap { skill in
            skill.documents.map { (skill.id + "/" + $0.path, skill.title, $0) }
        }
    }
    private var current: ApplicationSkillDocument? {
        documents.first(where: { $0.id == selectedDocument })?.document ?? documents.first?.document
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            VStack(alignment: .leading, spacing: 5) {
                Text("Application skills").font(.title2.bold())
                Text(bundleID).font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
                Text("Defined guidance; see each guide for its supported scope and verification status.")
                    .font(.callout).foregroundStyle(.secondary)
            }.padding()
            Divider()
            if let current {
                HSplitView {
                    List(selection: $selectedDocument) {
                        ForEach(documents, id: \.id) { entry in
                            VStack(alignment: .leading, spacing: 3) {
                                Text(entry.document.title)
                                Text(entry.title).font(.caption).foregroundStyle(.secondary)
                            }.tag(entry.id)
                        }
                    }.frame(minWidth: 180, idealWidth: 220, maxWidth: 280)
                    ScrollView {
                        VStack(alignment: .leading, spacing: 12) {
                            Text(current.title).font(.title2.bold())
                            Text((try? AttributedString(markdown: current.content,
                                options: .init(interpretedSyntax: .inlineOnlyPreservingWhitespace))) ?? AttributedString(current.content))
                                .textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading)
                        }.padding(20)
                    }.frame(minWidth: 340)
                }
            } else {
                ContentUnavailableView("No skills defined", systemImage: "book.closed",
                    description: Text("This application has no bundled skill guide yet."))
            }
        }
        .frame(minWidth: 640, minHeight: 400)
        .onChange(of: bundleID) { _, _ in selectedDocument = nil }
    }
}
