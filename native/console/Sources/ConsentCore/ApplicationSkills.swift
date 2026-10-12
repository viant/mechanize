import Foundation

public struct ApplicationSkillDocument: Codable, Identifiable, Equatable {
    public let path: String
    public let title: String
    public let content: String
    public var id: String { path }
}

public struct ApplicationSkill: Codable, Identifiable, Equatable {
    public let id: String
    public let title: String
    public let bundleIDs: [String]
    public let documents: [ApplicationSkillDocument]
}

public struct ApplicationSkillCatalog: Codable {
    public let version: Int
    public let skills: [ApplicationSkill]
    public static let empty = ApplicationSkillCatalog(version: 1, skills: [])

    public static func load(from url: URL?) -> ApplicationSkillCatalog {
        guard let url, let data = try? Data(contentsOf: url), data.count <= 2 * 1024 * 1024,
              let catalog = try? JSONDecoder().decode(Self.self, from: data), catalog.version == 1,
              Set(catalog.skills.map(\.id)).count == catalog.skills.count,
              catalog.skills.allSatisfy({ !$0.id.isEmpty && !$0.bundleIDs.isEmpty &&
                  !$0.documents.isEmpty && $0.documents.contains(where: { $0.path == "SKILL.md" }) &&
                  Set($0.documents.map(\.path)).count == $0.documents.count }) else { return .empty }
        return catalog
    }

    public func skills(for bundleID: String) -> [ApplicationSkill] {
        skills.filter { $0.bundleIDs.contains(bundleID) }
    }
}
