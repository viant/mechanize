import XCTest
@testable import ConsentCore

final class ApplicationSkillsTests: XCTestCase {
    func testOnlyExplicitApplicationMappingsEnableSkills() throws {
        let catalog = ApplicationSkillCatalog(version: 1, skills: [
            ApplicationSkill(id: "mechanize-openoffice", title: "OpenOffice", bundleIDs: ["org.openoffice.script"], documents: [
                ApplicationSkillDocument(path: "SKILL.md", title: "OpenOffice", content: "Guide")
            ])
        ])
        XCTAssertEqual(catalog.skills(for: "org.openoffice.script").count, 1)
        XCTAssertTrue(catalog.skills(for: "com.microsoft.Word").isEmpty)
        XCTAssertTrue(catalog.skills(for: "com.microsoft.Excel").isEmpty)
    }

    func testMalformedOrIncompleteCatalogDoesNotAdvertiseSkills() throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: url) }
        for contents in ["invalid", "{\"version\":2,\"skills\":[]}",
                         "{\"version\":1,\"skills\":[{\"id\":\"guide\",\"title\":\"Guide\",\"bundleIDs\":[\"com.example.App\"],\"documents\":[]}]}"] {
            try Data(contents.utf8).write(to: url)
            XCTAssertTrue(ApplicationSkillCatalog.load(from: url).skills.isEmpty)
        }
        XCTAssertTrue(ApplicationSkillCatalog.load(from: nil).skills.isEmpty)
    }
}
