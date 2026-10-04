import XCTest
import Foundation
import UniformTypeIdentifiers
import Darwin
import Security
@testable import ConsentCore

final class HelperInstallationTests: XCTestCase {
    private func fixture() throws -> (URL, URL) {
        let temporary = FileManager.default.temporaryDirectory.appendingPathComponent("mechanize-setup-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: temporary, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let canonical = temporary.path.withCString { realpath($0, nil) }!
        let directory = URL(fileURLWithPath: String(cString: canonical), isDirectory: true); free(canonical)
        addTeardownBlock { try? FileManager.default.removeItem(at: directory) }
        let app = directory.appendingPathComponent("Mechanize Permissions.app", isDirectory: true)
        try FileManager.default.createDirectory(at: app, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let helper = directory.appendingPathComponent("mechanize-native")
        try Data("inert fixture".utf8).write(to: helper)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: helper.path)
        return (app, helper)
    }
    func testSiblingResolutionAndEmbeddedPolicyAreExact() throws {
        let (app, helper) = try fixture()
        var verificationCount = 0
        let installed = try HelperInstallation.resolve(appURL: app, requirement: "pinned fixture", expectedUID: getuid()) { url, requirement in
            XCTAssertEqual(url, helper); XCTAssertEqual(requirement, "pinned fixture"); verificationCount += 1
        }
        XCTAssertEqual(installed.helperURL, helper)
        XCTAssertEqual(try installed.verifiedURL(), helper)
        XCTAssertEqual(verificationCount, 2)
    }
    func testMissingUntrustedAndUnsafeHelpersHaveNoInstallation() throws {
        let (app, helper) = try fixture()
        XCTAssertThrowsError(try HelperInstallation.resolve(appURL: app, requirement: "", expectedUID: getuid(), verify: { _, _ in XCTFail("Missing policy reached signature verification") }))
        XCTAssertThrowsError(try HelperInstallation.resolve(appURL: app, requirement: "pin", expectedUID: getuid(), verify: { _, _ in throw HelperInstallationError.untrustedImage }))
        try FileManager.default.setAttributes([.posixPermissions: 0o720], ofItemAtPath: helper.path)
        XCTAssertThrowsError(try HelperInstallation.resolve(appURL: app, requirement: "pin", expectedUID: getuid(), verify: { _, _ in XCTFail("Writable file reached signature verification") }))
        try FileManager.default.removeItem(at: helper)
        XCTAssertThrowsError(try HelperInstallation.resolve(appURL: app, requirement: "pin", expectedUID: getuid(), verify: { _, _ in XCTFail("Missing file reached signature verification") }))
    }
    func testSymlinkHardlinkAndNonExecutableDenied() throws {
        let (app, helper) = try fixture()
        let original = helper.deletingLastPathComponent().appendingPathComponent("original")
        try FileManager.default.moveItem(at: helper, to: original)
        try FileManager.default.createSymbolicLink(at: helper, withDestinationURL: original)
        XCTAssertThrowsError(try HelperInstallation.resolve(appURL: app, requirement: "pin", expectedUID: getuid(), verify: { _, _ in XCTFail("Symlink accepted") }))
        try FileManager.default.removeItem(at: helper)
        try FileManager.default.linkItem(at: original, to: helper)
        XCTAssertThrowsError(try HelperInstallation.resolve(appURL: app, requirement: "pin", expectedUID: getuid(), verify: { _, _ in XCTFail("Hardlink accepted") }))
        try FileManager.default.removeItem(at: original)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: helper.path)
        XCTAssertThrowsError(try HelperInstallation.resolve(appURL: app, requirement: "pin", expectedUID: getuid(), verify: { _, _ in XCTFail("Nonexecutable accepted") }))
    }
    func testProviderExportsRealHelperFileURLAndRechecksAtDrag() throws {
        let (app, helper) = try fixture()
        var checks = 0
        let installed = try HelperInstallation.resolve(appURL: app, requirement: "pin", expectedUID: getuid()) { _, _ in checks += 1 }
        let provider = try installed.makeItemProvider()
        XCTAssertEqual(checks, 2)
        XCTAssertTrue(provider.hasItemConformingToTypeIdentifier(UTType.fileURL.identifier))
        let loaded = expectation(description: "actual helper URL")
        provider.loadDataRepresentation(forTypeIdentifier: UTType.fileURL.identifier) { data, error in
            XCTAssertNil(error)
            XCTAssertEqual(data.flatMap { URL(dataRepresentation: $0, relativeTo: nil) }, helper)
            loaded.fulfill()
        }
        wait(for: [loaded], timeout: 2)
        try FileManager.default.setAttributes([.posixPermissions: 0o722], ofItemAtPath: helper.path)
        XCTAssertThrowsError(try installed.makeItemProvider())
        XCTAssertEqual(checks, 2, "Unsafe replacement must fail before signature verification")
    }
    func testUnsignedBinaryAndBroadRequirementAreRejectedBySecurity() throws {
        let (app, _) = try fixture()
        XCTAssertThrowsError(try HelperInstallation.resolve(appURL: app, requirement: "true", expectedUID: getuid()))
    }
    func testSignedImageAcceptsOnlyItsExactDesignatedRequirement() throws {
        let (app, helper) = try fixture()
        try FileManager.default.removeItem(at: helper)
        // Copy an inert signed system executable; never execute it or ask for TCC.
        try FileManager.default.copyItem(at: URL(fileURLWithPath: "/usr/bin/true"), to: helper)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: helper.path)
        var code: SecStaticCode?; var requirement: SecRequirement?; var text: CFString?
        XCTAssertEqual(SecStaticCodeCreateWithPath(helper as CFURL, [], &code), errSecSuccess)
        XCTAssertEqual(SecCodeCopyDesignatedRequirement(try XCTUnwrap(code), [], &requirement), errSecSuccess)
        XCTAssertEqual(SecRequirementCopyString(try XCTUnwrap(requirement), [], &text), errSecSuccess)
        let installed = try HelperInstallation.resolve(appURL: app, requirement: try XCTUnwrap(text) as String, expectedUID: getuid())
        XCTAssertEqual(try installed.verifiedURL(), helper)
        XCTAssertThrowsError(try HelperInstallation.resolve(appURL: app, requirement: "true", expectedUID: getuid()))
        XCTAssertThrowsError(try HelperInstallation.resolve(appURL: app, requirement: "identifier \"com.unenrolled\"", expectedUID: getuid()))
    }
    func testFixedNativeIdentifierAndExactHashConjunction() throws {
        let (app, helper) = try fixture()
        try FileManager.default.removeItem(at: helper)
        try FileManager.default.copyItem(at: URL(fileURLWithPath: "/usr/bin/true"), to: helper)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: helper.path)
        let signer = Process(); signer.executableURL = URL(fileURLWithPath: "/usr/bin/codesign")
        signer.arguments = ["--force", "--sign", "-", "--identifier", "com.viant.mechanize.native", helper.path]
        signer.standardOutput = Pipe(); signer.standardError = Pipe()
        try signer.run(); signer.waitUntilExit(); XCTAssertEqual(signer.terminationStatus, 0)
        var code: SecStaticCode?; var requirement: SecRequirement?; var text: CFString?
        XCTAssertEqual(SecStaticCodeCreateWithPath(helper as CFURL, [], &code), errSecSuccess)
        XCTAssertEqual(SecCodeCopyDesignatedRequirement(try XCTUnwrap(code), [], &requirement), errSecSuccess)
        XCTAssertEqual(SecRequirementCopyString(try XCTUnwrap(requirement), [], &text), errSecSuccess)
        let actual = try XCTUnwrap(text) as String
        let strict = "identifier \"com.viant.mechanize.native\" and " + actual
        XCTAssertNoThrow(try HelperInstallation.resolve(appURL: app, requirement: strict, expectedUID: getuid()))
        XCTAssertNoThrow(try HelperInstallation.resolve(appURL: app, requirement: actual, expectedUID: getuid()))
        XCTAssertThrowsError(try HelperInstallation.resolve(appURL: app, requirement: "true", expectedUID: getuid()))
        XCTAssertThrowsError(try HelperInstallation.resolve(appURL: app, requirement: strict + " or true", expectedUID: getuid()))
        XCTAssertThrowsError(try HelperInstallation.resolve(appURL: app, requirement: "identifier \"com.other\" and " + actual, expectedUID: getuid()))
    }
    func testSettingsURLIsFixedAccessibilityPane() {
        XCTAssertEqual(HelperInstallation.accessibilitySettingsURL.absoluteString, "x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility")
    }
}
