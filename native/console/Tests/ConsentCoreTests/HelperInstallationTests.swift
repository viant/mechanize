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
        let helper = directory.appendingPathComponent("mechanize")
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
    func testFixedBrokerIdentifierAndExactHashConjunction() throws {
        let (app, helper) = try fixture()
        try FileManager.default.removeItem(at: helper)
        try FileManager.default.copyItem(at: URL(fileURLWithPath: "/usr/bin/true"), to: helper)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: helper.path)
        let signer = Process(); signer.executableURL = URL(fileURLWithPath: "/usr/bin/codesign")
        signer.arguments = ["--force", "--sign", "-", "--identifier", "com.viant.mechanize.broker", helper.path]
        signer.standardOutput = Pipe(); signer.standardError = Pipe()
        try signer.run(); signer.waitUntilExit(); XCTAssertEqual(signer.terminationStatus, 0)
        var code: SecStaticCode?; var requirement: SecRequirement?; var text: CFString?
        XCTAssertEqual(SecStaticCodeCreateWithPath(helper as CFURL, [], &code), errSecSuccess)
        XCTAssertEqual(SecCodeCopyDesignatedRequirement(try XCTUnwrap(code), [], &requirement), errSecSuccess)
        XCTAssertEqual(SecRequirementCopyString(try XCTUnwrap(requirement), [], &text), errSecSuccess)
        let actual = try XCTUnwrap(text) as String
        let strict = "identifier \"com.viant.mechanize.broker\" and " + actual
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

extension HelperInstallationTests {
    func testCertificateDesignatedRequirementAcceptsOnlyVerifiedExactBrokerPin() {
        let actual = "identifier \"com.viant.mechanize.broker\" and certificate leaf = H\"" + String(repeating: "1", count: 40) + "\""
        let hash = "cdhash H\"" + String(repeating: "a", count: 40) + "\""
        let pin = "identifier \"com.viant.mechanize.broker\" and " + hash
        XCTAssertTrue(HelperInstallation.acceptsVerifiedRequirement(actual: actual, supplied: actual))
        XCTAssertTrue(HelperInstallation.acceptsVerifiedRequirement(actual: actual, supplied: pin))
        XCTAssertTrue(HelperInstallation.acceptsVerifiedRequirement(actual: actual, supplied: hash + " and identifier \"com.viant.mechanize.broker\""))
        for invalid in ["true", hash, pin + " or true", pin.replacingOccurrences(of: "broker", with: "other"), pin + "\ntrue"] {
            XCTAssertFalse(HelperInstallation.acceptsVerifiedRequirement(actual: actual, supplied: invalid))
        }
    }
    func testFinderRevealsAppBundleAndRechecksItAtClickTime() throws {
        let (app, helper) = try fixture()
        var trusted = true
        var appChecks = 0
        let installation = try HelperInstallation.resolve(appURL: app, requirement: "pin", expectedUID: getuid(),
            verifyApp: { url in
                XCTAssertEqual(url, app)
                appChecks += 1
                if !trusted { throw HelperInstallationError.untrustedImage }
            }, verify: { url, _ in XCTAssertEqual(url, helper) })
        XCTAssertEqual(try installation.verifiedAppURL(), app)
        XCTAssertEqual(try installation.verifiedURL(), helper)
        trusted = false
        XCTAssertThrowsError(try installation.verifiedAppURL())
        XCTAssertEqual(appChecks, 2)
    }
    func testConsoleOwnedModeDragsAppAndLegacyStillUsesBroker() throws {
        let (app,sibling)=try fixture(),helpers=app.appendingPathComponent("Contents/Helpers")
        try FileManager.default.createDirectory(at:helpers,withIntermediateDirectories:true,attributes:[.posixPermissions:0o700])
        try FileManager.default.copyItem(at:sibling,to:helpers.appendingPathComponent("mechanize"))
        var metadata:[String:Any]=["MechanizeRuntimeLayoutVersion":1,"MechanizeBrokerRelativePath":"Contents/Helpers/mechanize","MechanizeHelperRelativePath":"Contents/Helpers/mechanize-native","MechanizeNativeHostRelativePath":"Contents/Helpers/mechanize-native-host","MechanizeHelperLaunchTransport":"console-v1"]
        var appChecks=0
        let installed=try HelperInstallation.resolve(appURL:app,requirement:"pin",expectedUID:getuid(),layout:metadata,verifyApp:{url in XCTAssertEqual(url,app);appChecks+=1},verify:{_,_ in})
        XCTAssertTrue(installed.appOwnsAutomation);XCTAssertEqual(try installed.verifiedURL(),app);XCTAssertEqual(installed.permissionDisplayURL,app);XCTAssertEqual(appChecks,1)
        metadata["MechanizeHelperLaunchTransport"]="unknown"
        XCTAssertThrowsError(try HelperInstallation.resolve(appURL:app,requirement:"pin",expectedUID:getuid(),layout:metadata,verifyApp:{_ in},verify:{_,_ in}))
    }
    func testEmbeddedBrokerRevalidatesDirectoriesWithoutSiblingFallback() throws {
        let (app, sibling) = try fixture()
        let contents = app.appendingPathComponent("Contents")
        let helpers = contents.appendingPathComponent("Helpers")
        try FileManager.default.createDirectory(at: helpers, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let embedded = helpers.appendingPathComponent("mechanize")
        try FileManager.default.copyItem(at: sibling, to: embedded)
        let metadata: [String: Any] = ["MechanizeRuntimeLayoutVersion": 1,
            "MechanizeBrokerRelativePath": "Contents/Helpers/mechanize",
            "MechanizeHelperRelativePath": "Contents/Helpers/mechanize-native",
            "MechanizeNativeHostRelativePath": "Contents/Helpers/mechanize-native-host"]
        let installation = try HelperInstallation.resolve(appURL: app, requirement: "pin", expectedUID: getuid(), layout: metadata) { url, _ in XCTAssertEqual(url, embedded) }
        XCTAssertEqual(try installation.verifiedURL(), embedded)
        try FileManager.default.setAttributes([.posixPermissions: 0o722], ofItemAtPath: helpers.path)
        XCTAssertThrowsError(try installation.verifiedURL())
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: helpers.path)
        try FileManager.default.removeItem(at: embedded)
        XCTAssertThrowsError(try HelperInstallation.resolve(appURL: app, requirement: "pin", expectedUID: getuid(), layout: metadata, verify: { _, _ in XCTFail("must not fall back to existing sibling") }))
    }
    func testClosedEmbeddedRuntimeLayoutAndLegacyCompatibility() throws {
        let app = URL(fileURLWithPath: "/fixture/Mechanize.app")
        let metadata: [String: Any] = ["MechanizeRuntimeLayoutVersion": 1,
            "MechanizeBrokerRelativePath": "Contents/Helpers/mechanize",
            "MechanizeHelperRelativePath": "Contents/Helpers/mechanize-native",
            "MechanizeNativeHostRelativePath": "Contents/Helpers/mechanize-native-host"]
        let paths = try HelperInstallation.runtimePaths(appURL: app, metadata: metadata)
        XCTAssertTrue(paths.embedded)
        XCTAssertEqual(paths.broker.path, "/fixture/Mechanize.app/Contents/Helpers/mechanize")
        XCTAssertEqual(paths.helper.lastPathComponent, "mechanize-native")
        XCTAssertEqual(paths.nativeHost.lastPathComponent, "mechanize-native-host")
        XCTAssertFalse(try HelperInstallation.runtimePaths(appURL: app, metadata: [:]).embedded)
        for key in metadata.keys {
            var incomplete = metadata; incomplete.removeValue(forKey: key)
            XCTAssertThrowsError(try HelperInstallation.runtimePaths(appURL: app, metadata: incomplete))
        }
        for bad: Any in [true, 2, "1", 1.5] {
            var malformed = metadata; malformed["MechanizeRuntimeLayoutVersion"] = bad
            XCTAssertThrowsError(try HelperInstallation.runtimePaths(appURL: app, metadata: malformed))
        }
        for bad in ["../mechanize", "/tmp/mechanize", "Contents/Helpers/../mechanize", "Contents/Helpers/other"] {
            var malformed = metadata; malformed["MechanizeBrokerRelativePath"] = bad
            XCTAssertThrowsError(try HelperInstallation.runtimePaths(appURL: app, metadata: malformed))
        }
    }
}
