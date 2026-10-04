import Foundation
import Security
import AppKit
import UniformTypeIdentifiers
import Darwin

public enum HelperInstallationError: Error, LocalizedError {
    case unavailable, unsafePath, untrustedImage
    public var errorDescription: String? {
        switch self {
        case .unavailable: return "A trusted Mechanize Native installation is not available. Reinstall Mechanize to finish setup."
        case .unsafePath: return "The installed Mechanize Native file could not be verified. Reinstall Mechanize to finish setup."
        case .untrustedImage: return "Mechanize Native does not match this installation's signed identity. Reinstall Mechanize to finish setup."
        }
    }
}

/// Only the running signed console's embedded policy selects the drag recipient.
/// Verification establishes the file identity; it does not grant macOS permission.
public struct HelperInstallation {
    public static let accessibilitySettingsURL = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility")!
    public let helperURL: URL
    private let requirement: String
    private let expectedUID: uid_t
    private let verify: (URL, String) throws -> Void

    public static func installed() throws -> HelperInstallation {
        guard Bundle.main.bundleIdentifier == "com.viant.mechanize.consent",
              let requirement = Bundle.main.object(forInfoDictionaryKey: "MechanizeHelperRequirement") as? String else {
            throw HelperInstallationError.unavailable
        }
        return try resolve(appURL: Bundle.main.bundleURL, requirement: requirement, expectedUID: getuid())
    }

    // Internal seam for disposable filesystem/signature fixtures. Product callers
    // cannot select an arbitrary helper path or substitute a verifier.
    static func resolve(appURL: URL, requirement: String, expectedUID: uid_t,
                        verify: @escaping (URL, String) throws -> Void = verifySignature) throws -> HelperInstallation {
        guard appURL.isFileURL, appURL.pathExtension == "app",
              !requirement.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              !requirement.contains("\0") else { throw HelperInstallationError.unavailable }
        try validateFile(appURL, expectedUID: expectedUID, directory: true)
        let helper = appURL.deletingLastPathComponent().appendingPathComponent("mechanize-native", isDirectory: false)
        try validateFile(helper, expectedUID: expectedUID, directory: false)
        try verify(helper, requirement)
        return HelperInstallation(helperURL: helper, requirement: requirement, expectedUID: expectedUID, verify: verify)
    }

    /// Recheck at the user action, so an installation replacement cannot reuse a
    /// previously rendered drag tile's verification.
    public func verifiedURL() throws -> URL {
        try Self.validateFile(helperURL, expectedUID: expectedUID, directory: false)
        try verify(helperURL, requirement)
        return helperURL
    }

    public func makeItemProvider() throws -> NSItemProvider {
        let url = try verifiedURL()
        let provider = NSItemProvider()
        provider.suggestedName = "Mechanize Native"
        provider.registerDataRepresentation(forTypeIdentifier: UTType.fileURL.identifier, visibility: .all) { completion in
            // A file URL to the actual signed helper, never a copy or promised file.
            completion(url.dataRepresentation, nil)
            return nil
        }
        return provider
    }

    private static func validateFile(_ url: URL, expectedUID: uid_t, directory: Bool) throws {
        let path = url.path
        guard url.isFileURL, path.hasPrefix("/"), let canonical = path.withCString({ realpath($0, nil) }) else {
            throw HelperInstallationError.unsafePath
        }
        defer { free(canonical) }
        guard String(cString: canonical) == path else { throw HelperInstallationError.unsafePath }
        var info = stat()
        guard lstat(path, &info) == 0,
              info.st_uid == expectedUID || info.st_uid == 0,
              info.st_mode & 0o022 == 0 else { throw HelperInstallationError.unsafePath }
        if directory {
            guard info.st_mode & S_IFMT == S_IFDIR else { throw HelperInstallationError.unsafePath }
        } else {
            guard info.st_mode & S_IFMT == S_IFREG, info.st_nlink == 1, info.st_mode & 0o111 != 0 else {
                throw HelperInstallationError.unsafePath
            }
        }
    }

    private static func verifySignature(_ helper: URL, _ text: String) throws {
        var requirement: SecRequirement?
        var code: SecStaticCode?
        guard SecRequirementCreateWithString(text as CFString, [], &requirement) == errSecSuccess,
              SecStaticCodeCreateWithPath(helper as CFURL, [], &code) == errSecSuccess,
              let requirement, let code,
              SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate | kSecCSCheckAllArchitectures), requirement) == errSecSuccess else {
            throw HelperInstallationError.untrustedImage
        }
        var actual: SecRequirement?
        var actualText: CFString?; var suppliedText: CFString?
        guard SecCodeCopyDesignatedRequirement(code, [], &actual) == errSecSuccess, let actual,
              SecRequirementCopyString(actual, [], &actualText) == errSecSuccess,
              SecRequirementCopyString(requirement, [], &suppliedText) == errSecSuccess,
              let actualText, let suppliedText else {
            throw HelperInstallationError.untrustedImage
        }
        let actualString = actualText as String
        let suppliedString = suppliedText as String
        let nativeIdentifier = "identifier \"com.viant.mechanize.native\""
        // The manifest may add the fixed helper identifier to an ad hoc CDHash.
        // Accept only that exact conjunction; broad or OR alternatives fail.
        let stricterPin = actualString.hasPrefix("cdhash H\"") &&
            (suppliedString == nativeIdentifier + " and " + actualString || suppliedString == actualString + " and " + nativeIdentifier)
        guard actualString == suppliedString || stricterPin else { throw HelperInstallationError.untrustedImage }
    }
}
