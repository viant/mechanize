import Foundation
import Security
import AppKit
import UniformTypeIdentifiers
import Darwin

public enum HelperInstallationError: Error, LocalizedError {
    case unavailable, unsafePath, untrustedImage
    public var errorDescription: String? {
        switch self {
        case .unavailable: return "A trusted Mechanize installation is not available. Reinstall Mechanize to finish setup."
        case .unsafePath: return "The installed Mechanize file could not be verified. Reinstall Mechanize to finish setup."
        case .untrustedImage: return "Mechanize does not match this installation's signed identity. Reinstall Mechanize to finish setup."
        }
    }
}

/// Only the running signed console's embedded policy selects the drag recipient.
/// Verification establishes the file identity; it does not grant macOS permission.
public struct HelperInstallation {
    public static let accessibilitySettingsURL = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility")!
    public let helperURL: URL
    public let appURL: URL
    public var appOwnsAutomation: Bool { appOwnedLaunch }
    public var permissionDisplayURL: URL { appOwnedLaunch ? appURL : helperURL }
    private let appOwnedLaunch: Bool
    private let requirement: String
    private let expectedUID: uid_t
    private let directories: [URL]
    private let verify: (URL, String) throws -> Void
    private let verifyApp: (URL) throws -> Void

    public static func installed() throws -> HelperInstallation {
        guard Bundle.main.bundleIdentifier == "com.viant.mechanize.consent",
              let requirement = Bundle.main.object(forInfoDictionaryKey: "MechanizeBrokerRequirement") as? String else {
            throw HelperInstallationError.unavailable
        }
        // Authenticate the sealed metadata before it selects a runtime image.
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(Bundle.main.bundleURL as CFURL, [], &code) == errSecSuccess,
              let code, SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate | kSecCSCheckAllArchitectures), nil) == errSecSuccess else {
            throw HelperInstallationError.untrustedImage
        }
        return try resolve(appURL: Bundle.main.bundleURL, requirement: requirement, expectedUID: getuid(),
                           layout: Bundle.main.infoDictionary ?? [:])
    }

    // Internal seam for disposable filesystem/signature fixtures. Product callers
    // cannot select an arbitrary helper path or substitute a verifier.
    static func resolve(appURL: URL, requirement: String, expectedUID: uid_t, layout: [String: Any] = [:],
                        verifyApp: @escaping (URL) throws -> Void = verifyAppSignature,
                        verify: @escaping (URL, String) throws -> Void = verifySignature) throws -> HelperInstallation {
        guard appURL.isFileURL, appURL.pathExtension == "app",
              !requirement.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              !requirement.contains("\0") else { throw HelperInstallationError.unavailable }
        try validateFile(appURL, expectedUID: expectedUID, directory: true)
        let runtime = try runtimePaths(appURL: appURL, metadata: layout)
        let appOwned = layout["MechanizeHelperLaunchTransport"] != nil
        if appOwned {guard runtime.embedded,layout["MechanizeHelperLaunchTransport"] as? String=="console-v1" else{throw HelperInstallationError.unavailable}}
        let helper = runtime.broker
        if runtime.embedded {
            try validateFile(appURL.appendingPathComponent("Contents"), expectedUID: expectedUID, directory: true)
            try validateFile(appURL.appendingPathComponent("Contents/Helpers"), expectedUID: expectedUID, directory: true)
        }
        try validateFile(helper, expectedUID: expectedUID, directory: false)
        try verify(helper, requirement)
        let directories = runtime.embedded ? [appURL, appURL.appendingPathComponent("Contents"), appURL.appendingPathComponent("Contents/Helpers")] : [appURL]
        return HelperInstallation(helperURL: helper, appURL: appURL, appOwnedLaunch: appOwned, requirement: requirement, expectedUID: expectedUID, directories: directories, verify: verify, verifyApp: verifyApp)
    }

    // Closed layout: partial enrollment cannot silently select the legacy sibling.
    static func runtimePaths(appURL: URL, metadata: [String: Any]) throws -> (broker: URL, helper: URL, nativeHost: URL, embedded: Bool) {
        let paths = ["MechanizeBrokerRelativePath": "Contents/Helpers/mechanize",
                     "MechanizeHelperRelativePath": "Contents/Helpers/mechanize-native",
                     "MechanizeNativeHostRelativePath": "Contents/Helpers/mechanize-native-host"]
        let enrolled = metadata["MechanizeRuntimeLayoutVersion"] != nil || paths.keys.contains { metadata[$0] != nil }
        if !enrolled {
            let parent = appURL.deletingLastPathComponent()
            return (parent.appendingPathComponent("mechanize"), parent.appendingPathComponent("mechanize-native"), parent.appendingPathComponent("mechanize-native-host"), false)
        }
        guard let version = metadata["MechanizeRuntimeLayoutVersion"] as? NSNumber,
              CFGetTypeID(version) != CFBooleanGetTypeID(), version == 1,
              paths.allSatisfy({ metadata[$0.key] as? String == $0.value }) else {
            throw HelperInstallationError.unavailable
        }
        return (appURL.appendingPathComponent(paths["MechanizeBrokerRelativePath"]!),
                appURL.appendingPathComponent(paths["MechanizeHelperRelativePath"]!),
                appURL.appendingPathComponent(paths["MechanizeNativeHostRelativePath"]!), true)
    }

    /// Recheck at the user action, so an installation replacement cannot reuse a
    /// previously rendered drag tile's verification.
    public func verifiedURL() throws -> URL {
        for directory in directories { try Self.validateFile(directory, expectedUID: expectedUID, directory: true) }
        try Self.validateFile(helperURL, expectedUID: expectedUID, directory: false)
        try verify(helperURL, requirement)
        if appOwnedLaunch {try verifyApp(appURL);return appURL}
        return helperURL
    }

    /// Finder reveals the running app bundle, not its internal broker or a
    /// different staged installation. Permission drag targets remain separate.
    public func verifiedAppURL() throws -> URL {
        _ = try verifiedURL()
        try verifyApp(appURL)
        return appURL
    }

    private static func verifyAppSignature(_ app: URL) throws {
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(app as CFURL, [], &code) == errSecSuccess,
              let code,
              SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate | kSecCSCheckAllArchitectures), nil) == errSecSuccess else {
            throw HelperInstallationError.untrustedImage
        }
    }

    public func makeItemProvider() throws -> NSItemProvider {
        let url = try verifiedURL()
        let provider = NSItemProvider()
        provider.suggestedName = "Mechanize"
        provider.registerDataRepresentation(forTypeIdentifier: UTType.fileURL.identifier, visibility: .all) { completion in
            // A file URL to the actual signed broker, never a copy or promised file.
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
        let nativeIdentifier = "identifier \"com.viant.mechanize.broker\""
        // The manifest may add the fixed broker identifier to an ad hoc CDHash.
        // Accept only that exact conjunction; broad or OR alternatives fail.
        let stricterPin = actualString.hasPrefix("cdhash H\"") &&
            (suppliedString == nativeIdentifier + " and " + actualString || suppliedString == actualString + " and " + nativeIdentifier)
        guard actualString == suppliedString || stricterPin else { throw HelperInstallationError.untrustedImage }
    }
}
