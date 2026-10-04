import Foundation
import Security
import Darwin

public struct ConsoleEnrollmentReport: Codable {
    public let enrolled: Bool
    public let code: String
    public var exitCode: Int32 { enrolled ? 0 : 1 }
    public func json() -> Data {
        (try? JSONEncoder().encode(self)) ?? Data("{\"enrolled\":false,\"code\":\"outputUnavailable\"}".utf8)
    }
}

enum ConsoleEnrollmentError: String, Error {
    case invalidArguments, invalidConfiguration, invalidInput, existingEnrollment
    case interactionPolicyUnavailable, signatureRejected, enrollmentUnavailable
}

protocol ConsoleEnrollmentStore {
    func configure(interactive: Bool) throws
    func exists(account: String) throws -> Bool
    /// Must be create-only: a concurrent duplicate is preserved, never updated.
    func add(account: String, executable: String, credential: Data) throws
}

/// Enrollment runs in the signed console process so macOS's creator signing
/// partition matches its future credential reader. No update/delete/ACL rewrite.
public enum ConsoleOwnedEnrollment {
    public static func runCLI(arguments: [String], bundle: Bundle = .main) -> ConsoleEnrollmentReport {
        do {
            var own: SecCode?
            var requirement: SecRequirement?
            guard SecCodeCopySelf([], &own) == errSecSuccess,
                  SecRequirementCreateWithString("identifier \"com.viant.mechanize.consent\"" as CFString, [], &requirement) == errSecSuccess,
                  let own, let requirement,
                  SecCodeCheckValidity(own, SecCSFlags(rawValue: kSecCSStrictValidate), requirement) == errSecSuccess else {
                throw ConsoleEnrollmentError.signatureRejected
            }
            return try execute(arguments: arguments, bundleID: bundle.bundleIdentifier,
                               account: bundle.object(forInfoDictionaryKey: "MechanizeEnrollmentAccount") as? String,
                               uid: getuid(), executable: bundle.executableURL?.path,
                               read: { count in try FileHandle.standardInput.read(upToCount: count) ?? Data() },
                               store: KeychainConsoleEnrollmentStore())
        } catch {
            return failure(error)
        }
    }

    static func execute(arguments: [String], bundleID: String?, account: String?, uid: uid_t,
                        executable: String?, read: (Int) throws -> Data,
                        store: any ConsoleEnrollmentStore) throws -> ConsoleEnrollmentReport {
        guard arguments == ["--enroll-credential"] || arguments == ["--enroll-credential", "--interactive"] else {
            throw ConsoleEnrollmentError.invalidArguments
        }
        guard let account, let bundleID, bundleID == "com.viant.mechanize.consent",
              KeychainEnrollment.selectedAccount(trustedBundleID: bundleID, uid: uid, enrolledAccount: account) == account,
              let executable, executable.hasPrefix("/"), !executable.isEmpty else {
            throw ConsoleEnrollmentError.invalidConfiguration
        }
        let interactive = arguments.count == 2
        try store.configure(interactive: interactive)
        // Metadata-only existence check before accepting any credential bytes.
        guard try !store.exists(account: account) else { throw ConsoleEnrollmentError.existingEnrollment }
        var credential = Data()
        while credential.count <= 32768 {
            let chunk = try read(32769 - credential.count)
            if chunk.isEmpty { break }
            credential.append(chunk)
        }
        guard !credential.isEmpty, credential.count <= 32768,
              let text = String(data: credential, encoding: .utf8) else { throw ConsoleEnrollmentError.invalidInput }
        let segments = text.split(separator: ".", omittingEmptySubsequences: false)
        let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        guard segments.count == 3, segments.allSatisfy({ !$0.isEmpty && $0.allSatisfy { alphabet.contains($0) } }) else {
            throw ConsoleEnrollmentError.invalidInput
        }
        try store.add(account: account, executable: executable, credential: credential)
        return ConsoleEnrollmentReport(enrolled: true, code: "enrollmentAdded")
    }

    static func failure(_ error: Error) -> ConsoleEnrollmentReport {
        ConsoleEnrollmentReport(enrolled: false, code: (error as? ConsoleEnrollmentError)?.rawValue ?? "enrollmentUnavailable")
    }
}

private final class KeychainConsoleEnrollmentStore: ConsoleEnrollmentStore {
    private var interactive = false
    func configure(interactive: Bool) throws {
        guard SecKeychainSetUserInteractionAllowed(interactive) == errSecSuccess else {
            throw ConsoleEnrollmentError.interactionPolicyUnavailable
        }
        self.interactive = interactive
    }
    private func query(_ account: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: KeychainEnrollment.service, kSecAttrAccount as String: account,
         kSecUseAuthenticationUI as String: interactive ? kSecUseAuthenticationUIAllow : kSecUseAuthenticationUIFail]
    }
    func exists(account: String) throws -> Bool {
        let status = SecItemCopyMatching(query(account) as CFDictionary, nil)
        if status == errSecSuccess { return true }
        guard status == errSecItemNotFound else { throw ConsoleEnrollmentError.enrollmentUnavailable }
        return false
    }
    func add(account: String, executable: String, credential: Data) throws {
        var trusted: SecTrustedApplication?
        var access: SecAccess?
        guard executable.withCString({ SecTrustedApplicationCreateFromPath($0, &trusted) }) == errSecSuccess,
              let trusted,
              SecAccessCreate("Mechanize console enrollment" as CFString, [trusted] as CFArray, &access) == errSecSuccess,
              let access else { throw ConsoleEnrollmentError.enrollmentUnavailable }
        var item = query(account)
        item[kSecValueData as String] = credential
        item[kSecAttrAccess as String] = access
        item[kSecAttrLabel as String] = "Mechanize console enrollment"
        let status = SecItemAdd(item as CFDictionary, nil)
        if status == errSecDuplicateItem { throw ConsoleEnrollmentError.existingEnrollment }
        guard status == errSecSuccess else { throw ConsoleEnrollmentError.enrollmentUnavailable }
    }
}
