// Development-only enrollment. Secret bytes arrive on stdin, never argv or logs.
import Foundation
import Security
import Darwin

func stop(_ message: String, _ code: Int32 = 1) -> Never {
    fputs(message + "\n", stderr); exit(code)
}
var enrollmentArguments = CommandLine.arguments
let interactive = enrollmentArguments.count > 1 && enrollmentArguments[1] == "--interactive"
if interactive { enrollmentArguments.remove(at:1) }
guard enrollmentArguments.count == 3 || enrollmentArguments.count == 4 else { stop("usage: enroll-console [--interactive] <installed-app-path> <designated-requirement> [enrolled-account]") }
let legacyAccount = "com.viant.mechanize.consent:\(getuid())"
let account: String
if enrollmentArguments.count == 4 {
    let candidate = enrollmentArguments[3]
    let prefix = legacyAccount + ":"
    let suffix = candidate.hasPrefix(prefix) ? String(candidate.dropFirst(prefix.count)) : ""
    guard suffix.count == 32, suffix.allSatisfy({ "0123456789abcdef".contains($0) }) else {
        stop("Enrollment account must use the fixed console/current-UID prefix and a fresh 32-character lowercase hex suffix")
    }
    account = candidate
} else { account = legacyAccount }
guard SecKeychainSetUserInteractionAllowed(interactive) == errSecSuccess else { stop("Cannot configure Keychain interaction") }
let app = URL(fileURLWithPath: enrollmentArguments[1])
var requirement: SecRequirement?
var code: SecStaticCode?
guard SecRequirementCreateWithString(enrollmentArguments[2] as CFString, [], &requirement) == errSecSuccess,
      SecStaticCodeCreateWithPath(app as CFURL, [], &code) == errSecSuccess,
      let code, let requirement,
      SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate), requirement) == errSecSuccess else { stop("Installed console signature rejected") }
if enrollmentArguments.count == 4 {
    guard let bundle = Bundle(url: app), bundle.bundleIdentifier == "com.viant.mechanize.consent",
          bundle.object(forInfoDictionaryKey: "MechanizeEnrollmentAccount") as? String == account else {
        stop("Enrollment account differs from the installed console's signed configuration")
    }
}
let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: "com.viant.mechanize.console.enrollment", kSecAttrAccount as String: account,
    kSecUseAuthenticationUI as String: interactive ? kSecUseAuthenticationUIAllow : kSecUseAuthenticationUIFail]
let existing = SecItemCopyMatching(query as CFDictionary, nil)
guard existing == errSecItemNotFound else {
    if existing == errSecSuccess { stop("Existing enrollment preserved; no update attempted", 2) }
    stop("Enrollment lookup unavailable without interaction (OSStatus \(existing)); no update attempted", 3)
}
let token = FileHandle.standardInput.readDataToEndOfFile()
guard !token.isEmpty, token.count <= 32768, let text = String(data: token, encoding: .utf8), text.split(separator: ".").count == 3 else { stop("Invalid enrollment input") }
var trusted: SecTrustedApplication?
let executable = app.appendingPathComponent("Contents/MacOS/MechanizeConsent").path
let trustStatus = executable.withCString { SecTrustedApplicationCreateFromPath($0, &trusted) }
guard trustStatus == errSecSuccess, let trusted else { stop("Cannot constrain enrollment access to installed console") }
var access: SecAccess?
guard SecAccessCreate("Mechanize development console enrollment" as CFString, [trusted] as CFArray, &access) == errSecSuccess,
      let access else { stop("Cannot create restricted console access") }
// SecAccessCreate's explicit application list avoids the default creating-process ACL.
// No SecItemUpdate, deletion, universal trust, or partition-list broadening is used.
var item = query
item[kSecValueData as String] = token
item[kSecAttrAccess as String] = access
item[kSecAttrLabel as String] = "Mechanize development console enrollment"
let status = SecItemAdd(item as CFDictionary, nil)
guard status == errSecSuccess else {
    if status == errSecDuplicateItem { stop("Concurrent existing enrollment preserved", 2) }
    stop("Enrollment unavailable without interaction (OSStatus \(status)); no update attempted", 3)
}
print("Enrollment added with installed-console-only trusted application ACL")
