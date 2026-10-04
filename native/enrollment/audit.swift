// Read access metadata only. Never requests kSecReturnData or credentials.
import Foundation
import Security
import Darwin
func stop(_ message: String) -> Never { fputs(message + "\n", stderr); exit(1) }
guard SecKeychainSetUserInteractionAllowed(false) == errSecSuccess else { stop("Cannot disable interaction") }
let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: "com.viant.mechanize.console.enrollment",
    kSecAttrAccount as String: "com.viant.mechanize.consent:\(getuid())",
    kSecReturnRef as String: true, kSecUseAuthenticationUI as String: kSecUseAuthenticationUIFail]
var result: CFTypeRef?
let status = SecItemCopyMatching(query as CFDictionary, &result)
guard status == errSecSuccess, let result else { stop("Access metadata unavailable (OSStatus \(status))") }
let item = result as! SecKeychainItem
var access: SecAccess?
guard SecKeychainItemCopyAccess(item, &access) == errSecSuccess, let access else { stop("Cannot inspect access metadata") }
var entries: CFArray?
guard SecAccessCopyACLList(access, &entries) == errSecSuccess, let entries else { stop("Cannot inspect ACL metadata") }
var output: [[String: Any]] = []
for acl in entries as! [SecACL] {
    var applications: CFArray?
    var description: CFString?
    var prompt = SecKeychainPromptSelector(rawValue: 0)
    guard SecACLCopyContents(acl, &applications, &description, &prompt) == errSecSuccess else { stop("Cannot inspect ACL contents") }
    var paths: [String] = []
    if let applications {
        for app in applications as! [SecTrustedApplication] {
            var data: CFData?
            guard SecTrustedApplicationCopyData(app, &data) == errSecSuccess, let data else { stop("Cannot inspect trusted application") }
            paths.append(String(decoding: (data as Data).prefix(while: { $0 != 0 }), as: UTF8.self))
        }
    }
    output.append(["authorizations": SecACLCopyAuthorizations(acl) as? [String] ?? [],
                   "trustedApplications": paths, "unrestrictedApplicationList": applications == nil,
                   "promptSelector": prompt.rawValue])
}
let json = try JSONSerialization.data(withJSONObject: output, options: [.prettyPrinted, .sortedKeys])
print(String(decoding: json, as: UTF8.self))
