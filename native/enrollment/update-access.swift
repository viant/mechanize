// Metadata-only, two-phase developer-console ACL upgrade. Never reads credentials.
// Audit before replacement; apply only after reviewing/installing the new signed
// console at the SAME path. A noninteractive Keychain denial remains a user gate.
// Apple APIs: https://developer.apple.com/documentation/security/access-control-lists
import Foundation
import Security
import CryptoKit
import Darwin

struct Failure: Error {
    let status: String
    let message: String
    let osStatus: OSStatus?
    init(_ message: String, status: String = "rejected", osStatus: OSStatus? = nil) {
        self.message = message; self.status = status; self.osStatus = osStatus
    }
}
func trace(_ stage: String, phase: String = "begin", osStatus: OSStatus? = nil) {
    var record: [String: Any] = ["stage": stage, "phase": phase, "credentialDataRead": false]
    if let osStatus { record["osStatus"] = osStatus }
    if let data = try? JSONSerialization.data(withJSONObject: record, options: [.sortedKeys]) {
        var line = data; line.append(10)
        try? FileHandle.standardError.write(contentsOf: line)
    }
}
func check(_ status: OSStatus, _ operation: String) throws {
    trace(operation, phase: "completed", osStatus: status)
    guard status != errSecSuccess else { return }
    let interaction = status == errSecInteractionNotAllowed || status == errSecInteractionRequired || status == errSecUserCanceled
    let keychainAuthorization = status == errSecAuthFailed && ["Enrollment reference lookup", "Access metadata lookup", "Restricted enrollment ACL update"].contains(operation)
    let result = interaction ? "interactionRequired" : (keychainAuthorization ? "authorizationRequired" : "securityDenied")
    throw Failure(operation + " failed; no credential data operation attempted", status: result, osStatus: status)
}
func hash(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
func encoded<T: Encodable>(_ value: T) throws -> Data {
    let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
    return try encoder.encode(value)
}
struct ApplicationMetadata: Codable { let path: String; let dataSHA256: String }
struct ACLMetadata: Codable {
    let authorizations: [String]
    let applications: [ApplicationMetadata]?
    let descriptionSHA256: String?
    let promptSelector: UInt32
}
struct Snapshot: Codable {
    let version: Int
    let uid: UInt32
    let service: String
    let account: String
    let appPath: String
    let oldRequirement: String
    let aclSHA256: String
    let recipientDataSHA256: String
}
struct Entry {
    let acl: SecACL
    let applications: [SecTrustedApplication]?
    let description: CFString?
    let prompt: SecKeychainPromptSelector
    let metadata: ACLMetadata
}
var accessUpdateState = "notAttempted"
let service = "com.viant.mechanize.console.enrollment"
let account = "com.viant.mechanize.consent:\(getuid())"
let sensitiveTags = Set(["ACLAuthorizationDecrypt", "ACLAuthorizationDerive", "ACLAuthorizationExportClear", "ACLAuthorizationExportWrapped", "ACLAuthorizationMAC", "ACLAuthorizationSign"])
let platformTags = Set(["ACLAuthorizationEncrypt", "ACLAuthorizationIntegrity", "ACLAuthorizationPartitionID"])

func canonicalPath(_ path: String) throws -> String {
    guard let resolved = path.withCString({ realpath($0, nil) }) else { throw Failure("Cannot resolve metadata path") }
    defer { free(resolved) }
    return String(cString: resolved)
}
func checkedPath(_ path: String, directory: Bool) throws -> URL {
    let url = URL(fileURLWithPath: path)
    guard path.hasPrefix("/"), url.path == path,
          try canonicalPath(path) == path else { throw Failure("Absolute canonical path without symlinks required") }
    let attributes = try FileManager.default.attributesOfItem(atPath: path)
    let type = attributes[.type] as? FileAttributeType
    let owner = (attributes[.ownerAccountID] as? NSNumber)?.uint32Value
    let permissions = (attributes[.posixPermissions] as? NSNumber)?.uint16Value ?? 0xffff
    guard type == (directory ? .typeDirectory : .typeRegular), owner == UInt32(getuid()), permissions & 0o022 == 0,
          directory || (attributes[.referenceCount] as? NSNumber)?.intValue == 1 else {
        throw Failure("Operator-owned path without group/other write access required")
    }
    return url
}
// Require the actual designated requirement or its stricter fixed-identifier
// CDHash conjunction, as well as validity. Broad substitute requirements fail.
func verifyConsole(_ app: URL, requirementText: String) throws -> String {
    guard !requirementText.isEmpty, !requirementText.contains("\0"), app.pathExtension == "app" else { throw Failure("Enrolled application and designated requirement required") }
    _ = try checkedPath(app.appendingPathComponent("Contents/MacOS/MechanizeConsent").path, directory: false)
    var code: SecStaticCode?
    try check(SecStaticCodeCreateWithPath(app as CFURL, [], &code), "Console static-code lookup")
    guard let code else { throw Failure("Console static-code lookup returned no code") }
    var supplied: SecRequirement?
    try check(SecRequirementCreateWithString(requirementText as CFString, [], &supplied), "Requirement parsing")
    guard let supplied else { throw Failure("Missing requirement") }
    try check(SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate | kSecCSCheckAllArchitectures), supplied), "Console signature validation")
    var actual: SecRequirement?
    try check(SecCodeCopyDesignatedRequirement(code, [], &actual), "Designated requirement lookup")
    guard let actual else { throw Failure("Missing designated requirement") }
    var actualString: CFString?; var suppliedString: CFString?
    try check(SecRequirementCopyString(actual, [], &actualString), "Designated requirement serialization")
    try check(SecRequirementCopyString(supplied, [], &suppliedString), "Supplied requirement serialization")
    guard let actualString, let suppliedString else { throw Failure("Missing canonical requirement") }
    let actualText = actualString as String
    let suppliedText = suppliedString as String
    // The developer manifest adds the fixed signed console identifier to its
    // ad hoc exact CDHash. This conjunction is stricter than the actual DR;
    // broad predicates, disjunctions and alternate hashes are never accepted.
    let pinnedIdentifier = "identifier \"com.viant.mechanize.consent\""
    let stricterManifest = actualText.hasPrefix("cdhash H\"") &&
        Bundle(url: app)?.bundleIdentifier == "com.viant.mechanize.consent" &&
        (suppliedText == pinnedIdentifier + " and " + actualText || suppliedText == actualText + " and " + pinnedIdentifier)
    guard actualText == suppliedText || stricterManifest else { throw Failure("Requirement is not the console's exact designated requirement or fixed-identifier CDHash pin") }
    return actualText
}
func itemReference() throws -> SecKeychainItem {
    let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service, kSecAttrAccount as String: account,
        kSecMatchLimit as String: kSecMatchLimitAll, kSecReturnRef as String: true,
        kSecUseAuthenticationUI as String: kSecUseAuthenticationUIFail]
    var result: CFTypeRef?
    trace("Enrollment reference lookup")
    try check(SecItemCopyMatching(query as CFDictionary, &result), "Enrollment reference lookup")
    guard let result, let items = result as? [SecKeychainItem], items.count == 1 else { throw Failure("Exactly one existing enrollment reference required") }
    return items[0]
}
func accessEntries(_ item: SecKeychainItem) throws -> (SecAccess, [Entry]) {
    var access: SecAccess?
    trace("Access metadata lookup")
    try check(SecKeychainItemCopyAccess(item, &access), "Access metadata lookup")
    guard let access else { throw Failure("Missing access metadata") }
    var list: CFArray?
    trace("ACL metadata lookup")
    try check(SecAccessCopyACLList(access, &list), "ACL metadata lookup")
    guard let list, let acls = list as? [SecACL], !acls.isEmpty else { throw Failure("Missing ACL metadata") }
    var entries: [Entry] = []
    for acl in acls {
        var applications: CFArray?; var description: CFString?
        var prompt = SecKeychainPromptSelector(rawValue: 0)
        trace("ACL contents lookup")
        try check(SecACLCopyContents(acl, &applications, &description, &prompt), "ACL contents lookup")
        guard let tags = SecACLCopyAuthorizations(acl) as? [String], !tags.isEmpty else { throw Failure("Invalid ACL authorization metadata") }
        var trusted: [SecTrustedApplication]? = nil
        var metadata: [ApplicationMetadata]? = nil
        if let applications {
            guard let parsed = applications as? [SecTrustedApplication] else { throw Failure("Invalid trusted application list") }
            trusted = parsed; metadata = []
            for application in parsed {
                var data: CFData?
                trace("Trusted application metadata lookup")
                try check(SecTrustedApplicationCopyData(application, &data), "Trusted application metadata lookup")
                guard let data else { throw Failure("Missing trusted application metadata") }
                let bytes = data as Data
                // Public data contains only path bytes on this installation. Its hash
                // pins exposed metadata, not the hidden trusted signing identity.
                guard let end = bytes.firstIndex(of: 0), let path = String(data: bytes.prefix(upTo: end), encoding: .utf8), path.hasPrefix("/") else { throw Failure("Trusted application path unavailable") }
                metadata?.append(ApplicationMetadata(path: path, dataSHA256: hash(bytes)))
            }
        }
        let summary = ACLMetadata(authorizations: tags.sorted(), applications: metadata,
            descriptionSHA256: description.map { hash(Data(($0 as String).utf8)) }, promptSelector: UInt32(prompt.rawValue))
        entries.append(Entry(acl: acl, applications: trusted, description: description, prompt: prompt, metadata: summary))
    }
    return (access, entries)
}
func fingerprint(_ entries: [Entry]) throws -> String {
    let canonical = try entries.map { String(decoding: try encoded($0.metadata), as: UTF8.self) }.sorted()
    return hash(try encoded(canonical))
}
func recipient(_ entries: [Entry], appPath: String) throws -> Entry {
    var selected: [Entry] = []
    for entry in entries {
        let tags = Set(entry.metadata.authorizations)
        if tags == sensitiveTags {
            guard let applications = entry.metadata.applications, applications.count == 1,
                  applications[0].path == appPath, entry.applications?.count == 1, entry.description != nil else {
                throw Failure("Sensitive ACL recipient differs from the exact enrolled console")
            }
            selected.append(entry)
        } else if tags.count == 1 && tags.isSubset(of: platformTags) {
            guard entry.applications == nil else { throw Failure("Unexpected platform ACL recipient") }
        } else if tags == Set(["ACLAuthorizationChangeACL"]) {
            guard let applications = entry.applications, applications.isEmpty else { throw Failure("Unexpected change-ACL recipient") }
        } else { throw Failure("Unexpected ACL authorization layout; no update attempted") }
    }
    guard selected.count == 1 else { throw Failure("Exactly one restricted sensitive ACL required") }
    return selected[0]
}
func emit(_ object: [String: Any]) throws {
    let data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    print(String(decoding: data, as: UTF8.self))
}
func run() throws {
    let arguments = Array(CommandLine.arguments.dropFirst())
    if arguments == ["--help"] {
        print("usage: update-access --audit <installed-app-path> <old-designated-requirement> <new-snapshot-path>\n       update-access --inspect <snapshot-path> <current-designated-requirement>\n       update-access --apply <snapshot-path> <new-designated-requirement>\nAudit reads ACL metadata only. Apply requires reviewed replacement at the same installed path. No credentials are read or changed. Keychain prompts are never bypassed.")
        return
    }
    guard (arguments.count == 4 && arguments[0] == "--audit") || (arguments.count == 3 && ["--apply", "--inspect"].contains(arguments[0])) else { throw Failure("Use --help for the two-phase upgrade contract") }
    try check(SecKeychainSetUserInteractionAllowed(false), "Noninteractive Keychain policy")
    if arguments[0] == "--audit" {
        let app = try checkedPath(arguments[1], directory: true)
        let oldRequirement = try verifyConsole(app, requirementText: arguments[2])
        let item = try itemReference()
        let (_, entries) = try accessEntries(item)
        let current = try recipient(entries, appPath: app.path)
        let snapshot = Snapshot(version: 1, uid: UInt32(getuid()), service: service, account: account,
            appPath: app.path, oldRequirement: oldRequirement, aclSHA256: try fingerprint(entries),
            recipientDataSHA256: current.metadata.applications![0].dataSHA256)
        let path = arguments[3]
        let url = URL(fileURLWithPath: path)
        guard path.hasPrefix("/"), url.path == path,
              try canonicalPath(url.deletingLastPathComponent().path) == url.deletingLastPathComponent().path else { throw Failure("Canonical snapshot path required") }
        let bytes = try encoded(snapshot)
        let fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
        guard fd >= 0 else { throw Failure("Cannot create new private snapshot; existing files preserved") }
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        try handle.write(contentsOf: bytes); try handle.synchronize(); try handle.close()
        try emit(["status": "audited", "snapshotPath": path, "appPath": app.path,
            "aclSHA256": snapshot.aclSHA256, "recipientDataSHA256": snapshot.recipientDataSHA256,
            "aclCount": entries.count, "credentialDataRead": false, "accessChanged": false])
        return
    }
    let snapshotURL = try checkedPath(arguments[1], directory: false)
    let permissions = (try FileManager.default.attributesOfItem(atPath: snapshotURL.path)[.posixPermissions] as? NSNumber)?.uint16Value ?? 0xffff
    guard permissions & 0o077 == 0 else { throw Failure("Snapshot must be private to the current operator") }
    let bytes = try Data(contentsOf: snapshotURL, options: [.mappedIfSafe])
    guard bytes.count <= 65536 else { throw Failure("Snapshot too large") }
    let snapshot = try JSONDecoder().decode(Snapshot.self, from: bytes)
    guard snapshot.version == 1, snapshot.uid == UInt32(getuid()), snapshot.service == service,
          snapshot.account == account, !snapshot.oldRequirement.isEmpty else { throw Failure("Snapshot enrollment identity mismatch") }
    let app = try checkedPath(snapshot.appPath, directory: true)
    let newRequirement = try verifyConsole(app, requirementText: arguments[2])
    if arguments[0] == "--apply" {
        guard newRequirement != snapshot.oldRequirement else { throw Failure("Console requirement has not changed; no update attempted") }
    }
    let item = try itemReference()
    let (access, entries) = try accessEntries(item)
    let current = try recipient(entries, appPath: app.path)
    if arguments[0] == "--inspect" {
        let currentHash = try fingerprint(entries)
        try emit(["status": "inspected", "appPath": app.path, "aclSHA256": currentHash,
            "exposedMetadataMatchesSnapshot": currentHash == snapshot.aclSHA256,
            "recipientDataSHA256": current.metadata.applications![0].dataSHA256,
            "trustedCodeIdentity": "notExposedByPublicMetadata", "priorApplyOutcome": "unconfirmed",
            "credentialDataRead": false, "accessChanged": false])
        return
    }
    guard try fingerprint(entries) == snapshot.aclSHA256,
          current.metadata.applications![0].dataSHA256 == snapshot.recipientDataSHA256 else { throw Failure("Current enrollment ACL differs from the pinned pre-upgrade snapshot") }
    var replacement: SecTrustedApplication?
    try check(app.path.withCString { SecTrustedApplicationCreateFromPath($0, &replacement) }, "New console trusted application creation")
    guard let replacement, let description = current.description else { throw Failure("Missing restricted replacement metadata") }
    // Recheck immutable image policy and current ACL immediately before changing
    // the copied access. The installer must serialize upgrades; this API has no CAS.
    _ = try verifyConsole(app, requirementText: newRequirement)
    let (_, latestEntries) = try accessEntries(item)
    guard try fingerprint(latestEntries) == snapshot.aclSHA256 else { throw Failure("Enrollment ACL changed during review") }
    trace("Restricted ACL preparation")
    try check(SecACLSetContents(current.acl, [replacement] as CFArray, description, current.prompt), "Restricted ACL preparation")
    // All other existing ACL objects, authorizations, descriptions and prompts
    // remain in this copied SecAccess. No new default access or partition edits.
    let expectedOthers = try entries.filter { Set($0.metadata.authorizations) != sensitiveTags }.map { try encoded($0.metadata) }.map { String(decoding: $0, as: UTF8.self) }.sorted()
    var replacementData: CFData?
    try check(SecTrustedApplicationCopyData(replacement, &replacementData), "Replacement trusted metadata lookup")
    guard let replacementData else { throw Failure("Missing replacement trusted metadata") }
    let replacementHash = hash(replacementData as Data)
    accessUpdateState = "notConfirmed"
    trace("Restricted enrollment ACL update")
    let updateStatus = SecKeychainItemSetAccess(item, access)
    if updateStatus == errSecAuthFailed {
        throw Failure("Keychain denied noninteractive ACL authorization; normal user authorization may be required", status: "authorizationRequired", osStatus: updateStatus)
    }
    try check(updateStatus, "Restricted enrollment ACL update")
    accessUpdateState = "updated"
    let (_, updated) = try accessEntries(item)
    let updatedRecipient = try recipient(updated, appPath: app.path)
    guard updatedRecipient.metadata.applications?[0].dataSHA256 == replacementHash else { throw Failure("Saved recipient metadata does not match replacement; manual review required", status: "verificationRequired") }
    let newOther = try updated.filter { Set($0.metadata.authorizations) != sensitiveTags }.map { try encoded($0.metadata) }.map { String(decoding: $0, as: UTF8.self) }.sorted()
    guard expectedOthers == newOther else { throw Failure("Post-update metadata differs; manual review required", status: "verificationRequired") }
    try emit(["status": "updated", "appPath": app.path, "credentialDataRead": false,
        "credentialChanged": false, "otherACLsPreserved": true])
}
do { try run() } catch let failure as Failure {
    var output: [String: Any] = ["status": failure.status, "message": failure.message, "credentialDataRead": false, "accessUpdateState": accessUpdateState]
    if let status = failure.osStatus { output["osStatus"] = status }
    try? emit(output)
    exit(failure.status == "interactionRequired" || failure.status == "authorizationRequired" ? 3 : 1)
} catch {
    try? emit(["status": "rejected", "message": "Metadata operation failed; review required", "credentialDataRead": false, "accessUpdateState": accessUpdateState])
    exit(1)
}
