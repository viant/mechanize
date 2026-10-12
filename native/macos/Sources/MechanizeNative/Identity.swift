import Foundation
import Darwin
import Security

enum LaunchIdentityFailure: Error {
    case invalid
    case untrustedBroker
    case missingBrokerEnrollment
}

// This enrollment lives in the signed Mach-O __TEXT,__info_plist. Retrieve it
// through Code Signing Services only after validating our own signature. An
// environment variable, adjacent plist, or a request cannot enroll a broker.
func embeddedBrokerRequirement() throws -> SecRequirement {
    let strict = SecCSFlags(rawValue: kSecCSStrictValidate)
    var ownCode: SecCode?
    guard SecCodeCopySelf([], &ownCode) == errSecSuccess, let ownCode,
          SecCodeCheckValidity(ownCode, strict, nil) == errSecSuccess else {
        throw LaunchIdentityFailure.missingBrokerEnrollment
    }
    var staticCode: SecStaticCode?
    guard SecCodeCopyStaticCode(ownCode, [], &staticCode) == errSecSuccess, let staticCode,
          SecStaticCodeCheckValidity(staticCode, strict, nil) == errSecSuccess else {
        throw LaunchIdentityFailure.missingBrokerEnrollment
    }
    var information: CFDictionary?
    guard SecCodeCopySigningInformation(staticCode, [], &information) == errSecSuccess,
          let dictionary = information as? [String: Any],
          let plist = dictionary[kSecCodeInfoPList as String] as? [String: Any],
          let text = plist["MechanizeBrokerRequirement"] as? String,
          !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
          text.utf8.count <= 4096, !text.contains("\0") else {
        throw LaunchIdentityFailure.missingBrokerEnrollment
    }
    var requirement: SecRequirement?
    guard SecRequirementCreateWithString(text as CFString, [], &requirement) == errSecSuccess,
          let requirement,
          SecCodeCheckValidity(ownCode, strict, nil) == errSecSuccess,
          SecStaticCodeCheckValidity(staticCode, strict, nil) == errSecSuccess else {
        throw LaunchIdentityFailure.missingBrokerEnrollment
    }
    return requirement
}

// Delegation is available only to a fixed signed console that actually owns
// this child. The enrolled broker must independently accept this PID through
// its rendezvous before native services start; arguments alone grant nothing.
func consoleDelegationArguments(_ args:[String]) throws -> (broker:pid_t,requirement:String)? {
    let delegated = args.contains("--console-owned")
    func value(_ key: String) throws -> String {
        let positions = args.indices.filter { args[$0] == key }
        guard positions.count == 1, positions[0]+1 < args.count else { throw LaunchIdentityFailure.invalid }
        return args[positions[0]+1]
    }
    if !delegated {
        guard !args.contains("--console-parent-requirement"), !args.contains("--console-broker-pid") else { throw LaunchIdentityFailure.invalid }
        return nil
    }
    guard args.filter({$0 == "--console-owned"}).count == 1 else { throw LaunchIdentityFailure.invalid }
    let text = try value("--console-parent-requirement"), pidText = try value("--console-broker-pid")
    guard let broker = pid_t(pidText), broker > 1, String(broker) == pidText,
          !text.isEmpty, text.utf8.count <= 4096, !text.contains("\0") else { throw LaunchIdentityFailure.invalid }
    return (broker,text)
}
func delegatedBrokerPID(parent: pid_t) throws -> pid_t? {
    guard let delegation = try consoleDelegationArguments(ProcessInfo.processInfo.arguments) else { return nil }
    let broker = delegation.broker, text = delegation.requirement
    guard broker != parent, let birth = applicationProcessStartToken(parent), applicationLoginUID(parent) == getuid() else { throw LaunchIdentityFailure.untrustedBroker }
    var requirement: SecRequirement?, code: SecCode?
    guard SecRequirementCreateWithString(text as CFString,[],&requirement) == errSecSuccess, let requirement,
          SecCodeCopyGuestWithAttributes(nil,[kSecGuestAttributePid as String:parent] as CFDictionary,[],&code) == errSecSuccess,let code,
          SecCodeCheckValidity(code,SecCSFlags(rawValue:kSecCSStrictValidate),requirement) == errSecSuccess else { throw LaunchIdentityFailure.untrustedBroker }
    var information: CFDictionary?; var staticCode: SecStaticCode?
    guard SecCodeCopyStaticCode(code,[],&staticCode) == errSecSuccess, let staticCode,
          SecCodeCopySigningInformation(staticCode,[],&information) == errSecSuccess,
          (information as? [String:Any])?[kSecCodeInfoIdentifier as String] as? String == "com.viant.mechanize.consent",
          applicationProcessStartToken(parent) == birth, getppid() == parent else { throw LaunchIdentityFailure.untrustedBroker }
    return broker
}

// Only the kernel's socket peer audit token is passed to Security. The parent
// PID check binds this signed peer to the process that actually launched us;
// PID alone never supplies a Security.framework identity.
func verifyBrokerPeer(_ descriptor: Int32, requirement: SecRequirement) throws -> pid_t {
    let parent = getppid()
    let uid = getuid()
    let expectedBroker = try delegatedBrokerPID(parent:parent) ?? parent
    guard parent > 1, geteuid() == uid else { throw LaunchIdentityFailure.untrustedBroker }
    var peerUID: uid_t = 0
    var peerGID: gid_t = 0
    guard getpeereid(descriptor, &peerUID, &peerGID) == 0, peerUID == uid else {
        throw LaunchIdentityFailure.untrustedBroker
    }
    var token = audit_token_t()
    var size = socklen_t(MemoryLayout<audit_token_t>.size)
    guard getsockopt(descriptor, SOL_LOCAL, LOCAL_PEERTOKEN, &token, &size) == 0,
          size == MemoryLayout<audit_token_t>.size,
          audit_token_to_euid(token) == uid, audit_token_to_ruid(token) == uid,
          audit_token_to_pid(token) == expectedBroker else { throw LaunchIdentityFailure.untrustedBroker }
    let tokenData = withUnsafeBytes(of: &token) { Data($0) }
    let attributes = [kSecGuestAttributeAudit as String: tokenData] as CFDictionary
    var broker: SecCode?
    guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &broker) == errSecSuccess,
          let broker,
          SecCodeCheckValidity(broker, SecCSFlags(rawValue: kSecCSStrictValidate), requirement) == errSecSuccess,
          getppid() == parent else { throw LaunchIdentityFailure.untrustedBroker }
    return expectedBroker
}

// Read-only fixture launches without a rendezvous remain unqualified. Every
// configured rendezvous, and every mutation launch, requires reverse signed
// broker authentication before native services are initialized.
func authenticateLaunch() throws -> Bool {
    let arguments = ProcessInfo.processInfo.arguments
    let profiles = ["--allow-mutations", "--allow-launch", "--allow-semantic", "--allow-recording", "--private-administration"].filter { arguments.contains($0) }
    let actionRequested = !profiles.isEmpty || arguments.contains("--console-owned")
    guard profiles.count <= 1 else { throw LaunchIdentityFailure.invalid }
    let environment = ProcessInfo.processInfo.environment
    let path = environment["MECHANIZE_IDENTITY_SOCKET"]
    let nonce = environment["MECHANIZE_IDENTITY_NONCE"]
    defer {
        unsetenv("MECHANIZE_IDENTITY_SOCKET")
        unsetenv("MECHANIZE_IDENTITY_NONCE")
    }
    if path == nil && nonce == nil {
        guard !actionRequested else { throw LaunchIdentityFailure.invalid }
        return false
    }
    guard let path, !path.utf8.contains(0), let nonce, nonce.utf8.count == 64,
          nonce.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else { throw LaunchIdentityFailure.invalid }
    let requirement = try embeddedBrokerRequirement()
    var address = sockaddr_un()
    let pathBytes = Array(path.utf8) + [UInt8(0)]
    guard pathBytes.count <= MemoryLayout.size(ofValue: address.sun_path) else { throw LaunchIdentityFailure.invalid }
    address.sun_family = sa_family_t(AF_UNIX)
    address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
    withUnsafeMutableBytes(of: &address.sun_path) { $0.copyBytes(from: pathBytes) }
    let descriptor = socket(AF_UNIX, SOCK_STREAM, 0)
    guard descriptor >= 0 else { throw LaunchIdentityFailure.invalid }
    defer { close(descriptor) }
    var timeout = timeval(tv_sec: 2, tv_usec: 0)
    var noSignal: Int32 = 1
    guard setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size)) == 0,
          setsockopt(descriptor, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size)) == 0,
          setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE, &noSignal, socklen_t(MemoryLayout<Int32>.size)) == 0 else { throw LaunchIdentityFailure.invalid }
    let connected = withUnsafePointer(to: &address) { pointer in
        pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            Darwin.connect(descriptor, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
        }
    }
    guard connected == 0 else { throw LaunchIdentityFailure.invalid }
    let launchingParent = getppid()
    let brokerPID = try verifyBrokerPeer(descriptor, requirement: requirement)
    // The nonce binds the broker's forward check to this launch. It does not
    // authenticate the broker and is sent only after reverse authentication.
    let frame: [UInt8] = [0, 0, 0, 64] + Array(nonce.utf8)
    try frame.withUnsafeBytes { buffer in
        var sent = 0
        while sent < buffer.count {
            let count = Darwin.write(descriptor, buffer.baseAddress!.advanced(by: sent), buffer.count - sent)
            guard count > 0 else { throw LaunchIdentityFailure.invalid }
            sent += count
        }
    }
    var acknowledgment: UInt8 = 0
    // The broker closes this one-use rendezvous after ACK. Darwin discards
    // LOCAL_PEERTOKEN at peer EOF, so querying that socket again races a valid
    // close. Its peer was authenticated before nonce emission; revalidate the
    // independent exact parent identity here instead.
    guard Darwin.read(descriptor, &acknowledgment, 1) == 1, acknowledgment == 1,
          getppid() == launchingParent,
          try (delegatedBrokerPID(parent:launchingParent) ?? launchingParent) == brokerPID else { throw LaunchIdentityFailure.invalid }
    return true
}
