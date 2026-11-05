import AppKit
import ApplicationServices
import Testing
import MechanizeNativeCore
@testable import MechanizeNative

struct PrivatePasswordRecipientTests {
    final class Fixture {
        let pid: pid_t = 42000
        let field = AXUIElementCreateApplication(42001)
        let other = AXUIElementCreateApplication(42002)
        var mode = "", count = 0, countReads = 0
        var runtime: PrivatePasswordRecipientRuntime {
            PrivatePasswordRecipientRuntime(attribute: { [self] element, name in
                if name == kAXFocusedUIElementAttribute { return (.success, mode == "replacement" ? other : field) }
                if name == kAXRoleAttribute { return (.success, kAXTextFieldRole as CFString) }
                if name == kAXSubroleAttribute { return (.success, (mode == "plain" ? "AXUnknown" : kAXSecureTextFieldSubrole) as CFString) }
                if name == kAXEnabledAttribute || name == kAXFocusedAttribute { return (.success, NSNumber(value: mode != "disabled")) }
                if name == kAXValueAttribute || name == kAXSelectedTextAttribute {
                    Issue.record("Private recipient read secret content")
                    return (.failure, nil)
                }
                if name == kAXNumberOfCharactersAttribute {
                    countReads += 1
                    if mode == "unavailable" { return (.noValue, nil) }
                    if mode == "boolean" { return (.success, NSNumber(value: true)) }
                    if mode == "fraction" { return (.success, NSNumber(value: 0.5)) }
                    if mode == "driftOnRead" { mode = "replacement" }
                    return (.success, NSNumber(value: count))
                }
                return (.attributeUnsupported, nil)
            }, owner: { [self] _ in
                AXElementOwner(pid: mode == "foreign" ? 77 : pid, uid: 501,
                               birth: mode == "restarted" ? "100:2" : "100:1",
                               bundle: mode == "bundle" ? "com.example.Other" : "com.example.Login", status: AXError.success.rawValue)
            }, foreground: { [self] in mode == "background" ? 77 : pid }, sessionQualified: { [self] in mode != "locked" })
        }
        func pin() throws -> PrivatePasswordRecipient {
            try PrivatePasswordRecipient.pin(pid: pid, uid: 501, birth: "100:1", bundle: "com.example.Login", check: {}, runtime: runtime)
        }
    }
    @Test func pinsSecureFieldAndChecksOnlyCharacterMetadata() throws {
        let f = Fixture(), target = try f.pin()
        #expect(f.countReads == 0)
        try target.requireCharacterCount(0, check: {}, runtime: f.runtime)
        f.count = 1
        try target.requireCharacterCount(1, check: {}, runtime: f.runtime)
        f.count = 15
        try target.requireCharacterCount(15, check: {}, runtime: f.runtime)
        #expect(f.countReads == 3)
    }
    @Test func changedRecipientIsRejectedBeforeCountRead() throws {
        for mode in ["replacement", "plain", "disabled", "foreign", "restarted", "bundle", "background", "locked"] {
            let f = Fixture(), target = try f.pin()
            f.mode = mode
            #expect(throws: NativeFailure.self) { try target.requireCharacterCount(0, check: {}, runtime: f.runtime) }
            #expect(f.countReads == 0)
        }
    }
    @Test func unavailableMalformedAndChangedCountsCannotProveStructure() throws {
        for mode in ["unavailable", "boolean", "fraction", "wrong", "driftOnRead"] {
            let f = Fixture(), target = try f.pin()
            f.mode = mode
            f.count = mode == "driftOnRead" ? 1 : 2
            #expect(throws: NativeFailure.self) { try target.requireCharacterCount(1, check: {}, runtime: f.runtime) }
        }
    }
    @Test func expiredAuthorityAndProviderErrorsStayPrivate() throws {
        let f = Fixture(), target = try f.pin()
        do {
            try target.requireCharacterCount(0, check: { throw NSError(domain: "PRIVATE-CANARY", code: 1) }, runtime: f.runtime)
            Issue.record("Expired authority accepted")
        } catch let error as NativeFailure {
            #expect(error.code == "privatePasswordRecipientUnavailable")
            #expect(!String(describing: error).contains("CANARY"))
        }
        #expect(f.countReads == 0)
    }
}
