import XCTest
@testable import ConsentCore

final class ConsoleEnrollmentTests: XCTestCase {
    private let account = "com.viant.mechanize.consent:501:0123456789abcdef0123456789abcdef"
    private final class Store: ConsoleEnrollmentStore {
        var existing = false
        var duplicateAtAdd = false
        var configured: [Bool] = []
        var lookups: [String] = []
        var added: [(String, String, Data)] = []
        func configure(interactive: Bool) throws { configured.append(interactive) }
        func exists(account: String) throws -> Bool { lookups.append(account); return existing }
        func add(account: String, executable: String, credential: Data) throws {
            if duplicateAtAdd { throw ConsoleEnrollmentError.existingEnrollment }
            added.append((account, executable, credential))
        }
    }
    private func execute(_ store: Store, input: Data = Data("eyJhbGciOiJIUzI1NiJ9.e30.signature".utf8),
                         arguments: [String] = ["--enroll-credential"], account: String? = nil,
                         bundleID: String = "com.viant.mechanize.consent") throws -> ConsoleEnrollmentReport {
        var offset = 0
        return try ConsoleOwnedEnrollment.execute(arguments: arguments, bundleID: bundleID, account: account ?? self.account,
            uid: 501, executable: "/fixture/Mechanize Permissions.app/Contents/MacOS/MechanizeConsent", read: { count in
                let end = min(offset + count, input.count)
                defer { offset = end }
                return input.subdata(in: offset..<end)
            }, store: store)
    }
    func testCreateOnlyUsesSignedAccountAndSelfExecutableWithInteractionDisabled() throws {
        let store = Store(); let result = try execute(store)
        XCTAssertEqual(store.configured, [false]); XCTAssertEqual(store.lookups, [account])
        XCTAssertEqual(store.added.count, 1); XCTAssertEqual(store.added[0].0, account)
        XCTAssertEqual(store.added[0].1, "/fixture/Mechanize Permissions.app/Contents/MacOS/MechanizeConsent")
        XCTAssertTrue(result.enrolled)
        XCTAssertEqual(Set((try JSONSerialization.jsonObject(with: result.json()) as! [String: Any]).keys), ["enrolled", "code"])
        XCTAssertFalse(String(decoding: result.json(), as: UTF8.self).contains("signature"))
    }
    func testExistingItemDoesNotReadInputOrReplaceCredential() {
        let store = Store(); store.existing = true
        XCTAssertThrowsError(try ConsoleOwnedEnrollment.execute(arguments: ["--enroll-credential"], bundleID: "com.viant.mechanize.consent",
            account: account, uid: 501, executable: "/fixture/self", read: { _ in XCTFail("Existing item read stdin"); return Data() }, store: store)) {
            XCTAssertEqual($0 as? ConsoleEnrollmentError, .existingEnrollment)
        }
        XCTAssertTrue(store.added.isEmpty)
    }
    func testConcurrentDuplicateIsPreserved() {
        let store = Store(); store.duplicateAtAdd = true
        XCTAssertThrowsError(try execute(store)) { XCTAssertEqual($0 as? ConsoleEnrollmentError, .existingEnrollment) }
        XCTAssertTrue(store.added.isEmpty)
    }
    func testExactArgumentModeRejectsSecretArgAndOtherFlagsBeforeKeychain() {
        for args in [[], ["--interactive", "--enroll-credential"], ["--enroll-credential", "secret"],
                     ["--enroll-credential", "--check-connection"], ["--enroll-credential", "--interactive", "extra"]] {
            let store = Store()
            XCTAssertThrowsError(try execute(store, arguments: args))
            XCTAssertTrue(store.configured.isEmpty); XCTAssertTrue(store.lookups.isEmpty)
        }
    }
    func testInteractiveModeRequiresExplicitExactFlag() throws {
        let store = Store(); _ = try execute(store, arguments: ["--enroll-credential", "--interactive"])
        XCTAssertEqual(store.configured, [true])
    }
    func testInvalidSignedAccountsAndBundleNeverTouchKeychain() {
        for rejected in ["com.viant.mechanize.consent:501", account + "0", account.uppercased(),
                         "com.viant.mechanize.consent:502:0123456789abcdef0123456789abcdef"] {
            let store = Store(); XCTAssertThrowsError(try execute(store, account: rejected))
            XCTAssertTrue(store.configured.isEmpty)
        }
        let store = Store(); XCTAssertThrowsError(try execute(store, bundleID: "com.other"))
        XCTAssertTrue(store.configured.isEmpty)
        XCTAssertThrowsError(try ConsoleOwnedEnrollment.execute(arguments: ["--enroll-credential"],
            bundleID: "com.viant.mechanize.consent", account: nil, uid: 501, executable: "/fixture/self",
            read: { _ in XCTFail("Missing account read stdin"); return Data() }, store: store))
        XCTAssertTrue(store.configured.isEmpty)
    }
    func testBoundedInputRejectsEmptyOversizeMalformedAndWhitespaceWithoutWrites() {
        let inputs = [Data(), Data(repeating: 65, count: 32769), Data("a.b.".utf8), Data("a.b.c\n".utf8),
                      Data("a.b".utf8), Data([255, 46, 97, 46, 98]), Data("a.b.c+d".utf8)]
        for input in inputs {
            let store = Store(); XCTAssertThrowsError(try execute(store, input: input))
            XCTAssertTrue(store.added.isEmpty)
        }
    }
    func testInputReadIsBoundedEvenWhenStreamNeverEnds() {
        let store = Store(); var readCount = 0
        XCTAssertThrowsError(try ConsoleOwnedEnrollment.execute(arguments: ["--enroll-credential"], bundleID: "com.viant.mechanize.consent",
            account: account, uid: 501, executable: "/fixture/self", read: { count in
                readCount += 1; XCTAssertLessThanOrEqual(count, 32769); return Data(repeating: 65, count: count)
            }, store: store))
        XCTAssertEqual(readCount, 1); XCTAssertTrue(store.added.isEmpty)
    }
    func testErrorReportsContainOnlyFixedCodes() {
        let result = ConsoleOwnedEnrollment.failure(NSError(domain: "secret-do-not-log", code: 9))
        XCTAssertFalse(result.enrolled); XCTAssertEqual(result.code, "enrollmentUnavailable")
        XCTAssertFalse(String(decoding: result.json(), as: UTF8.self).contains("secret"))
    }
}
