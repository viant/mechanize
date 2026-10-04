import XCTest
import ApplicationServices
@testable import MechanizeNative
import MechanizeNativeCore

final class NativeTextFixture {
    let element = AXUIElementCreateApplication(42_000)
    var value = "", count = 0, selection = CFRange(location: 0, length: 0)
    var writes: [String] = [], valueReads = 0
    var mode = "valid", role = kAXTextAreaRole, subrole: String?, title: String?
    func rangeValue() -> AXValue { var range = selection; return AXValueCreate(.cfRange, &range)! }
    var runtime: NativeTextRuntime { NativeTextRuntime(attribute: { _, name in
        switch name {
        case kAXRoleAttribute: return (.success, self.role as CFString)
        case kAXEnabledAttribute: return (.success, NSNumber(value: self.mode != "disabled"))
        case kAXSubroleAttribute: return self.subrole.map { (.success, $0 as CFString) } ?? (.noValue, nil)
        case kAXTitleAttribute: return self.title.map { (.success, $0 as CFString) } ?? (.noValue, nil)
        case kAXIdentifierAttribute: return self.mode == "unknownLabel" ? (.cannotComplete, nil) : (.attributeUnsupported, nil)
        case kAXNumberOfCharactersAttribute:
            if self.mode == "badCount" { return (.success, NSNumber(value: -1)) }
            if self.mode == "booleanCount" { return (.success, NSNumber(value: true)) }
            if self.mode == "oversizeCount" { return (.success, NSNumber(value: 65_537)) }
            if self.mode == "changedCount" && !self.writes.isEmpty { return (.success, NSNumber(value: self.count + 1)) }
            return (.success, NSNumber(value: self.count))
        case kAXSelectedTextRangeAttribute:
            if self.mode == "rangeMissing" { return (.noValue, nil) }
            if self.mode == "rangeMalformed" { return (.success, "not-a-range" as CFString) }
            return (.success, self.rangeValue())
        case kAXValueAttribute:
            self.valueReads += 1
            if self.mode == "readMissing" { return (.cannotComplete, nil) }
            return (.success, self.value as CFString)
        default: XCTFail("unexpected read attribute"); return (.attributeUnsupported, nil)
        }
    }, settable: { _, name in (.success, self.mode != "unsupported" && (name == kAXSelectedTextRangeAttribute || name == kAXSelectedTextAttribute)) }, set: { _, name, raw in
        self.writes.append(name)
        if name == kAXSelectedTextRangeAttribute {
            if self.mode == "selectionFailure" { return .failure }
            var range = CFRange(location: 0, length: 0)
            XCTAssertEqual(CFGetTypeID(raw), AXValueGetTypeID()); XCTAssertTrue(AXValueGetValue(raw as! AXValue, .cfRange, &range))
            if self.mode != "selectionNoop" { self.selection = range }
        } else {
            XCTAssertEqual(name, kAXSelectedTextAttribute)
            if self.mode == "textFailure" { return .failure }
            if self.mode != "textNoop" { self.value = raw as! String; self.count = self.value.utf16.count }
        }
        return .success
    }) }
}
final class NativeTextOperationsTests: XCTestCase {
    func testExplicitWholeElementSelectionThenOneSelectedTextWriteAndIndependentProof() throws {
        let f = NativeTextFixture(); f.value = "prior"; f.count = 5
        var reserved = 0
        let outcome = try replaceNativeText(f.element, expected: "public literal", verify: true, revalidate: {}, willMutate: { reserved += 1; XCTAssertTrue(f.writes.isEmpty) }, runtime: f.runtime)
        XCTAssertEqual(reserved, 1); XCTAssertEqual(f.writes, [kAXSelectedTextRangeAttribute, kAXSelectedTextAttribute])
        XCTAssertEqual(f.selection.location, 0); XCTAssertEqual(f.selection.length, 5); XCTAssertEqual(outcome.matches, true); XCTAssertEqual(outcome.dispatchState, "dispatched"); XCTAssertEqual(f.valueReads, 1)
    }
    func testUnsupportedUnknownSecureAndUnboundedTextRejectBeforeAnyWrite() {
        for mode in ["unsupported", "unknownLabel", "badCount", "booleanCount", "oversizeCount", "secure", "protected", "role", "disabled"] {
            let f = NativeTextFixture(); f.mode = mode
            if mode == "secure" { f.subrole = kAXSecureTextFieldSubrole }
            if mode == "protected" { f.title = "Password" }
            if mode == "role" { f.role = kAXButtonRole }
            XCTAssertThrowsError(try replaceNativeText(f.element, expected: "own literal", verify: true, revalidate: {}, willMutate: { XCTFail("must not reserve") }, runtime: f.runtime))
            XCTAssertTrue(f.writes.isEmpty); XCTAssertEqual(f.valueReads, 0)
        }
        for text in [String(repeating: "x", count: 65_537), "bad\0literal"] {
            let f = NativeTextFixture()
            XCTAssertThrowsError(try replaceNativeText(f.element, expected: text, verify: true, revalidate: {}, willMutate: {}, runtime: f.runtime)); XCTAssertTrue(f.writes.isEmpty)
        }
    }
    func testSelectionFailureNoopLostRangeOrChangedCountNeverWritesTextOrRetriesSelection() throws {
        for mode in ["selectionFailure", "selectionNoop", "rangeMissing", "rangeMalformed", "changedCount"] {
            let f = NativeTextFixture(); f.mode = mode; f.count = 5
            let outcome = try replaceNativeText(f.element, expected: "own literal", verify: true, revalidate: {}, willMutate: {}, runtime: f.runtime)
            XCTAssertEqual(outcome.dispatchState, "unknown"); XCTAssertEqual(outcome.failure?.code, "textReplacementUnconfirmed"); XCTAssertEqual(f.writes, [kAXSelectedTextRangeAttribute]); XCTAssertEqual(f.valueReads, 0)
        }
    }
    func testTextSetterFailureOrIgnoredSetterNeverManufacturesProofOrRetries() throws {
        for mode in ["textFailure", "textNoop", "readMissing"] {
            let f = NativeTextFixture(); f.mode = mode
            let outcome = try replaceNativeText(f.element, expected: "public literal", verify: true, revalidate: {}, willMutate: {}, runtime: f.runtime)
            XCTAssertNotEqual(outcome.matches, true); XCTAssertEqual(f.writes, [kAXSelectedTextRangeAttribute, kAXSelectedTextAttribute]); XCTAssertLessThanOrEqual(f.valueReads, 10)
            if mode == "textFailure" { XCTAssertEqual(outcome.dispatchState, "unknown") }
        }
    }
    func testLeaseRootOrBudgetChangeAfterSelectionCannotAttemptTextWrite() throws {
        for code in ["staleLease", "staleFocus", "deadlineExceeded"] {
            let f = NativeTextFixture()
            let outcome = try replaceNativeText(f.element, expected: "public literal", verify: true, revalidate: { if !f.writes.isEmpty { throw NativeFailure(code, "fixture") } }, willMutate: {}, runtime: f.runtime)
            XCTAssertEqual(outcome.dispatchState, "unknown"); XCTAssertEqual(f.writes, [kAXSelectedTextRangeAttribute])
        }
    }
    func testComparisonPolicyDisabledDoesNotReadValueAfterExplicitWrite() throws {
        let f = NativeTextFixture()
        let outcome = try replaceNativeText(f.element, expected: "bound input", verify: false, revalidate: {}, willMutate: {}, runtime: f.runtime)
        XCTAssertEqual(outcome.dispatchState, "dispatched"); XCTAssertNil(outcome.matches); XCTAssertEqual(f.valueReads, 0); XCTAssertEqual(f.writes.count, 2)
    }
    func testReadOnlyComparisonReturnsOnlyBooleanWithoutAnySetter() throws {
        let f = NativeTextFixture(); f.value = "own public literal"
        XCTAssertTrue(try nativeValueMatches(f.element, expected: f.value, revalidate: {}, runtime: f.runtime))
        XCTAssertFalse(try nativeValueMatches(f.element, expected: "different literal", revalidate: {}, runtime: f.runtime))
        XCTAssertTrue(f.writes.isEmpty)
        f.value = "e\u{301}"
        XCTAssertFalse(try nativeValueMatches(f.element, expected: "\u{e9}", revalidate: {}, runtime: f.runtime))
    }
    func testReadOnlyUnknownProtectedOrChangedIdentityDoesNotExposeOrInventFalse() {
        for mode in ["secure", "protected", "unknownLabel", "readMissing", "stale"] {
            let f = NativeTextFixture(); f.mode = mode
            if mode == "secure" { f.subrole = kAXSecureTextFieldSubrole }; if mode == "protected" { f.title = "Token" }
            XCTAssertThrowsError(try nativeValueMatches(f.element, expected: "public literal", revalidate: { if mode == "stale" { throw NativeFailure("staleReference", "fixture") } }, runtime: f.runtime))
            XCTAssertTrue(f.writes.isEmpty)
            if ["secure", "protected", "unknownLabel", "stale"].contains(mode) { XCTAssertEqual(f.valueReads, 0) }
        }
    }
}
