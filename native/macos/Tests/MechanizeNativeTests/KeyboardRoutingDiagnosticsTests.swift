import XCTest
import ApplicationServices
@testable import MechanizeNative
import MechanizeNativeCore
final class KeyboardRoutingDiagnosticsTests:XCTestCase {
 func testRepresentativeChordCGAndCocoaFlagsWithoutPosting() {
  let facts=constructedChordDiagnostics(keyCode:5,key:"G",modifiers:["command","shift"])
  XCTAssertEqual(facts["eventConstructed"] as? Bool,true);XCTAssertEqual(facts["eventPosted"] as? Bool,false)
  XCTAssertEqual(facts["cgCommand"] as? Bool,true);XCTAssertEqual(facts["cgShift"] as? Bool,true);XCTAssertEqual(facts["keyCode"] as? Int64,5);XCTAssertEqual(facts["upFlagsClear"] as? Bool,true)
  if facts["nsEventAvailable"] as? Bool == true {XCTAssertEqual(facts["nsCommand"] as? Bool,true);XCTAssertEqual(facts["nsShift"] as? Bool,true);XCTAssertEqual(facts["nsKeyCodeMatch"] as? Bool,true);XCTAssertNotNil(facts["nsWindowNumber"])}
  let encoded=try! JSONSerialization.data(withJSONObject:facts);XCTAssertFalse(String(decoding:encoded,as:UTF8.self).contains("charactersIgnoringModifiers\""))
 }
 func testWindowAndSheetRelationsRemainScalarAndDoNotReadContents()throws {
  let target=AXUIElementCreateApplication(42),window=AXUIElementCreateApplication(43),sheet=AXUIElementCreateApplication(44)
  var reads:[String]=[]
  let runtime=RoutingDiagnosticRuntime(read:{element,attribute in
   reads.append(attribute)
   switch attribute {
   case kAXFocusedWindowAttribute,kAXMainWindowAttribute,kAXWindowAttribute:return(.success,window)
   case kAXTopLevelUIElementAttribute,kAXParentAttribute:return(.success,sheet)
   case kAXRoleAttribute:return(.success,(CFEqual(element,sheet) ? "AXSheet":"AXWindow") as CFString)
   case kAXFocusedAttribute,kAXMainAttribute,kAXModalAttribute:return(.success,kCFBooleanTrue)
   default:return(.attributeUnsupported,nil)
   }
  },owner:{_ in (.success,42)})
  let facts=keyboardWindowDiagnostics(target,rootPID:42,budget:try Budget(milliseconds:1000),runtime:runtime)
  XCTAssertEqual(facts["targetTopRoleBucket"] as? String,"sheet");XCTAssertEqual(facts["focusedEqualsTargetWindow"] as? Bool,true);XCTAssertEqual(facts["focusedEqualsTargetTop"] as? Bool,false);XCTAssertEqual(facts["topFoundInParentChain"] as? Bool,true)
  XCTAssertFalse(reads.contains(kAXTitleAttribute));XCTAssertFalse(reads.contains(kAXValueAttribute));XCTAssertFalse(reads.contains(kAXDescriptionAttribute))
  XCTAssertEqual(facts["qualificationChanged"] as? Bool,false)
  let encoded=try JSONSerialization.data(withJSONObject:facts);XCTAssertLessThan(encoded.count,12000)
 }
 func testUnknownAttributesStayUnknownAndParentChainBounded()throws {
  var reads=0
  let runtime=RoutingDiagnosticRuntime(read:{_,_ in reads+=1;return(.cannotComplete,nil)},owner:{_ in return(.cannotComplete,0)})
  let facts=keyboardWindowDiagnostics(AXUIElementCreateApplication(42),rootPID:42,budget:try Budget(milliseconds:1000),runtime:runtime)
  XCTAssertNil(facts["focusedEqualsTargetWindow"]);XCTAssertEqual(facts["topFoundInParentChain"] as? Bool,false);XCTAssertLessThanOrEqual(reads,6)
 }
}
extension KeyboardRoutingDiagnosticsTests {
 func testMissingTopStillFindsFocusedSheetInBoundedParentAncestry()throws {
  let target=AXUIElementCreateApplication(42),sheet=AXUIElementCreateApplication(44),window=AXUIElementCreateApplication(43)
  var contentReads=0
  let runtime=RoutingDiagnosticRuntime(read:{element,attribute in
   switch attribute {
   case kAXFocusedWindowAttribute:return(.success,sheet)
   case kAXMainWindowAttribute:return(.success,window)
   case kAXWindowAttribute,kAXTopLevelUIElementAttribute:return(.noValue,nil)
   case kAXParentAttribute:if CFEqual(element,target){return(.success,sheet)};if CFEqual(element,sheet){return(.success,window)};return(.attributeUnsupported,nil)
   case kAXRoleAttribute:return(.success,(CFEqual(element,sheet) ? "AXSheet":CFEqual(element,window) ? "AXWindow":"AXOutline") as CFString)
   case kAXFocusedAttribute,kAXMainAttribute,kAXModalAttribute:return(.success,kCFBooleanFalse)
   case kAXTitleAttribute,kAXValueAttribute,kAXDescriptionAttribute:contentReads+=1;return(.success,"must-not-read" as CFString)
   default:return(.attributeUnsupported,nil)
   }
  },owner:{_ in (.success,42)})
  let facts=keyboardWindowDiagnostics(target,rootPID:42,budget:try Budget(milliseconds:1000),runtime:runtime)
  XCTAssertEqual(facts["targetTopStatus"] as? Int32,AXError.noValue.rawValue)
  XCTAssertEqual(facts["ancestor1RoleBucket"] as? String,"sheet");XCTAssertEqual(facts["ancestor1EqualsFocusedWindow"] as? Bool,true);XCTAssertEqual(facts["ancestor1RootPIDMatch"] as? Bool,true)
  XCTAssertEqual(facts["ancestor2RoleBucket"] as? String,"window");XCTAssertEqual(facts["ancestor2EqualsMainWindow"] as? Bool,true)
  XCTAssertEqual(contentReads,0);XCTAssertEqual(facts["qualificationChanged"] as? Bool,false)
 }
}
