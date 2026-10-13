import XCTest
import AppKit
import ApplicationServices
import MechanizeNativeCore
@testable import MechanizeNative

final class AXKeyboardForegroundTests:XCTestCase {
 final class Fixture {
  let pid:pid_t=43000,uid:uid_t=501,birth="123:456",bundle="com.fixture.app"
  let app=AXUIElementCreateApplication(43000),target=AXUIElementCreateApplication(43001),window=AXUIElementCreateApplication(43002),other=AXUIElementCreateApplication(43003)
  var associated:AXUIElement?,selectedWindow:AXUIElement?,selectedElement:AXUIElement?
  var targetFocused=true,foreign:AXUIElement?,mismatch="pid",reads:[String]=[]
  var missing:Set<String>=[]
  init(){associated=window;selectedWindow=window;selectedElement=target}
  func owner(_ element:AXUIElement)->AXElementOwner {
   let changed=foreign.map{CFEqual(element,$0)} == true
   return AXElementOwner(pid:changed && mismatch=="pid" ? 77:pid,uid:changed && mismatch=="uid" ? 77:uid,birth:changed && mismatch=="birth" ? "999:1":birth,bundle:changed && mismatch=="bundle" ? "com.foreign.app":bundle,status:AXError.success.rawValue)
  }
  var runtime:ScopedNativeRootRuntime{ScopedNativeRootRuntime(attribute:{element,name in
   self.reads.append(name)
   if self.missing.contains(name){return(.cannotComplete,nil)}
   switch name {
   case kAXRoleAttribute:return(.success,(CFEqual(element,self.target) ? kAXTextFieldRole:kAXWindowRole) as CFString)
   case kAXWindowAttribute:return self.associated.map{(.success,$0 as CFTypeRef)} ?? (.noValue,nil)
   case kAXFocusedWindowAttribute:return self.selectedWindow.map{(.success,$0 as CFTypeRef)} ?? (.noValue,nil)
   case kAXFocusedUIElementAttribute:return self.selectedElement.map{(.success,$0 as CFTypeRef)} ?? (.noValue,nil)
   case kAXFocusedAttribute:return(.success,self.targetFocused as CFBoolean)
   default:XCTFail("keyboard recipient read geometry or contents: \(name)");return(.cannotComplete,nil)
   }
  },owner:{self.owner($0)})}
  func bind()throws->AXSemanticForegroundRecipient{try AXSemanticForegroundRecipient.bind(element:target,application:app,pid:pid,uid:uid,birth:birth,bundle:bundle,menuRoot:false,budget:Budget(milliseconds:1000),runtime:runtime)}
 }
 func testOwnedFocusedPopupKeyboardProofDoesNotNeedSupportedPixelLayer()throws {
  let f=Fixture(),proof=try f.bind()
  let popup=SessionKeyWindow(id:7,pid:f.pid,layer:101,visible:true,alpha:1,bounds:CGRect(x:320,y:107,width:670,height:711))
  XCTAssertThrowsError(try NativeForegroundTarget.physicalWindow([popup],pid:f.pid,windowID:7,phase:.preflight))
  XCTAssertTrue(try proof.keyboardFocused(Budget(milliseconds:1000),runtime:f.runtime))
  let allowed:Set<String>=[kAXRoleAttribute,kAXWindowAttribute,kAXFocusedWindowAttribute,kAXFocusedUIElementAttribute,kAXFocusedAttribute]
  XCTAssertTrue(Set(f.reads).isSubset(of:allowed))
  XCTAssertFalse(f.reads.contains(kAXValueAttribute))
 }
 func testKeyboardRequiresExactFocusedElementNotJustSameOwnedWindow()throws {
  for mode in ["otherElement","notFocused","otherWindow"] {
   let f=Fixture(),proof=try f.bind()
   switch mode {
   case "otherElement":f.selectedElement=f.other
   case "notFocused":f.targetFocused=false
   default:f.selectedWindow=f.other
   }
   XCTAssertFalse(try proof.keyboardFocused(Budget(milliseconds:1000),runtime:f.runtime),mode)
  }
 }
 func testMissingFocusAndForeignOwnersDenyBeforeKeyboardPosting()throws {
  for field in [kAXFocusedWindowAttribute,kAXFocusedUIElementAttribute,kAXFocusedAttribute,kAXRoleAttribute,kAXWindowAttribute] {
   let f=Fixture(),proof=try f.bind();f.missing.insert(field)
   XCTAssertThrowsError(try proof.keyboardFocused(Budget(milliseconds:1000),runtime:f.runtime),field)
  }
  for identity in ["pid","uid","birth","bundle"] {
   for recipient in ["app","target","window","focusedElement"] {
    let f=Fixture(),proof=try f.bind();f.mismatch=identity
    switch recipient {
    case "app":f.foreign=f.app
    case "target":f.foreign=f.target
    case "window":f.foreign=f.window
    default:f.selectedElement=f.other;f.foreign=f.other
    }
    XCTAssertThrowsError(try proof.keyboardFocused(Budget(milliseconds:1000),runtime:f.runtime)){error in
     XCTAssertEqual((error as? NativeFailure)?.code,"foregroundAXOwnerMismatch")
    }
   }
  }
 }
 func testFocusRaceAndReparentAfterAcquisitionCannotPostKeyboardEvent()throws {
  for mode in ["element","focusedFlag","association"] {
   let f=Fixture(),proof=try f.bind();var samples=0,input=0
   let base=f.runtime
   let runtime=ScopedNativeRootRuntime(attribute:{element,name in
    if name==kAXFocusedUIElementAttribute {
     samples+=1
     if samples==2 {
      switch mode {
      case "element":f.selectedElement=f.other
      case "focusedFlag":f.targetFocused=false
      default:f.associated=f.other
      }
     }
    }
    return base.attribute(element,name)
   },owner:base.owner)
   let inputs=InputSafety();inputs.enable()
   XCTAssertThrowsError(try KeyboardPosting.press(inputs:inputs,token:"key",delivery:.process,preflight:{
    guard try proof.keyboardFocused(Budget(milliseconds:1000),runtime:runtime) else{throw NativeFailure("focusNotObserved","fixture")}
   },down:{_ in input+=1;return true},up:{_ in true}))
   XCTAssertEqual(input,0,mode)
  }
 }
 func testWindowlessMenuCannotQualifyKeyboardEvenWhenSemanticActionCan()throws {
  let f=Fixture();f.associated=nil
  let proof=try AXSemanticForegroundRecipient.bind(element:f.target,application:f.app,pid:f.pid,uid:f.uid,birth:f.birth,bundle:f.bundle,menuRoot:true,budget:Budget(milliseconds:100),runtime:f.runtime)
  XCTAssertTrue(try proof.focused(Budget(milliseconds:100),runtime:f.runtime))
  XCTAssertThrowsError(try proof.keyboardFocused(Budget(milliseconds:100),runtime:f.runtime))
 }
 func testOnlyNamedReferenceKeyboardRoutesUseAXRecipientProof() {
  XCTAssertEqual(NativeForegroundRoutes.focusedKeyboard,Set(["elements.pressKey","elements.pressSessionKey"]))
  for method in ["input.key","input.text","input.pointer","windows.setPosition","windows.pressSessionKey","windows.typeText","windows.clickFrame"] {
   XCTAssertFalse(NativeForegroundRoutes.focusedKeyboard.contains(method),method)
  }
 }
}
