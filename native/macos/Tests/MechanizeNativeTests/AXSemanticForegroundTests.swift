import XCTest
import AppKit
import ApplicationServices
import MechanizeNativeCore
@testable import MechanizeNative

final class AXSemanticForegroundTests:XCTestCase {
 final class Fixture {
  let pid:pid_t=42000,uid:uid_t=501,birth="123:456",bundle="com.fixture.app"
  let app=AXUIElementCreateApplication(42000),target=AXUIElementCreateApplication(42001),window=AXUIElementCreateApplication(42002),other=AXUIElementCreateApplication(42003)
  var selected:AXUIElement?,associated:AXUIElement?,foreign:AXUIElement?,reads:[String]=[]
  var missingRole=false
  init(){selected=window;associated=window}
  func owner(_ element:AXUIElement)->AXElementOwner{AXElementOwner(pid:foreign.map{CFEqual(element,$0)} == true ? 77:pid,uid:uid,birth:birth,bundle:bundle,status:AXError.success.rawValue)}
  var runtime:ScopedNativeRootRuntime{ScopedNativeRootRuntime(attribute:{element,name in
   self.reads.append(name)
   switch name {
   case kAXRoleAttribute:
    if self.missingRole{return(.cannotComplete,nil)}
    return(.success,(CFEqual(element,self.target) ? kAXTextAreaRole:kAXWindowRole) as CFString)
   case kAXWindowAttribute:
    XCTAssertTrue(CFEqual(element,self.target));return self.associated.map{(.success,$0 as CFTypeRef)} ?? (.noValue,nil)
   case kAXFocusedWindowAttribute:
    XCTAssertTrue(CFEqual(element,self.app));return self.selected.map{(.success,$0 as CFTypeRef)} ?? (.noValue,nil)
   default:XCTFail("semantic proof read geometry/content: \(name)");return(.cannotComplete,nil)
   }
  },owner:{self.owner($0)})}
  func bind()throws->AXSemanticForegroundRecipient{try AXSemanticForegroundRecipient.bind(element:target,application:app,pid:pid,uid:uid,birth:birth,bundle:bundle,menuRoot:false,budget:Budget(milliseconds:1000),runtime:runtime)}
 }
 func testSameAXFocusAcceptsWithoutCGGeometryEvenWhenWindowBoundsCoincide()throws {
  let f=Fixture(),proof=try f.bind()
  let bounds=CGRect(x:10,y:46,width:1292,height:735)
  let physical=[SessionKeyWindow(id:208,pid:f.pid,layer:0,visible:true,alpha:1,bounds:bounds),SessionKeyWindow(id:209,pid:f.pid,layer:0,visible:true,alpha:1,bounds:bounds)]
  XCTAssertEqual(physical.filter{$0.bounds==bounds}.count,2)
  XCTAssertTrue(try proof.focused(Budget(milliseconds:1000),runtime:f.runtime))
  f.selected=f.other
  XCTAssertFalse(try proof.focused(Budget(milliseconds:1000),runtime:f.runtime),"same geometry must never equate different AX windows")
  XCTAssertTrue(Set(f.reads).isSubset(of:[kAXRoleAttribute,kAXWindowAttribute,kAXFocusedWindowAttribute]))
 }
 func testMissingWindowNilFocusForeignOwnerAndStaleAssociationDenyBeforeInput()throws {
  for mode in ["window","focus","foreignTarget","foreignWindow","foreignFocus","foreignApp","association","role"] {
   let f=Fixture(),proof=try f.bind();var input=0
   switch mode {
   case "window":f.associated=nil
   case "focus":f.selected=nil
   case "foreignTarget":f.foreign=f.target
   case "foreignWindow":f.foreign=f.window
   case "foreignFocus":f.selected=f.other;f.foreign=f.other
   case "foreignApp":f.foreign=f.app
   case "association":f.associated=f.other
   default:f.missingRole=true
   }
   do{if try proof.focused(Budget(milliseconds:100),runtime:f.runtime){input+=1};XCTFail("invalid recipient accepted: \(mode)")}catch let failure as NativeFailure{XCTAssertTrue(["foregroundAXWindowUnavailable","foregroundAXFocusUnavailable","foregroundAXOwnerMismatch","foregroundAXWindowChanged"].contains(failure.code))}
   XCTAssertEqual(input,0)
  }
 }
 func testExactAXWindowRaisesOnceThenConfirmsBeforeSemanticInput()throws {
  let f=Fixture(),proof=try f.bind();f.selected=f.other
  var activation=0,raises=0,input=0,events:[String]=[]
  let budget=try Budget(milliseconds:1000)
  let runtime=ForegroundAcquisitionRuntime(validate:{try proof.validate(budget,runtime:f.runtime)},ready:{try proof.focused(budget,runtime:f.runtime)},activate:{activation+=1;events.append("activate");return true},needsRaise:{try !proof.focused(budget,runtime:f.runtime)},raise:{raises+=1;events.append("raise");f.selected=f.window;return true},pause:{_ in})
  try acquireNativeForeground(budget,runtime:runtime,reserve:{events.append("prepare")},publish:{_ in})
  try proof.validate(budget,runtime:f.runtime)
  guard try proof.focused(budget,runtime:f.runtime) else{XCTFail("input recipient not confirmed");return}
  input+=1;events.append("input")
  XCTAssertEqual(activation,1);XCTAssertEqual(raises,1);XCTAssertEqual(input,1);XCTAssertEqual(events,["prepare","activate","raise","input"])
 }
 func testAlreadyExactFocusDoesNotActivateOrRaise()throws {
  let f=Fixture(),proof=try f.bind(),budget=try Budget(milliseconds:100)
  let runtime=ForegroundAcquisitionRuntime(validate:{try proof.validate(budget,runtime:f.runtime)},ready:{try proof.focused(budget,runtime:f.runtime)},activate:{XCTFail("activation");return false},needsRaise:{XCTFail("raise probe");return false},raise:{XCTFail("raise");return false},pause:{_ in XCTFail("wait")})
  try acquireNativeForeground(budget,runtime:runtime,reserve:{XCTFail("reservation")},publish:{XCTAssertTrue($0.confirmed || !$0.activationRequested)})
 }
 func testChangedOwnershipDuringActivationAndUnsettledFocusNeverInput()throws {
  for revoked in [true,false]{
   let f=Fixture(),proof=try f.bind();f.selected=f.other
   var raises=0,input=0
   let budget=try Budget(milliseconds:1000)
   let runtime=ForegroundAcquisitionRuntime(validate:{try proof.validate(budget,runtime:f.runtime)},ready:{try proof.focused(budget,runtime:f.runtime)},activate:{if revoked{f.foreign=f.target};return true},needsRaise:{true},raise:{raises+=1;return true},pause:{_ in})
   XCTAssertThrowsError(try acquireNativeForeground(budget,runtime:runtime,reserve:{},publish:{_ in}))
   if (try? proof.focused(budget,runtime:f.runtime)) == true{input+=1}
   XCTAssertEqual(input,0);XCTAssertEqual(raises,revoked ? 0:1)
  }
 }
 func testWindowlessMenuRequiresOwnedMenuScopeAndNeverAdoptsLaterWindow()throws {
  let f=Fixture();f.associated=nil
  XCTAssertThrowsError(try f.bind())
  let proof=try AXSemanticForegroundRecipient.bind(element:f.target,application:f.app,pid:f.pid,uid:f.uid,birth:f.birth,bundle:f.bundle,menuRoot:true,budget:Budget(milliseconds:100),runtime:f.runtime)
  XCTAssertTrue(try proof.focused(Budget(milliseconds:100),runtime:f.runtime))
  f.associated=f.window
  XCTAssertThrowsError(try proof.validate(Budget(milliseconds:100),runtime:f.runtime))
 }
 func testFocusChangesDuringRecipientProofFailClosed()throws {
  let f=Fixture(),proof=try f.bind();var samples=0
  let base=f.runtime
  let runtime=ScopedNativeRootRuntime(attribute:{element,name in
   if name==kAXFocusedWindowAttribute{samples+=1;if samples==2{f.selected=f.other}}
   return base.attribute(element,name)
  },owner:base.owner)
  XCTAssertThrowsError(try proof.focused(Budget(milliseconds:100),runtime:runtime)){error in XCTAssertEqual((error as? NativeFailure)?.code,"foregroundAXFocusChanged")}
  XCTAssertEqual(samples,2)
 }
 func testSemanticRoutesExcludeEveryEventInputAndPhysicalRoute(){
  XCTAssertEqual(NativeForegroundRoutes.semantic,Set(["elements.focus","elements.press","elements.showMenu","elements.submit","elements.setValue","elements.replaceText"]))
  for method in ["elements.pressKey","elements.pressSessionKey","input.key","input.text","input.pointer","windows.setPosition","windows.pressSessionKey","windows.typeText","windows.clickFrame"]{XCTAssertFalse(NativeForegroundRoutes.semantic.contains(method));XCTAssertTrue(NativeForegroundRoutes.requiresAcquisition(method))}
 }
 func testScopeReparentAfterPreparationStillBlocksExactWindowSemanticInput()throws {
  let f=Fixture(),proof=try f.bind(),root=AXUIElementCreateApplication(42004)
  var reparented=false,input=0
  let scopedRuntime=ScopedNativeRootRuntime(attribute:{element,name in
   if name==kAXFocusedUIElementAttribute{return(.success,root)}
   if name==kAXParentAttribute{return(.success,reparented ? f.app:root)}
   XCTFail("unexpected scoped read");return(.cannotComplete,nil)
  },owner:{f.owner($0)})
  let scope=try ScopedNativeRoot.resolve(.focusedElement,application:f.app,pid:f.pid,uid:f.uid,birth:f.birth,bundle:f.bundle,check:{},runtime:scopedRuntime)
  let budget=try Budget(milliseconds:100)
  let runtime=ForegroundAcquisitionRuntime(validate:{try scope.validate(referenceElement:f.target,check:{try budget.check()},runtime:scopedRuntime);try proof.validate(budget,runtime:f.runtime)},ready:{try proof.focused(budget,runtime:f.runtime)},activate:{XCTFail("already focused");return false},needsRaise:{false},raise:{false},pause:{_ in})
  try acquireNativeForeground(budget,runtime:runtime,reserve:{},publish:{_ in})
  reparented=true
  do{try runtime.validate();input+=1;XCTFail("reparented target admitted")}catch{}
  XCTAssertEqual(input,0)
 }
}
