import XCTest
import AppKit
import MechanizeNativeCore
@testable import MechanizeNative
final class ForegroundAcquisitionTests:XCTestCase {
 func testDelayedPreparationActivatesAndRaisesOnceBeforeBusinessInput()throws {
  var activated=0,raised=0,observations=0,inputs=0,reservations=0;var last=ForegroundAcquisitionReceipt()
  let runtime=ForegroundAcquisitionRuntime(validate:{},ready:{observations+=1;return observations>=4},activate:{activated+=1;return true},needsRaise:{true},raise:{raised+=1;return true},pause:{_ in})
  let budget=try Budget(milliseconds:1000)
  try acquireNativeForeground(budget,runtime:runtime,reserve:{reservations+=1},publish:{last=$0})
  try budget.check();inputs+=1
  XCTAssertEqual(activated,1);XCTAssertEqual(raised,1);XCTAssertEqual(reservations,1);XCTAssertEqual(inputs,1);XCTAssertTrue(last.confirmed)
 }
 func testAlreadyQualifiedTargetDoesNotActivateRaiseOrReserve()throws {
  var metadata=ForegroundAcquisitionReceipt()
  let runtime=ForegroundAcquisitionRuntime(validate:{},ready:{true},activate:{XCTFail("unnecessary activation");return false},needsRaise:{XCTFail("unnecessary raise probe");return false},raise:{XCTFail("unnecessary raise");return false},pause:{_ in XCTFail("unnecessary wait")})
  try acquireNativeForeground(Budget(milliseconds:100),runtime:runtime,reserve:{XCTFail("unnecessary reservation")},publish:{metadata=$0})
  XCTAssertTrue(metadata.confirmed);XCTAssertFalse(metadata.activationRequested);XCTAssertFalse(metadata.windowRaiseRequested)
 }
 func testTransientRefreshOnlyRetriesObservationAndKeepsOriginalBudget()throws {
  var observed=0,activated=0;let budget=try Budget(milliseconds:1000)
  let runtime=ForegroundAcquisitionRuntime(validate:{try budget.check()},ready:{observed+=1;if observed<=2{throw NativeFailure("foregroundRefreshUnavailable","fixture")};return true},activate:{activated+=1;return true},needsRaise:{false},raise:{XCTFail("unexpected raise");return false},pause:{_ in})
  try acquireNativeForeground(budget,runtime:runtime,reserve:{},publish:{_ in})
  XCTAssertEqual(activated,1);XCTAssertEqual(observed,3)
 }
 func testChangedOwnershipAndRevokedAuthorityNeverDispatchInput()throws {
  for denyAt in [1,3,5] {
   var validations=0,activated=0,input=0
   let runtime=ForegroundAcquisitionRuntime(validate:{validations+=1;if validations>=denyAt{throw NativeFailure("staleReference","fixture")}},ready:{false},activate:{activated+=1;return true},needsRaise:{false},raise:{false},pause:{_ in})
   do{try acquireNativeForeground(Budget(milliseconds:100),runtime:runtime,reserve:{},publish:{_ in});input+=1;XCTFail("revoked acquisition accepted")}catch{}
   XCTAssertEqual(input,0);XCTAssertLessThanOrEqual(activated,1)
  }
 }
 func testDeadlineAfterActivationIsVisibilityOnlyAndDoesNotRaiseOrInput()throws {
  var receipt=ForegroundAcquisitionReceipt(),activated=0,inputs=0
  let runtime=ForegroundAcquisitionRuntime(validate:{},ready:{false},activate:{activated+=1;Thread.sleep(forTimeInterval:0.01);return true},needsRaise:{XCTFail("expired raise probe");return true},raise:{XCTFail("expired raise");return true},pause:{_ in})
  do{try acquireNativeForeground(Budget(milliseconds:5),runtime:runtime,reserve:{},publish:{receipt=$0});inputs+=1;XCTFail("expired acquisition accepted")}catch{}
  XCTAssertEqual(activated,1);XCTAssertEqual(inputs,0);XCTAssertTrue(receipt.activationRequested);XCTAssertFalse(receipt.windowRaiseRequested);XCTAssertFalse(receipt.confirmed)
 }
 func testUnconfirmedRaiseRetainsDistinctPreparationAndNoBusinessDispatch()throws {
  var receipt=ForegroundAcquisitionReceipt(),activated=0,raised=0
  let runtime=ForegroundAcquisitionRuntime(validate:{},ready:{false},activate:{activated+=1;return true},needsRaise:{true},raise:{raised+=1;return false},pause:{_ in})
  XCTAssertThrowsError(try acquireNativeForeground(Budget(milliseconds:100),runtime:runtime,reserve:{},publish:{receipt=$0}))
  XCTAssertEqual(activated,1);XCTAssertEqual(raised,1);XCTAssertTrue(receipt.activationRequested);XCTAssertTrue(receipt.windowRaiseRequested);XCTAssertFalse(receipt.confirmed)
 }
 func testPreparationReservationRemainsDeduplicatedWithoutInputReceiptPromotion()throws {
  let ledger=MutationLedger();let id="original";var activated=0
  let runtime=ForegroundAcquisitionRuntime(validate:{},ready:{false},activate:{activated+=1;return false},needsRaise:{false},raise:{false},pause:{_ in})
  var facts=ForegroundAcquisitionReceipt()
  XCTAssertThrowsError(try acquireNativeForeground(Budget(milliseconds:100),runtime:runtime,reserve:{try ledger.reserve(id)},publish:{facts=$0}))
  ledger.finish(id,reply:["receipt":["dispatchState":"notDispatched"],"foregroundAcquisition":facts.metadata])
  XCTAssertEqual((ledger.reply(for:id)?["receipt"] as? [String:String])?["dispatchState"],"notDispatched")
  XCTAssertThrowsError(try ledger.reserve(id));XCTAssertEqual(activated,1)
 }
 func testAllNativeInputRoutesAndNoObservationRoutesRequirePreparation(){
  for method in ["elements.focus","elements.press","elements.submit","elements.setValue","elements.replaceText","elements.showMenu","elements.pressKey","elements.pressSessionKey","input.key","input.text","input.pointer","windows.setPosition","windows.pressSessionKey","windows.typeText","windows.clickFrame"]{XCTAssertTrue(NativeForegroundRoutes.requiresAcquisition(method),method)}
  for method in ["doctor","apps.list","windows.list","elements.snapshot","elements.read","elements.valueMatches","windows.captureFrame","capture.image","capture.windows","app.quit","app.launch","app.activate","controlBadge.begin"]{XCTAssertFalse(NativeForegroundRoutes.requiresAcquisition(method),method)}
 }
 func testFocusOnlyInvalidationCannotHideStructuralChanges(){
  let signal=HierarchySignal();signal.focusChanged();XCTAssertEqual(signal.revision,1);XCTAssertEqual(signal.structuralRevision,0)
  signal.changed();XCTAssertEqual(signal.revision,2);XCTAssertEqual(signal.structuralRevision,1)
  signal.retire();signal.focusChanged();signal.changed();XCTAssertEqual(signal.revision,2);XCTAssertEqual(signal.structuralRevision,1)
 }
}

extension ForegroundAcquisitionTests {
 func testAcknowledgedFocusRevisionCannotCoverStructuralOrFailedTargetProof()throws {
  let signal=HierarchySignal();signal.focusChanged();var reads=0
  let accepted=try confirmNativeFocusTransition(signal,structural:0,revalidate:{reads+=1;signal.focusChanged()})
  XCTAssertEqual(accepted,2);XCTAssertEqual(reads,1)
  XCTAssertThrowsError(try confirmNativeFocusTransition(signal,structural:0,revalidate:{throw NativeFailure("staleReference","fixture")}))
  XCTAssertThrowsError(try confirmNativeFocusTransition(signal,structural:0,revalidate:{signal.changed()}))
  XCTAssertThrowsError(try confirmNativeFocusTransition(signal,structural:0,revalidate:{XCTFail("structural change was ignored")}))
 }
}

extension ForegroundAcquisitionTests {
 func testPointerPreparationSelectsExactWindowWhileKeyboardRetainsTopWindowBarrier()throws {
  let bounds=CGRect(x:0,y:0,width:800,height:600)
  func window(_ id:UInt32,_ layer:Int,_ pid:pid_t=42)->SessionKeyWindow {SessionKeyWindow(id:id,pid:pid,layer:layer,visible:true,alpha:1,bounds:bounds)}
  let utility=window(8,101),main=window(7,0)
  XCTAssertTrue(NativeForegroundTarget.physicalWindowReady([utility,main],pid:42,windowID:7,pointerDelivery:true))
  XCTAssertFalse(NativeForegroundTarget.physicalWindowReady([utility,main],pid:42,windowID:7,pointerDelivery:false))
  for layer in [0,3,8] {
   XCTAssertTrue(NativeForegroundTarget.physicalWindowReady([window(9,layer),main],pid:42,windowID:7,pointerDelivery:true))
   XCTAssertFalse(NativeForegroundTarget.physicalWindowReady([window(9,layer),main],pid:42,windowID:7,pointerDelivery:false))
  }
  XCTAssertFalse(NativeForegroundTarget.physicalWindowReady([utility],pid:42,windowID:7,pointerDelivery:true))
  for rows in [[window(7,0,77)],[main,main],[window(7,101)]] {
   XCTAssertFalse(NativeForegroundTarget.physicalWindowReady(rows,pid:42,windowID:7,pointerDelivery:true))
  }
  var activations=0,raises=0,reserves=0
  let runtime=ForegroundAcquisitionRuntime(validate:{},ready:{NativeForegroundTarget.physicalWindowReady([window(9,8),main],pid:42,windowID:7,pointerDelivery:true)},activate:{activations+=1;return true},needsRaise:{true},raise:{raises+=1;throw NativeFailure("incompleteObservation","Unsupported unrelated AXWindows entry")},pause:{_ in})
  try acquireNativeForeground(Budget(milliseconds:100),runtime:runtime,reserve:{reserves+=1},publish:{_ in})
  XCTAssertEqual(activations,0);XCTAssertEqual(raises,0);XCTAssertEqual(reserves,0)
 }
}

extension ForegroundAcquisitionTests {
 func testPhysicalCensusDiagnosticsAreFinitePhaseSpecificAndNeverInput()throws {
  func row(id:UInt32=7,pid:pid_t=42,layer:Int=0,visible:Bool=true,alpha:Double=1)->SessionKeyWindow {SessionKeyWindow(id:id,pid:pid,layer:layer,visible:visible,alpha:alpha,bounds:CGRect(x:0,y:0,width:800,height:600))}
  let cases:[([SessionKeyWindow],String)]=[([],"Missing"),([row(pid:99)],"Missing"),([row(visible:false)],"Invisible"),([row(layer:101)],"UnsupportedLayer"),([row(alpha:0)],"ZeroAlpha"),([row(alpha:Double.nan)],"AlphaUnavailable"),([row(),row()],"Ambiguous")]
  var inputs=0
  for (rows,reason) in cases {
   do{_=try NativeForegroundTarget.physicalWindow(rows,pid:42,windowID:7,phase:.preflight);inputs+=1;XCTFail("ineligible census accepted")}catch let e as NativeFailure{XCTAssertEqual(e.code,"foregroundWindow"+reason);XCTAssertFalse(e.message.contains("https://"));XCTAssertFalse(e.message.contains("permission"))}
  }
  for (rows,reason) in [([SessionKeyWindow](),"Missing"),([row(visible:false)],"Invisible"),([row(),row()],"Ambiguous")] {
   XCTAssertThrowsError(try NativeForegroundTarget.physicalWindow(rows,pid:42,windowID:7,phase:.raise)){error in XCTAssertEqual((error as? NativeFailure)?.code,"foregroundRaiseWindow"+reason)}
  }
  XCTAssertEqual(inputs,0);XCTAssertEqual(try NativeForegroundTarget.physicalWindow([row()],pid:42,windowID:7,phase:.preflight).id,7)
 }
}

extension ForegroundAcquisitionTests {
 func testPhysicalDiagnosticsPreserveExistingCensusAdmissionPredicates()throws {
  for phase in [NativeForegroundTarget.PhysicalPhase.preflight,.raise] {
   for pid:pid_t in [42,99] {for layer in [0,3,8,101] {for visible in [true,false] {for alpha in [0.0,1.0,Double.nan] {
    let row=SessionKeyWindow(id:7,pid:pid,layer:layer,visible:visible,alpha:alpha,bounds:CGRect(x:0,y:0,width:800,height:600))
    let before=pid==42 && visible && (phase == .raise || [0,3,8].contains(layer)&&alpha>0)
    let after=(try? NativeForegroundTarget.physicalWindow([row],pid:42,windowID:7,phase:phase)) != nil
    XCTAssertEqual(after,before)
   }}}}
  }
 }
}
