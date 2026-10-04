import Foundation

public enum KeyboardDelivery: String {case process;case session}
/// Immutable explicit route, never retry/fallback. Cleanup uses the SAME route.
public enum KeyboardPosting {
 public static func press(inputs:InputSafety,token:String,delivery:KeyboardDelivery,preflight:()throws->Void,down:(KeyboardDelivery)->Bool,up:@escaping(KeyboardDelivery)->Bool)throws {
  try inputs.press(token:token,preflight:preflight,down:{down(delivery)},up:{up(delivery)})
 }
}
public enum SessionWindowProof {
 public static func validate<Node>(target:Node,focusedWindow:Node,rootPID:Int32,owner:(Node)throws->Int32,role:(Node)throws->String,parent:(Node)throws->Node?,equal:(Node,Node)->Bool,recheck:()throws->Node,check:()throws->Void)throws {
  try check()
  guard try owner(focusedWindow)==rootPID,["AXSheet","AXWindow"].contains(try role(focusedWindow)) else {throw NativeFailure("sessionWindowUnqualified","Focused container must be same-process sheet/window")}
  var current=target,seen:[Node]=[]
  for _ in 0..<16 {
   try check()
   guard try owner(current)==rootPID else {throw NativeFailure("sessionWindowUnqualified","Target ancestry leaves exact root application")}
   guard !seen.contains(where:{equal($0,current)}) else {throw NativeFailure("sessionWindowUnqualified","Target parent cycle prevents exact container proof")}
   if equal(current,focusedWindow){
    try check()
    guard equal(try recheck(),focusedWindow) else {throw NativeFailure("sessionWindowUnqualified","Application focused container changed during ancestry proof")}
    try check();return
   }
   seen.append(current)
   guard let next=try parent(current) else {throw NativeFailure("sessionWindowUnqualified","Target is not inside exact application-focused container")}
   current=next
  }
  throw NativeFailure("sessionWindowUnqualified","Target ancestry exceeds bounded container proof")
 }
}
