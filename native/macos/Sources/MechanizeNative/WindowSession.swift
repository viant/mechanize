import Foundation
import CoreGraphics

// These public session facts describe console/login ownership. They do not
// prove an unlocked desktop or authorize AX/event posting.
func windowSession() -> [String: Any] {
    windowSessionState(CGSessionCopyCurrentDictionary() as? [String: Any])
}

func windowSessionState(_ dictionary: [String: Any]?) -> [String: Any] {
    let unavailable: [String: Any] = ["available": false, "onConsole": false, "loginDone": false, "uid": NSNull()]
    guard let dictionary,
          let console = dictionary[kCGSessionOnConsoleKey] as? NSNumber,
          CFGetTypeID(console) == CFBooleanGetTypeID(),
          let login = dictionary[kCGSessionLoginDoneKey] as? NSNumber,
          CFGetTypeID(login) == CFBooleanGetTypeID(),
          let user = dictionary[kCGSessionUserIDKey] as? NSNumber,
          CFGetTypeID(user) == CFNumberGetTypeID() else { return unavailable }
    let uid = user.doubleValue
    guard uid.isFinite, uid >= 0, uid <= Double(UInt32.max), uid.rounded(.towardZero) == uid else { return unavailable }
    return ["available": true, "onConsole": console.boolValue, "loginDone": login.boolValue, "uid": UInt32(uid)]
}
