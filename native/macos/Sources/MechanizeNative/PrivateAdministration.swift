import Foundation
import MechanizeNativeCore
import AppKit
import ApplicationServices
import Security

private func privateFailure(_ code:String = "privateProofUnavailable") -> NativeFailure { NativeFailure(code,"Independent private proof unavailable") }
private func privateSignature(_ pid: pid_t, _ text: String) throws {
    guard !text.isEmpty, text.utf8.count <= 4096, !text.contains("\0") else { throw privateFailure() }
    var requirement: SecRequirement?, code: SecCode?
    guard SecRequirementCreateWithString(text as CFString, [], &requirement) == errSecSuccess, let requirement,
          SecCodeCopyGuestWithAttributes(nil,[kSecGuestAttributePid as String:pid] as CFDictionary,[],&code) == errSecSuccess, let code,
          SecCodeCheckValidity(code,SecCSFlags(rawValue:kSecCSStrictValidate),requirement) == errSecSuccess else { throw privateFailure() }
}
func privateAdministrationResult(method:String,params:[String:Any],budget:Budget) throws -> [String:Any] {
    guard let nonce = params["nonce"] as? String, nonce.count == 64, nonce.allSatisfy({"0123456789abcdef".contains($0)}) else { throw privateFailure() }
    guard AXIsProcessTrusted() else { throw privateFailure("privateAXTrustDenied") }
    try budget.check()
    if method == "private.consoleWindows" {
        guard Set(params.keys) == ["nonce","consoleRequirement","entryID"],
              let requirement = params["consoleRequirement"] as? String,
              let entryID = params["entryID"] as? String, entryID.isEmpty || (entryID.count == 64 && entryID.allSatisfy({"0123456789abcdef".contains($0)})) else { throw privateFailure() }
        let apps = NSRunningApplication.runningApplications(withBundleIdentifier:"com.viant.mechanize.consent")
        guard apps.count <= 4 else { throw privateFailure("privateConsoleInventoryUnavailable") }
        var entries = 0, matched = 0
        for app in apps {
            let pid = app.processIdentifier
            guard let birth = applicationProcessStartToken(pid), applicationLoginUID(pid) == getuid() else { throw privateFailure("privateConsoleProcessInvalid") }
            do { try privateSignature(pid,requirement) } catch { throw privateFailure("privateConsoleSignatureInvalid") }
            func value(_ element:AXUIElement,_ name:String) throws -> CFTypeRef {
                try privateConsoleAXValue(element,name,pid:pid,budget:budget)
            }
            let root = AXUIElementCreateApplication(pid)
            guard let windows = try value(root,kAXWindowsAttribute) as? [AXUIElement], windows.count <= 32 else { throw privateFailure("privateWindowShapeUnavailable") }
            for window in windows {
                guard try value(window,kAXRoleAttribute) as? String == "AXWindow",
                      let title = try value(window,kAXTitleAttribute) as? String, title.utf8.count <= 1024 else { throw privateFailure("privateWindowShapeUnavailable") }
                if title.hasPrefix("Mechanize Secure Entry ") { entries += 1; if !entryID.isEmpty && title == "Mechanize Secure Entry " + entryID { matched += 1 } }
            }
            guard applicationProcessStartToken(pid) == birth, applicationLoginUID(pid) == getuid() else { throw privateFailure("privateConsoleProcessInvalid") }
            do { try privateSignature(pid,requirement) } catch { throw privateFailure("privateConsoleSignatureInvalid") }
        }
        try budget.check()
        return ["version":1,"nonce":nonce,"consoles":apps.count,"entries":entries,"matched":matched]
    }
    guard method == "private.managementProof", Set(params.keys) == ["nonce","pid","birth","title","extensionID","chromeRequirement","receipt"],
          let pid = params["pid"] as? Int32, pid > 0, let birth = params["birth"] as? String,
          let title = params["title"] as? String, !title.isEmpty, title.utf8.count <= 1024,
          let extensionID = params["extensionID"] as? String, let requirement = params["chromeRequirement"] as? String,
          let encoded = params["receipt"] as? String, let receipt = Data(base64Encoded:encoded), receipt.count <= 128*1024 else { throw privateFailure() }
    try privateSignature(pid,requirement)
    let result = try PrivateManagementOS.loadedManagementPath(receipt,pid,birth,title,extensionID)
    try budget.check(); try privateSignature(pid,requirement)
    return ["version":1,"nonce":nonce,"pid":pid,"birth":birth,"extensionID":extensionID,"path":result.0,"observedAtUnixMilliseconds":Int64(result.1.timeIntervalSince1970*1000)]
}
