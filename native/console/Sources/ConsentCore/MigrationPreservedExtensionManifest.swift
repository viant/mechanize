import Foundation
import CoreFoundation

/// Preservation has no writable extension artifact and no storage observation.
/// This early native check complements the Go installer's complete write-set and
/// frozen-config checks before any journal is created or artifact is placed.
struct MigrationPreservedExtensionManifest {
    let path: String, extensionID: String
    init(runtime: [String:Any]) throws {
        guard runtime["Mode"] as? String == "preserve-extension-v1", runtime["ExtensionStorageSHA256"] == nil,
              let entry=runtime["PreservedExtension"] as? [String:Any],Set(entry.keys)==Set(["path","extensionID","inventory","inventorySHA256"] + (entry["runtimeResourcesOnly"] == nil ? [] : ["runtimeResourcesOnly"])),
              let path=entry["path"] as? String,MigrationRuntimeConsoleManifest.path(path),
              let id=entry["extensionID"] as? String,id.count==32,id.allSatisfy({("a"..."p").contains(String($0))}),id==runtime["ExtensionID"] as? String,
              let inventory=entry["inventory"] as? [String:[String:Any]],
              let digest=entry["inventorySHA256"] as? String,MigrationAuthorizationRecord.digest(digest),
              try Self.inventoryDigest(inventory)==digest,
              let artifacts=runtime["Artifacts"] as? [[String:Any]],artifacts.count==3,
              Set(artifacts.compactMap{$0["role"] as? String})==Set(["helper","native-host","console"]),
              let chrome=runtime["ChromeRequirement"] as? String,!chrome.isEmpty,chrome.utf8.count<=4096 else{throw MigrationUpgradeError.invalidPreparation}
        if let runtimeOnly=entry["runtimeResourcesOnly"] {
            guard let flag=runtimeOnly as? NSNumber, CFGetTypeID(flag)==CFBooleanGetTypeID(), flag.boolValue,
                  Set(inventory.keys)==Set([".","browser.js","content.js","controller.js","dom.js","fingerprint.js","manifest.json","options.html","options.js","protocol.js","recorder.js","retirement.js","secure-input.js","setup-metadata.js","worker.js"]) else {throw MigrationUpgradeError.invalidPreparation}
        }
        if let recovery=runtime["ChromeRecovery"] {
            guard let fields=recovery as? [String:Any],Set(fields.keys)==Set(["originalConfig","originalChromeSHA256"]),
                  let reference=fields["originalConfig"] as? [String:Any],Set(reference.keys)==Set(["path","sha256"]),
                  let file=reference["path"] as? String,MigrationRuntimeConsoleManifest.path(file),
                  let sha=reference["sha256"] as? String,MigrationAuthorizationRecord.digest(sha),
                  let chromeSHA=fields["originalChromeSHA256"] as? String,MigrationAuthorizationRecord.digest(chromeSHA),
                  chrome.range(of:#"^identifier "com\.google\.Chrome" and (cdhash H"[a-f0-9]{40}"|\(cdhash H"[a-f0-9]{40}"( or cdhash H"[a-f0-9]{40}"){1,3}\))$"#,options:.regularExpression) != nil else {throw MigrationUpgradeError.invalidPreparation}
        }
        if let recordRoot=runtime["NativeRecordRoot"] {
            guard let recordRoot=recordRoot as? String,recordRoot==FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".secret/vault-records").path else{throw MigrationUpgradeError.invalidPreparation}
        }
        for artifact in artifacts {
            for key in ["target","candidate"] {
                guard let candidate=artifact[key] as? String,MigrationRuntimeConsoleManifest.path(candidate),
                      !Self.overlap(path,candidate) else{throw MigrationUpgradeError.invalidPreparation}
            }
        }
        self.path=path;extensionID=id
    }
    static func overlap(_ a:String,_ b:String)->Bool {a==b || a.hasPrefix(b+"/") || b.hasPrefix(a+"/")}
    static func inventoryDigest(_ inventory:[String:[String:Any]])throws->String {
        let base:Set<String>=["browser.js","content.js","dom.js","manifest.json","options.html","options.js","protocol.js","recorder.js","worker.js"]
        let additions=["fingerprint.js","retirement.js","setup-metadata.js","secure-input.js","controller.js"]
        guard (0...additions.count).contains(where:{Set(inventory.keys)==base.union(additions.prefix($0)).union(["."])}) else{throw MigrationUpgradeError.invalidPreparation}
        var members:[String]=[],total=0
        for name in inventory.keys.sorted() {
            guard let entry=inventory[name],Set(entry.keys)==Set(["kind","mode","size","sha256"]),
                  let kind=entry["kind"] as? String,let mode=MigrationRuntimeConsoleManifest.integer(entry["mode"]),
                  let size=MigrationRuntimeConsoleManifest.integer(entry["size"]),let sha=entry["sha256"] as? String else{throw MigrationUpgradeError.invalidPreparation}
            if name=="." {guard kind=="directory",[0o700,0o755].contains(mode),size==0,sha.isEmpty else{throw MigrationUpgradeError.invalidPreparation}}
            else {guard kind=="file",[0o600,0o644,0o700,0o755].contains(mode),size<=4*1024*1024,MigrationAuthorizationRecord.digest(sha) else{throw MigrationUpgradeError.invalidPreparation};total+=size}
            let encoded=try MigrationWorkerSession.canonical(["kind":kind,"mode":mode,"size":size,"sha256":sha],order:["kind","mode","size","sha256"])
            guard let text=String(data:encoded,encoding:.utf8) else{throw MigrationUpgradeError.invalidPreparation}
            members.append("\""+name+"\":"+text)
        }
        guard total<=16*1024*1024 else{throw MigrationUpgradeError.invalidPreparation}
        return MigrationUpgradeIntent.digest(Data(("{"+members.joined(separator:",")+"}").utf8))
    }
}
