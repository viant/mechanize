import Foundation

/// Exact same-path whole-bundle replacement. The original complete bundle is
/// retained by the writer; no nested helper is an independent writable target.
struct MigrationUnifiedUpdateManifest {
    let artifact: [String:Any]
    let bundle: URL
    init(runtime: [String:Any], intent: MigrationUpgradeIntent) throws {
        let bundle=FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Applications/Mechanize.app")
        guard runtime["Mode"] as? String == "unified-app-update-v3", intent.newCanonicalExecutable == nil,
              intent.options[0] == bundle.appendingPathComponent("Contents/Helpers/mechanize").path,
              runtime["BrokerPath"] as? String == intent.options[0], runtime["NewBrokerPath"] == nil,
 let config=runtime["ConfigPath"] as? String, MigrationRuntimeConsoleManifest.path(config), URL(fileURLWithPath:config).lastPathComponent == "config.json", !MigrationPreservedExtensionManifest.overlap(URL(fileURLWithPath:config).deletingLastPathComponent().path,bundle.path),
              runtime["preinstalledUnifiedApp"] == nil, runtime["preinstalledApprovalConsole"] == nil,
              runtime["ApprovalConsole"] == nil, runtime["OriginalConsoleArtifact"] == nil,
              runtime["OldBrokerRequirement"] as? String == intent.options[1], runtime["NewBrokerRequirement"] as? String == intent.options[2],
              let artifacts=runtime["Artifacts"] as? [[String:Any]], artifacts.count == 1, let app=artifacts.first,
              app["role"] as? String == "unified-app", app["target"] as? String == bundle.path,
              let candidate=app["candidate"] as? String, MigrationRuntimeConsoleManifest.path(candidate), !MigrationPreservedExtensionManifest.overlap(candidate,bundle.path),
              let old=app["Old"] as? [String:Any], let new=app["New"] as? [String:Any],
              let oldDigest=app["OldDigest"] as? String, let newDigest=app["NewDigest"] as? String, oldDigest != newDigest,
              try MigrationUnifiedAppManifest.inventoryDigest(old)==oldDigest, try MigrationUnifiedAppManifest.inventoryDigest(new)==newDigest,
              let oldPin=app["OldRequirement"] as? String, MigrationAuthorizationRecord.requirement(oldPin,role:"consent"),
              let newPin=app["NewRequirement"] as? String, MigrationAuthorizationRecord.requirement(newPin,role:"consent"),
              let roles=runtime["LegacyArtifacts"] as? [[String:Any]], roles.count==3,
              Set(roles.compactMap{$0["role"] as? String})==Set(["helper","native-host","console"]) else {throw MigrationUpgradeError.invalidPreparation}
        var preservation=runtime;preservation["Mode"]="preserve-extension-v1";preservation["Artifacts"]=roles
        let preserved=try MigrationPreservedExtensionManifest(runtime:preservation)
        guard !MigrationPreservedExtensionManifest.overlap(preserved.path,bundle.path), !MigrationPreservedExtensionManifest.overlap(preserved.path,candidate) else{throw MigrationUpgradeError.invalidPreparation}
        for entry in roles {
            let role=entry["role"] as? String ?? "", suffix=role=="helper" ? "native" : role=="console" ? "consent" : "chrome.nativehost"
            guard let a=entry["OldRequirement"] as? String, let b=entry["NewRequirement"] as? String, MigrationAuthorizationRecord.requirement(a,role:suffix), MigrationAuthorizationRecord.requirement(b,role:suffix),
                  let oldView=entry["Old"] as? [String:Any], let newView=entry["New"] as? [String:Any],
                  try MigrationUnifiedAppManifest.inventoryDigest(oldView)==entry["OldDigest"] as? String,
                  try MigrationUnifiedAppManifest.inventoryDigest(newView)==entry["NewDigest"] as? String else{throw MigrationUpgradeError.invalidPreparation}
            if role=="console" {
                guard entry["target"] as? String==bundle.path, entry["candidate"] as? String==candidate,
                      NSDictionary(dictionary:oldView).isEqual(to:old),NSDictionary(dictionary:newView).isEqual(to:new),a==oldPin,b==newPin else{throw MigrationUpgradeError.invalidPreparation}
            } else {
                let relative="Contents/Helpers/"+(role=="helper" ? "mechanize-native" : "mechanize-native-host")
                guard entry["target"] as? String==bundle.appendingPathComponent(relative).path, entry["candidate"] as? String==URL(fileURLWithPath:candidate).appendingPathComponent(relative).path,
                      Set(oldView.keys)==["."],Set(newView.keys)==["."],let oldEntry=oldView["."] as? NSDictionary, let newEntry=newView["."] as? NSDictionary,
                      let oldFull=old[relative] as? [String:Any],let newFull=new[relative] as? [String:Any],oldEntry.isEqual(to:oldFull),newEntry.isEqual(to:newFull) else{throw MigrationUpgradeError.invalidPreparation}
                if role=="helper" {guard runtime["ActiveHelperPath"] as? String==entry["target"] as? String, runtime["ActiveHelperRequirement"] as? String==a,runtime["ActiveHelperSHA256"] as? String==oldFull["sha256"] as? String else{throw MigrationUpgradeError.invalidPreparation}}
            }
        }
        for inventory in [old,new] {for name in ["Contents/MacOS/MechanizeConsent","Contents/Helpers/mechanize","Contents/Helpers/mechanize-native","Contents/Helpers/mechanize-native-host"] {
            guard let file=inventory[name] as? [String:Any],file["kind"] as? String=="file",let mode=MigrationRuntimeConsoleManifest.integer(file["mode"]),[0o700,0o755].contains(mode) else{throw MigrationUpgradeError.invalidPreparation}
        }}
        self.artifact=app;self.bundle=bundle
    }
}
