import Foundation
import CoreFoundation

/// Initial whole-app relocation only. Legacy artifacts remain read-only evidence;
/// this does not authorize replacement or deletion of any old installation.
struct MigrationUnifiedAppManifest {
    let artifact: [String:Any]
    let bundle: URL
    init(runtime: [String:Any], intent: MigrationUpgradeIntent) throws {
 if runtime["Mode"] as? String == "unified-app-update-v3" { let update = try MigrationUnifiedUpdateManifest(runtime:runtime,intent:intent); self.artifact=update.artifact; self.bundle=update.bundle; return }
        if let value=runtime["preinstalledUnifiedApp"] {
            guard let flag=value as? NSNumber,CFGetTypeID(flag)==CFBooleanGetTypeID(),flag.boolValue else {throw MigrationUpgradeError.invalidPreparation}
        }
        let bundle = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Applications/Mechanize.app")
        guard runtime["Mode"] as? String == "unified-app-v2", runtime["ConfigPath"] == nil,
              let destination = intent.newCanonicalExecutable,
              destination == bundle.appendingPathComponent("Contents/Helpers/mechanize").path,
              runtime["NewBrokerPath"] as? String == destination,
              runtime["BrokerPath"] as? String == intent.options[0],
              runtime["OldBrokerRequirement"] as? String == intent.options[1],
              runtime["NewBrokerRequirement"] as? String == intent.options[2],
              let artifacts = runtime["Artifacts"] as? [[String:Any]], artifacts.count == 1,
              let artifact = artifacts.first, artifact["role"] as? String == "unified-app",
              artifact["target"] as? String == bundle.path,
              let candidate = artifact["candidate"] as? String, MigrationRuntimeConsoleManifest.path(candidate),
              !MigrationPreservedExtensionManifest.overlap(candidate,bundle.path),
              let old = artifact["Old"] as? [String:Any], old.isEmpty,
              artifact["OldDigest"] as? String == "", artifact["OldRequirement"] as? String == "",
              let new = artifact["New"] as? [String:Any], new.count <= 4096,
              let digest = artifact["NewDigest"] as? String, MigrationAuthorizationRecord.digest(digest),
              let pin = artifact["NewRequirement"] as? String, MigrationAuthorizationRecord.requirement(pin,role:"consent"),
              let legacy = runtime["LegacyArtifacts"] as? [[String:Any]], legacy.count == 3,
              Set(legacy.compactMap { $0["role"] as? String }) == Set(["helper","native-host","console"]) else { throw MigrationUpgradeError.invalidPreparation }
        guard try Self.inventoryDigest(new) == digest else { throw MigrationUpgradeError.invalidPreparation }
        // Existing preserved-extension checks retain their original full strength.
        var preserved = runtime; preserved["Mode"] = "preserve-extension-v1"; preserved["Artifacts"] = legacy
        let extensionManifest = try MigrationPreservedExtensionManifest(runtime:preserved)
        guard !MigrationPreservedExtensionManifest.overlap(extensionManifest.path,bundle.path),
              !MigrationPreservedExtensionManifest.overlap(extensionManifest.path,candidate),
              !MigrationPreservedExtensionManifest.overlap(intent.options[0],bundle.path) else { throw MigrationUpgradeError.invalidPreparation }
        for entry in legacy {
            let role = entry["role"] as? String == "console" ? "consent" : entry["role"] as? String == "helper" ? "native" : "chrome.nativehost"
            guard let oldPin = entry["OldRequirement"] as? String, MigrationAuthorizationRecord.requirement(oldPin,role:role),
                  let newPin = entry["NewRequirement"] as? String, MigrationAuthorizationRecord.requirement(newPin,role:role) else { throw MigrationUpgradeError.invalidPreparation }
            guard let target = entry["target"] as? String, !MigrationPreservedExtensionManifest.overlap(target,bundle.path) else { throw MigrationUpgradeError.invalidPreparation }
            guard let oldInventory = entry["Old"] as? [String:Any], let oldDigest = entry["OldDigest"] as? String,
                  try Self.inventoryDigest(oldInventory) == oldDigest else { throw MigrationUpgradeError.invalidPreparation }
            if entry["role"] as? String == "console" {
                guard entry["candidate"] as? String == candidate, entry["NewRequirement"] as? String == pin,
                      let inventory = entry["New"] as? NSDictionary, inventory.isEqual(to:new), entry["NewDigest"] as? String == digest else { throw MigrationUpgradeError.invalidPreparation }
            } else {
                let relative = entry["role"] as? String == "helper" ? "Contents/Helpers/mechanize-native" : "Contents/Helpers/mechanize-native-host"
                guard entry["candidate"] as? String == URL(fileURLWithPath:candidate).appendingPathComponent(relative).path,
                      let inventory = entry["New"] as? [String:Any], Set(inventory.keys) == ["."],
                      let actual = inventory["."] as? NSDictionary, let expected = new[relative] as? [String:Any], actual.isEqual(to:expected),
                      let sha = entry["NewDigest"] as? String, try Self.inventoryDigest(inventory) == sha else { throw MigrationUpgradeError.invalidPreparation }
            }
        }
        for path in ["Contents/MacOS/MechanizeConsent","Contents/Helpers/mechanize","Contents/Helpers/mechanize-native","Contents/Helpers/mechanize-native-host"] {
            guard let entry = new[path] as? [String:Any], entry["kind"] as? String == "file",
                  let mode = MigrationRuntimeConsoleManifest.integer(entry["mode"]), [0o700,0o755].contains(mode),
                  let size = MigrationRuntimeConsoleManifest.integer(entry["size"]), size > 0,
                  let digest = entry["sha256"] as? String, MigrationAuthorizationRecord.digest(digest) else { throw MigrationUpgradeError.invalidPreparation }
        }
        self.artifact = artifact; self.bundle = bundle
    }
    static func inventoryDigest(_ inventory: [String:Any]) throws -> String {
        guard !inventory.isEmpty, inventory.count <= 4096 else { throw MigrationUpgradeError.invalidPreparation }
        var members: [String] = []; var total = 0
        for path in inventory.keys.sorted() {
            guard path == "." || (!path.hasPrefix("/") && MigrationRuntimeConsoleManifest.path("/" + path)),
                  let entry = inventory[path] as? [String:Any], Set(entry.keys) == ["kind","mode","size","sha256"],
                  let kind = entry["kind"] as? String, let mode = MigrationRuntimeConsoleManifest.integer(entry["mode"]),
                  [0o600,0o644,0o700,0o755].contains(mode),
                  let size = MigrationRuntimeConsoleManifest.integer(entry["size"]), size <= 512*1024*1024,
                  let hash = entry["sha256"] as? String else { throw MigrationUpgradeError.invalidPreparation }
            if kind == "directory" { guard size == 0, hash.isEmpty, [0o700,0o755].contains(mode) else { throw MigrationUpgradeError.invalidPreparation } }
            else { guard kind == "file", MigrationAuthorizationRecord.digest(hash) else { throw MigrationUpgradeError.invalidPreparation }; total += size }
            guard total <= 512*1024*1024 else { throw MigrationUpgradeError.invalidPreparation }
            let key = try MigrationWorkerSession.canonical(["v":path],order:["v"]).dropFirst(5).dropLast()
            let value = try MigrationWorkerSession.canonical(entry,order:["kind","mode","size","sha256"])
            guard let keyText = String(data:key,encoding:.utf8), let valueText = String(data:value,encoding:.utf8) else { throw MigrationUpgradeError.invalidPreparation }
            members.append(keyText + ":" + valueText)
        }
        return MigrationUpgradeIntent.digest(Data(("{" + members.joined(separator:",") + "}").utf8))
    }
}
