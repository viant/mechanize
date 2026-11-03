import Foundation
import Testing
@testable import ConsentCore

struct ScyVaultImportTests {
    let origin = "https://login.example.test"
    func plain() -> Data { Data(#"{"Username":"fixture-user","Password":"fixture-password-canary"}"#.utf8) }
    func fixture() throws -> URL {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        try Data("synthetic-ciphertext".utf8).write(to: root.appendingPathComponent("account.enc"))
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: root.appendingPathComponent("account.enc").path)
        return root
    }
    @Test func importsThroughPrivateSnapshotAndOneShotFrame() throws {
        let root = try fixture(); defer { try? FileManager.default.removeItem(at: root) }
        var calls = 0
        let frame = try ScyVaultImport.frame(resourceName: "account.enc", origin: origin, root: root) { snapshot in
            calls += 1
            #expect(snapshot.deletingLastPathComponent().deletingLastPathComponent().path == root.path)
            #expect(snapshot.lastPathComponent != "account.enc")
            let copied = try Data(contentsOf: snapshot)
            let permissions = try FileManager.default.attributesOfItem(atPath: snapshot.path)[.posixPermissions] as? NSNumber
            #expect(copied == Data("synthetic-ciphertext".utf8))
            #expect(permissions?.intValue == 0o600)
            // Reproduce the installed Scy/AFS reader's directory chmod.
            try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: snapshot.deletingLastPathComponent().path)
            return plain()
        }
        #expect(calls == 1)
        let remaining = try FileManager.default.contentsOfDirectory(atPath: root.path)
        #expect(remaining == ["account.enc"])
        let rootPermissions = try FileManager.default.attributesOfItem(atPath: root.path)[.posixPermissions] as? NSNumber
        #expect(rootPermissions?.intValue == 0o700)
        #expect(!String(describing: frame).contains("fixture-password-canary"))
        try frame.writeOnce { bytes in
            let data = Data(bytes)
            #expect(data.range(of: Data("fixture-password-canary".utf8)) != nil)
            #expect(data.range(of: Data(origin.utf8)) != nil)
        }
        #expect(throws: (any Error).self) { try frame.writeOnce { _ in Issue.record("Frame replayed") } }
    }
    @Test func invalidCredentialsAndOriginsNeverProduceFrames() throws {
        for raw in [#"{"ClientID":"fixture","ClientSecret":"fixture-canary"}"#, #"{"Username":"u","Password":"p","ClientID":"oauth-client"}"#, #"{"Username":"u","Password":"p","Endpoint":"https://other.example.test"}"#, #"{"Username":"u","Password":""}"#, #"{"Username":"u","Password":"p","EncryptedPassword":"still-encrypted"}"#] {
            var bytes = Data(raw.utf8)
            #expect(throws: (any Error).self) { try ScyVaultImport.decodeFrame(&bytes, origin: origin) }
            #expect(bytes.isEmpty)
        }
        for invalid in ["http://login.example.test", "https://user:password@login.example.test", origin + "/path", origin + "?token=fixture"] {
            var bytes = plain()
            #expect(throws: (any Error).self) { try ScyVaultImport.decodeFrame(&bytes, origin: invalid) }
            #expect(bytes.isEmpty)
        }
    }
    @Test func refusesUnsafeSourceBeforeInvokingScy() throws {
        let root = try fixture(); defer { try? FileManager.default.removeItem(at: root) }
        let load: (URL) throws -> Data = { _ in Issue.record("Unsafe source reached Scy"); return plain() }
        for name in ["../account.enc", "/tmp/account.enc", "account.enc;command", "account.json"] {
            #expect(throws: (any Error).self) { try ScyVaultImport.frame(resourceName: name, origin: origin, root: root, load: load) }
        }
        try FileManager.default.createSymbolicLink(atPath: root.appendingPathComponent("link.enc").path, withDestinationPath: root.appendingPathComponent("account.enc").path)
        #expect(throws: (any Error).self) { try ScyVaultImport.frame(resourceName: "link.enc", origin: origin, root: root, load: load) }
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: root.appendingPathComponent("account.enc").path)
        #expect(throws: (any Error).self) { try ScyVaultImport.frame(resourceName: "account.enc", origin: origin, root: root, load: load) }
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: root.appendingPathComponent("account.enc").path)
        try FileManager.default.linkItem(at: root.appendingPathComponent("account.enc"), to: root.appendingPathComponent("hard.enc"))
        #expect(throws: (any Error).self) { try ScyVaultImport.frame(resourceName: "account.enc", origin: origin, root: root, load: load) }
        try FileManager.default.removeItem(at: root.appendingPathComponent("hard.enc"))
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: root.path)
        #expect(throws: (any Error).self) { try ScyVaultImport.frame(resourceName: "account.enc", origin: origin, root: root, load: load) }
    }
    @Test func subprocessOutputIsBoundedAndErrorsWithholdDiagnostics() throws {
        let root = try fixture(); defer { try? FileManager.default.removeItem(at: root) }
        let executable = root.appendingPathComponent("scy-fixture")
        for script in ["#!/bin/sh\nprintf 'fixture-secret-canary' >&2\nexit 1\n", "#!/bin/sh\n/usr/bin/yes fixture-secret-canary | /usr/bin/head -c 70000\n", "#!/bin/sh\nexec /bin/sleep 30\n"] {
            try Data(script.utf8).write(to: executable)
            try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: executable.path)
            do {
                _ = try ScyVaultImport.run(executable: executable, source: root.appendingPathComponent("account.enc"), timeout: 0.2)
                Issue.record("Unqualified subprocess output accepted")
            } catch { #expect(!String(describing: error).contains("fixture-secret-canary")) }
        }
    }
}
