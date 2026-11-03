import Foundation
import Darwin

public enum ScyVaultImportError: Error { case unavailable, invalidCredential }

/// Local native-entry adapter. Plaintext stays in bounded memory and is returned
/// only as the existing one-shot protected record frame, never as UI text or logs.
public enum ScyVaultImport {
    public static func frame(resourceName: String, origin: String) throws -> VaultRecordFrame {
        try frame(resourceName: resourceName, origin: origin,
                  root: FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".secret", isDirectory: true), load: reveal)
    }
    static func frame(resourceName: String, origin: String, root: URL, load: (URL) throws -> Data) throws -> VaultRecordFrame {
        guard let canonical = VaultOrigin.canonical(origin), canonical == origin,
              resourceName.range(of: #"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\.enc$"#, options: .regularExpression) != nil else {
            throw ScyVaultImportError.unavailable
        }
        let parent = open(root.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard parent >= 0 else { throw ScyVaultImportError.unavailable }
        defer { close(parent) }
        var directory = stat()
        guard fstat(parent, &directory) == 0, directory.st_uid == getuid(), directory.st_mode & 0o7777 == 0o700 else { throw ScyVaultImportError.unavailable }
        let source = openat(parent, resourceName, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard source >= 0 else { throw ScyVaultImportError.unavailable }
        defer { close(source) }
        var before = stat()
        guard fstat(source, &before) == 0, before.st_uid == getuid(), before.st_mode & S_IFMT == S_IFREG,
              before.st_mode & 0o7777 == 0o600, before.st_nlink == 1, before.st_size > 0, before.st_size <= 131072 else { throw ScyVaultImportError.unavailable }
        var encrypted = Data(count: Int(before.st_size))
        defer { encrypted.resetBytes(in: 0..<encrypted.count) }
        let count = encrypted.withUnsafeMutableBytes { Darwin.read(source, $0.baseAddress, $0.count) }
        var after = stat()
        guard count == encrypted.count, fstat(source, &after) == 0, before.st_size == after.st_size,
              before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec, before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec,
              before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec, before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec else { throw ScyVaultImportError.unavailable }
        // Snapshot ciphertext through an owner-only file so the CLI cannot follow
        // a replacement source symlink. Decrypted CLI output is never written
        // to a file; only the original resource bytes are copied here.
        let name = ".mechanize-scy-import-" + UUID().uuidString.lowercased() + ".enc"
        let temporary = openat(parent, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard temporary >= 0 else { throw ScyVaultImportError.unavailable }
        defer { close(temporary); _ = unlinkat(parent, name, 0) }
        let written = encrypted.withUnsafeBytes { Darwin.write(temporary, $0.baseAddress, $0.count) }
        guard written == encrypted.count, fsync(temporary) == 0 else { throw ScyVaultImportError.unavailable }
        var plain = try load(root.appendingPathComponent(name))
        defer { plain.resetBytes(in: 0..<plain.count) }
        return try decodeFrame(&plain, origin: canonical)
    }

    static func decodeFrame(_ bytes: inout Data, origin: String) throws -> VaultRecordFrame {
        defer { bytes.resetBytes(in: 0..<bytes.count); bytes.removeAll() }
        guard bytes.count <= 65536, VaultOrigin.canonical(origin) == origin,
              let object = try? JSONSerialization.jsonObject(with: bytes) as? [String: String] else { throw ScyVaultImportError.invalidCredential }
        var fields: [String: String] = [:]
        for (name, value) in object {
            let key = name.lowercased()
            guard ["username", "password", "endpoint", "email", "encryptedpassword"].contains(key), fields[key] == nil else { throw ScyVaultImportError.invalidCredential }
            fields[key] = value
        }
        guard let user = fields["username"], !user.isEmpty, let password = fields["password"], !password.isEmpty,
              fields["encryptedpassword", default: ""].isEmpty,
              !user.contains("\0"), !password.contains("\0"), user.utf8.count + password.utf8.count <= 32768 else { throw ScyVaultImportError.invalidCredential }
        if let endpoint = fields["endpoint"], !endpoint.isEmpty, VaultOrigin.canonical(endpoint) != origin { throw ScyVaultImportError.invalidCredential }
        var key = Data(("website:" + origin).utf8)
        var values: [(name: Data, value: Data)] = [
            (Data("$scy.type".utf8), Data("basic".utf8)),
            (Data("username".utf8), Data(user.utf8)),
            (Data("password".utf8), Data(password.utf8)),
            (Data("endpoint".utf8), Data(origin.utf8))
        ]
        return try VaultRecordFrame(key: &key, fields: &values)
    }

    private static func reveal(_ source: URL) throws -> Data {
        let candidates = ["/usr/local/bin/scy", "/opt/homebrew/bin/scy"]
        guard let executable = candidates.map({ URL(fileURLWithPath: $0).resolvingSymlinksInPath() }).first(where: { url in
            var info = stat()
            return lstat(url.path, &info) == 0 && info.st_mode & S_IFMT == S_IFREG && info.st_mode & 0o022 == 0 &&
                (info.st_uid == 0 || info.st_uid == getuid()) && access(url.path, X_OK) == 0
        }) else { throw ScyVaultImportError.unavailable }
        return try run(executable: executable, source: source)
    }
    static func run(executable: URL, source: URL, timeout: TimeInterval = 15) throws -> Data {
        let process = Process(), pipe = Pipe(), output = ScyImportOutput(), done = DispatchSemaphore(value: 0)
        process.executableURL = executable
        // Decode the original object ourselves: requesting Scy's Basic target
        // could discard OAuth/client fields before we can reject the wrong type.
        process.arguments = ["reveal", "-s", source.path, "-k", "blowfish://default", "-t", "raw"]
        process.standardInput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        process.standardOutput = pipe
        process.environment = ["HOME": FileManager.default.homeDirectoryForCurrentUser.path, "PATH": "/usr/bin:/bin"]
        let readDone = DispatchSemaphore(value: 0)
        process.terminationHandler = { _ in done.signal() }
        do { try process.run() } catch { throw ScyVaultImportError.unavailable }
        try? pipe.fileHandleForWriting.close()
        DispatchQueue.global(qos: .userInitiated).async {
            defer { readDone.signal() }
            while true {
                guard var bytes = try? pipe.fileHandleForReading.read(upToCount: 8192), !bytes.isEmpty else { break }
                output.append(bytes)
                bytes.resetBytes(in: 0..<bytes.count)
            }
        }
        let completed = done.wait(timeout: .now() + max(0.01, min(15, timeout)))
        defer { try? pipe.fileHandleForReading.close() }
        guard completed == .success else {
            process.terminate()
            if done.wait(timeout: .now() + 1) != .success, process.isRunning { _ = kill(process.processIdentifier, SIGKILL) }
            throw ScyVaultImportError.unavailable
        }
        guard readDone.wait(timeout: .now() + 1) == .success, process.terminationStatus == 0 else { throw ScyVaultImportError.unavailable }
        return try output.take()
    }
}

private final class ScyImportOutput: @unchecked Sendable {
    private let lock = NSLock()
    private var bytes = Data()
    private var overflow = false
    func append(_ incoming: Data) {
        lock.lock(); defer { lock.unlock() }
        if bytes.count + incoming.count > 65536 { overflow = true } else if !overflow { bytes.append(incoming) }
    }
    func take() throws -> Data {
        lock.lock(); defer { lock.unlock() }
        guard !overflow else { throw ScyVaultImportError.unavailable }
        let result = bytes; bytes = Data(); return result
    }
    deinit { bytes.resetBytes(in: 0..<bytes.count) }
}
