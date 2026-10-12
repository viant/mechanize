import Foundation
import Darwin

/// Public status only. Never supply record identifiers or secret input to this API.
public struct VaultRecordGuardStatus: Equatable, Sendable {
    public var protection: Bool
    public var mutation: Bool
    public var generation: String?
    public init(protection: Bool = false, mutation: Bool = false, generation: String? = nil) {
        self.protection = protection; self.mutation = mutation; self.generation = generation
    }
}
public enum VaultRecordGuardError: Error { case unavailable }
public protocol VaultRecordGuardStore: Sendable {
    func status() throws -> VaultRecordGuardStatus
    func beginProtection() throws -> String
    func beginMutation(generation: String) throws
    func acknowledgeMutation(generation: String) throws
    func acknowledgeProtection(generation: String) throws
}

/// Calls are synchronous and must run off the UI actor. A fixed public marker
/// survives crashes and lost acknowledgements. There is deliberately no reset or
/// replay API. Unrecognized files, partial writes, unsafe ownership and symlinks
/// make the guard unavailable. flock serializes separate console processes.
public final class VaultRecordGuard: VaultRecordGuardStore, @unchecked Sendable {
    private let parent: URL
    private let lock = NSLock()
    private let directoryName = "console-native-record-guard"
    private let stateName = "status"
    private let stageName = "pending"
    public init(parent: URL = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".secret", isDirectory: true)) {
        self.parent = parent
    }
    public func status() throws -> VaultRecordGuardStatus { try access(create: false) { $0 } }
    public func beginProtection() throws -> String {
        let generation = UUID().uuidString.lowercased()
        try change { old in
            guard !old.protection, !old.mutation else { throw VaultRecordGuardError.unavailable }
            return .init(protection: true, generation: generation)
        }
        return generation
    }
    public func beginMutation(generation: String) throws {
        try change { old in
            guard old.protection, !old.mutation, old.generation == generation else { throw VaultRecordGuardError.unavailable }
            return .init(protection: true, mutation: true, generation: generation)
        }
    }
    public func acknowledgeMutation(generation: String) throws {
        try change { old in
            guard old.mutation, old.generation == generation else { throw VaultRecordGuardError.unavailable }
            return .init(protection: old.protection, generation: old.protection ? generation : nil)
        }
    }
    public func acknowledgeProtection(generation: String) throws {
        try change { old in
            guard old.protection, old.generation == generation else { throw VaultRecordGuardError.unavailable }
            return .init(mutation: old.mutation, generation: old.mutation ? generation : nil)
        }
    }
    private func change(_ transform: (VaultRecordGuardStatus) throws -> VaultRecordGuardStatus) throws {
        _ = try access(create: true, transform: transform)
    }
    private func access(create: Bool, transform: (VaultRecordGuardStatus) throws -> VaultRecordGuardStatus) throws -> VaultRecordGuardStatus {
        lock.lock(); defer { lock.unlock() }
        let parentFD = try openDirectory(parent.path, relativeTo: AT_FDCWD, create: create)
        guard parentFD >= 0 else { return try transform(.init()) }
        defer { close(parentFD) }
        let directoryFD = try openDirectory(directoryName, relativeTo: parentFD, create: create)
        guard directoryFD >= 0 else { return try transform(.init()) }
        defer { close(directoryFD) }
        var lockFD = openat(directoryFD, "lock", O_RDWR | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        if lockFD < 0, errno == ENOENT, create {
            lockFD = openat(directoryFD, "lock", O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, mode_t(0o600))
            if lockFD < 0, errno == EEXIST { lockFD = openat(directoryFD, "lock", O_RDWR | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK) }
        }
        if lockFD < 0 {
            guard !create, errno == ENOENT, try names(directoryFD).isEmpty else { throw VaultRecordGuardError.unavailable }
            return try transform(.init())
        }
        defer { close(lockFD) }
        try verifyFile(lockFD)
        var lockStat = stat(); guard fstat(lockFD, &lockStat) == 0, lockStat.st_size == 0,
            flock(lockFD, LOCK_EX | LOCK_NB) == 0 else { throw VaultRecordGuardError.unavailable }
        defer { flock(lockFD, LOCK_UN) }
        let artifacts = try names(directoryFD)
        guard artifacts.isSubset(of: ["lock", stateName]) else { throw VaultRecordGuardError.unavailable }
        let previous = try read(directoryFD)
        let next = try transform(previous)
        if create {
            // Sync the lock and parent before any admission or mutation can run.
            let ancestor = open(parent.deletingLastPathComponent().path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard ancestor >= 0 else { throw VaultRecordGuardError.unavailable }
            defer { close(ancestor) }
            guard fsync(lockFD) == 0, fsync(parentFD) == 0, fsync(ancestor) == 0 else { throw VaultRecordGuardError.unavailable }
            try write(next, directoryFD)
        }
        return next
    }
    private func openDirectory(_ name: String, relativeTo fd: Int32, create: Bool) throws -> Int32 {
        var result = openat(fd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        if result < 0, errno == ENOENT {
            guard create else { return -1 }
            guard mkdirat(fd, name, mode_t(0o700)) == 0 || errno == EEXIST else { throw VaultRecordGuardError.unavailable }
            result = openat(fd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        }
        guard result >= 0 else { throw VaultRecordGuardError.unavailable }
        var info = stat()
        guard fstat(result, &info) == 0, info.st_uid == getuid(), info.st_mode & 0o7777 == 0o700,
              info.st_mode & S_IFMT == S_IFDIR else { close(result); throw VaultRecordGuardError.unavailable }
        return result
    }
    private func verifyFile(_ fd: Int32) throws {
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_uid == getuid(), info.st_mode & S_IFMT == S_IFREG,
              info.st_mode & 0o7777 == 0o600, info.st_nlink == 1 else { throw VaultRecordGuardError.unavailable }
    }
    private func names(_ fd: Int32) throws -> Set<String> {
        let copy = dup(fd)
        guard copy >= 0 else { throw VaultRecordGuardError.unavailable }
        guard let directory = fdopendir(copy) else { close(copy); throw VaultRecordGuardError.unavailable }
        defer { closedir(directory) }
        rewinddir(directory)
        var result: Set<String> = []
        errno = 0
        while let item = readdir(directory) {
            let name = withUnsafePointer(to: &item.pointee.d_name) {
                $0.withMemoryRebound(to: CChar.self, capacity: Int(item.pointee.d_namlen) + 1) { String(cString: $0) }
            }
            if name != ".", name != ".." { result.insert(name) }
            errno = 0
        }
        guard errno == 0 else { throw VaultRecordGuardError.unavailable }
        return result
    }
    private func read(_ directory: Int32) throws -> VaultRecordGuardStatus {
        let fd = openat(directory, stateName, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        if fd < 0, errno == ENOENT { return .init() }
        guard fd >= 0 else { throw VaultRecordGuardError.unavailable }
        defer { close(fd) }; try verifyFile(fd)
        var bytes = [UInt8](repeating: 0, count: 128)
        let count = Darwin.read(fd, &bytes, bytes.count)
        guard count >= 0, count < bytes.count else { throw VaultRecordGuardError.unavailable }
        guard let text = String(bytes: bytes.prefix(count), encoding: .utf8) else { throw VaultRecordGuardError.unavailable }
        let fields = text.components(separatedBy: "\n")
        guard fields.count == 4, fields[0] == "mechanize-record-guard-v1", fields[3].isEmpty,
              let uuid = UUID(uuidString: fields[1]), uuid.uuidString.lowercased() == fields[1] else { throw VaultRecordGuardError.unavailable }
        switch fields[2] {
        case "protection": return .init(protection: true, generation: fields[1])
        case "mutation": return .init(mutation: true, generation: fields[1])
        case "protection+mutation": return .init(protection: true, mutation: true, generation: fields[1])
        default: throw VaultRecordGuardError.unavailable
        }
    }

    private func write(_ status: VaultRecordGuardStatus, _ directory: Int32) throws {
        if !status.protection, !status.mutation {
            guard unlinkat(directory, stateName, 0) == 0 || errno == ENOENT,
                  fsync(directory) == 0 else { throw VaultRecordGuardError.unavailable }
            return
        }
        let label = status.protection ? (status.mutation ? "protection+mutation" : "protection") : "mutation"
        guard let generation = status.generation else { throw VaultRecordGuardError.unavailable }
        let bytes = Array("mechanize-record-guard-v1\n\(generation)\n\(label)\n".utf8)
        let fd = openat(directory, stageName, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode_t(0o600))
        guard fd >= 0 else { throw VaultRecordGuardError.unavailable }
        defer { close(fd) }
        try verifyFile(fd)
        guard Darwin.write(fd, bytes, bytes.count) == bytes.count, fsync(fd) == 0,
              renameat(directory, stageName, directory, stateName) == 0,
              fsync(directory) == 0 else { throw VaultRecordGuardError.unavailable }
    }
}
