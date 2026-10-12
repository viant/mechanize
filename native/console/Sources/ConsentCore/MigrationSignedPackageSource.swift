import Foundation
import CryptoKit
import Darwin

/// The approval console pins a public review key, not a package digest. This
/// permits signing the console before workers bind its identity, and signing the
/// completed external package afterward without a console/package hash cycle.
/// The signing key never belongs in the package, bundle, or browser transport.
@MainActor public final class MigrationSignedPackageSource: MigrationUpgradePackageSource {
    private let key: Curve25519.Signing.PublicKey
    private let read: () throws -> Data

    /// Enrollment belongs to the already authenticated, signed approval console.
    /// Neither website messages nor selected package contents can supply the key.
    public static func enrolled(in bundle: Bundle = .main) -> MigrationSignedPackageSource? {
        guard bundle.bundleIdentifier == "com.viant.mechanize.consent",
              let path = bundle.object(forInfoDictionaryKey: "MechanizeUpgradePackagePath") as? String,
              MigrationRuntimeConsoleManifest.path(path),
              let encoded = bundle.object(forInfoDictionaryKey: "MechanizeUpgradeReviewPublicKey") as? String,
              let bytes = Data(base64Encoded: encoded), bytes.count == 32,
              bytes.base64EncodedString() == encoded else { return nil }
        return try? MigrationSignedPackageSource(publicKey: bytes) { try readPackage(path) }
    }

    // Internal construction seam: production obtains this key from signed
    // bundle enrollment. Re-reading the envelope revalidates selection on Upgrade.
    init(publicKey: Data, read: @escaping () throws -> Data) throws {
        key = try Curve25519.Signing.PublicKey(rawRepresentation: publicKey)
        self.read = read
    }

    public func selectedPackage() async throws -> MigrationReviewedUpgradePackage {
        try selectedPackageSynchronously()
    }

    func selectedPackageSynchronously() throws -> MigrationReviewedUpgradePackage {
        let envelope = try read()
        guard !envelope.isEmpty, envelope.count <= 3_000_000 else { throw MigrationUpgradeError.invalidPreparation }
        try MigrationReadinessJSON.validate(envelope)
        guard let object = try JSONSerialization.jsonObject(with: envelope) as? [String: Any],
              Set(object.keys) == Set(["version", "payloadBase64", "signatureBase64"]),
              MigrationRuntimeConsoleManifest.integer(object["version"]) == 1,
              let payloadText = object["payloadBase64"] as? String,
              let payload = Data(base64Encoded: payloadText), !payload.isEmpty, payload.count <= 2_000_000,
              payload.base64EncodedString() == payloadText,
              let signatureText = object["signatureBase64"] as? String,
              let signature = Data(base64Encoded: signatureText), signature.count == 64,
              signature.base64EncodedString() == signatureText,
              key.isValidSignature(signature, for: Self.signingMessage(payload)) else { throw MigrationUpgradeError.invalidPreparation }
        return try MigrationReviewedUpgradePackage(authenticatedPayload: payload,
            expectedSHA256: MigrationUpgradeIntent.digest(payload))
    }

    static func signingMessage(_ payload: Data) -> Data {
        var message = Data("viant.mechanize.runtime-upgrade-package.v1\0".utf8)
        message.append(payload)
        return message
    }

    private static func readPackage(_ path: String) throws -> Data {
        // Descriptor-based traversal rejects symlinks, pipes and replacement
        // during reading. Signature verification is still the authority check.
        let parts = path.split(separator: "/")
        var parent = Darwin.open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard parent >= 0, let name = parts.last else { throw MigrationUpgradeError.unavailable }
        defer { Darwin.close(parent) }
        for part in parts.dropLast() {
            let next = openat(parent, String(part), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard next >= 0 else { throw MigrationUpgradeError.unavailable }
            Darwin.close(parent); parent = next
        }
        let fd = openat(parent, String(name), O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard fd >= 0 else { throw MigrationUpgradeError.unavailable }
        defer { Darwin.close(fd) }
        var before = stat()
        guard fstat(fd, &before) == 0, before.st_mode & S_IFMT == S_IFREG,
              before.st_uid == getuid(), before.st_nlink == 1, before.st_mode & 0o077 == 0,
              before.st_size > 0, before.st_size <= 3_000_000 else { throw MigrationUpgradeError.unavailable }
        var data = Data(count: Int(before.st_size)), offset = 0
        while offset < data.count {
            let count = data.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress!.advanced(by: offset), $0.count - offset) }
            if count < 0 && errno == EINTR { continue }
            guard count > 0 else { throw MigrationUpgradeError.unavailable }
            offset += count
        }
        var after = stat(), entry = stat()
        guard fstat(fd, &after) == 0, fstatat(parent, String(name), &entry, AT_SYMLINK_NOFOLLOW) == 0,
              before.st_dev == entry.st_dev, before.st_ino == entry.st_ino,
              before.st_size == after.st_size,
              before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec,
              before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec,
              before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec,
              before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec else { throw MigrationUpgradeError.unavailable }
        return data
    }
}
