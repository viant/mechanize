import Foundation

/// Dedicated native secret-channel frame, never JSON/MCP. The caller must first
/// acquire the authenticated broker's qualified entry-protection lease. Encoding
/// does not establish permission or capture protection. The transport sends one
/// frame, shuts down its write half and accepts only a sanitized opaque result.
public enum VaultCredentialFrame {
    public static func withBytes(username: Data, password: Data,
                                 consume: (Data) throws -> Void) throws {
        guard !username.isEmpty, !password.isEmpty,
              username.count <= 65_536, password.count <= 65_536,
              username.count + password.count <= 65_536,
              !username.contains(0), !password.contains(0),
              String(data: username, encoding: .utf8) != nil,
              String(data: password, encoding: .utf8) != nil else {
            throw VaultCredentialFrameError.invalidInput
        }
        var frame = Data([77, 86, 76, 84, 0, 0, 0, 1])
        for count in [username.count, password.count] {
            let value = UInt32(count)
            frame.append(contentsOf: [UInt8((value >> 24) & 255), UInt8((value >> 16) & 255), UInt8((value >> 8) & 255), UInt8(value & 255)])
        }
        frame.append(username); frame.append(password)
        defer { frame.resetBytes(in: 0..<frame.count) }
        // Swift Data and the transport may retain copies. This is lifetime
        // reduction, not a claim of locked or globally zeroed secure memory.
        do { try consume(frame) }
        catch { throw VaultCredentialFrameError.transportUnavailable }
    }
}
public enum VaultCredentialFrameError: Error { case invalidInput, transportUnavailable }
