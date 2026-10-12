import Foundation

public struct RuntimeSettingsSnapshot: Codable, Equatable, Sendable {
    public let transport: String
    public let currentAddress: String
    public let currentPort: Int
    public let savedPort: Int
    public let revision: Int
    public let restartRequired: Bool
    public var isValid: Bool {
        guard revision >= 0, (0...65535).contains(savedPort) else { return false }
        if transport == "stdio" { return currentAddress.isEmpty && currentPort == 0 && !restartRequired }
        guard transport == "http", (1...65535).contains(currentPort), (1...65535).contains(savedPort),
              let address = URLComponents(string: "http://" + currentAddress),
              address.user == nil, address.password == nil, address.path.isEmpty,
              address.query == nil, address.fragment == nil, address.port == currentPort,
              let host = address.host else { return false }
        let parts = host.split(separator: ".", omittingEmptySubsequences: false)
        let ipv4 = parts.count == 4 && parts.first == "127" && parts.allSatisfy { part in
            guard let value = Int(part), (0...255).contains(value) else { return false }
            return String(value) == part
        }
        return (host == "[::1]" || host == "::1" || ipv4) && restartRequired == (savedPort != currentPort)
    }
}
