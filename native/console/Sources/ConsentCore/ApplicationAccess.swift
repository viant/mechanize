import Foundation

public struct ApplicationAccessRule: Codable, Equatable {
    public let bundleID: String
    public let displayName: String
    public let modes: [ConsentMode]

    public init(bundleID: String, displayName: String, modes: [ConsentMode]) {
        self.bundleID = bundleID
        self.displayName = displayName
        self.modes = modes
    }
}

public struct ApplicationAccessPolicy: Codable, Equatable {
    public let desktopWide: Bool
    public let applications: [ApplicationAccessRule]

    public init(desktopWide: Bool, applications: [ApplicationAccessRule]) {
        self.desktopWide = desktopWide
        self.applications = applications
    }
}

public struct ApplicationAccessEntry: Codable, Equatable {
    public let bundleID: String
    public let displayName: String
    public let modes: [ConsentMode]
    public let status: String
    public let detail: String

    public init(bundleID: String, displayName: String, modes: [ConsentMode], status: String, detail: String) {
        self.bundleID = bundleID
        self.displayName = displayName
        self.modes = modes
        self.status = status
        self.detail = detail
    }
}

public struct ApplicationAccessSnapshot: Codable, Equatable {
    public let revision: Int
    public let policy: ApplicationAccessPolicy
    public let rows: [ApplicationAccessEntry]

    public init(revision: Int, policy: ApplicationAccessPolicy, rows: [ApplicationAccessEntry]) {
        self.revision = revision
        self.policy = policy
        self.rows = rows
    }
}
