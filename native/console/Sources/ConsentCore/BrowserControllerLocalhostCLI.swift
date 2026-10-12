import Foundation

public struct BrowserControllerLocalhostReport: Codable, Sendable {
    public let stage: String
    public let succeeded: Bool
    public let updated: Bool?
    public let errorCode: String?
    public init(stage: String, succeeded: Bool = false, updated: Bool? = nil, errorCode: String? = nil) {
        self.stage = stage; self.succeeded = succeeded; self.updated = updated; self.errorCode = errorCode
    }
    public func json() -> Data {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        return (try? encoder.encode(self)) ?? Data(#"{"stage":"output","succeeded":false,"errorCode":"encodingFailed"}"#.utf8)
    }
}

/// One explicit owner command, not a general RPC client. Uses the console's
/// provisioned peer and existing enrollment; no UI, browser input or secrets in output.
public enum BrowserControllerLocalhostCLI {
    public static let arguments = ["--trust-localhost-controllers"]
    private enum Failure: String, Error { case channelUnavailable, channelAmbiguous, channelChanged, policyCapacity, policyChanged, configurationUnconfirmed, deadlineExceeded }
    public static func run(arguments supplied: [String], transport: any FramedBrokerTransport, credentials: any EnrollmentCredentialProvider) async -> BrowserControllerLocalhostReport {
        guard supplied == arguments else { return .init(stage: "setup", errorCode: "invalidArguments") }
        let broker = SocketConsentBroker(transport: transport, credentials: credentials)
        defer { transport.close() }
        let deadline = Date().addingTimeInterval(10)
        func bounded() throws { if Task.isCancelled || Date() >= deadline { throw Failure.deadlineExceeded } }
        var stage = "connection"
        var writeAttempted = false
        do {
            try bounded(); try broker.connectFromUserAction()
            stage = "channel"
            let selected = try channel(try await broker.browserStatus()); try bounded()
            stage = "policy"
            let saved = try await broker.manageBrowserControllers(profileChannel: selected.0, browserInstance: selected.1, action: .status)
            try bounded()
            var origins = saved.policy.origins
            if !origins.contains("localhost:*") { origins.append("localhost:*") }
            let requested = BrowserControllerPolicy(enabled: true, origins: origins)
            guard requested.isValid else { throw Failure.policyCapacity }
            let changed = requested != saved.policy
            if changed {
                stage = "channel"
                let current = try channel(try await broker.browserStatus()); try bounded()
                guard current == selected else { throw Failure.channelChanged }
                stage = "policy"
                let currentPolicy = try await broker.manageBrowserControllers(profileChannel: selected.0, browserInstance: selected.1, action: .status)
                try bounded(); guard currentPolicy.policy == saved.policy else { throw Failure.policyChanged }
                stage = "configure"; writeAttempted = true
                let configured = try await broker.manageBrowserControllers(profileChannel: selected.0, browserInstance: selected.1, action: .configure, policy: requested)
                try bounded(); guard configured.policy == requested else { throw Failure.configurationUnconfirmed }
            }
            stage = "verify"
            let observed = try await broker.manageBrowserControllers(profileChannel: selected.0, browserInstance: selected.1, action: .status)
            try bounded(); guard observed.policy == requested else { throw Failure.configurationUnconfirmed }
            let current = try channel(try await broker.browserStatus()); try bounded()
            guard current == selected else { throw Failure.channelChanged }
            return .init(stage: "complete", succeeded: true, updated: changed)
        } catch {
            if writeAttempted { return .init(stage: stage, errorCode: "configurationUnconfirmed") }
            if let failure = error as? Failure { return .init(stage: stage, errorCode: failure.rawValue) }
            let code: String
            switch error as? BrokerTransportError {
            case .unavailable: code = "unavailable"
            case .unsafeEndpoint: code = "unsafeEndpoint"
            case .untrustedPeer: code = "untrustedPeer"
            case .malformedFrame: code = "malformedFrame"
            case .malformedResponse: code = "malformedResponse"
            case .remoteRejected: code = "remoteRejected"
            case .missingEnrollment: code = "missingEnrollment"
            case nil: code = "configurationUnavailable"
            }
            return .init(stage: stage, errorCode: code)
        }
    }
    private static func channel(_ status: BrowserConnectionStatus) throws -> (String, String) {
        guard status.available, !status.processQualificationFailed, status.channels.count <= 64 else { throw Failure.channelUnavailable }
        let connected = status.channels.filter(\.connected)
        guard connected.count <= 1 else { throw Failure.channelAmbiguous }
        guard let selected = connected.first, !selected.fixtureOnly, selected.processQualified, selected.scopeQualified,
              selected.trustScope == "desktop" && !selected.profileQualified || selected.trustScope == "profile" && selected.profileQualified,
              let profile = selected.profileChannel, !profile.isEmpty, profile.utf8.count <= 128,
              let browser = selected.browserInstance, !browser.isEmpty, browser.utf8.count <= 128 else { throw Failure.channelUnavailable }
        return (profile, browser)
    }
    public static func runFromExplicitCLI(arguments: [String], transport: any FramedBrokerTransport, credentials: any EnrollmentCredentialProvider) -> BrowserControllerLocalhostReport {
        guard arguments == Self.arguments else { return .init(stage: "setup", errorCode: "invalidArguments") }
        let result = LocalhostCommandResult(), completed = DispatchSemaphore(value: 0)
        let task = Task.detached {
            result.set(await run(arguments: arguments, transport: transport, credentials: credentials)); completed.signal()
        }
        guard completed.wait(timeout: .now() + 15) == .success else {
            task.cancel()
            // The signed command process exits after this report. A timed-out
            // write is never claimed absent or automatically repeated.
            return .init(stage: "deadline", errorCode: "configurationUnconfirmed")
        }
        return result.get() ?? .init(stage: "complete", errorCode: "configurationUnavailable")
    }
}
private final class LocalhostCommandResult: @unchecked Sendable {
    private let lock = NSLock()
    private var report: BrowserControllerLocalhostReport?
    func set(_ value: BrowserControllerLocalhostReport) { lock.lock(); defer { lock.unlock() }; report = value }
    func get() -> BrowserControllerLocalhostReport? { lock.lock(); defer { lock.unlock() }; return report }
}
