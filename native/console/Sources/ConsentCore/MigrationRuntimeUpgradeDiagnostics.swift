import Foundation
import AppKit

/// A fresh preservation observation only. Qualification is neither approval nor
/// installation readiness and cannot be supplied to the worker approval flow.
public struct MigrationRuntimeUpgradeDiagnosticReport: Sendable {
    public let qualified: Bool
    public let stage: String
    public let errorCode: String
    public func json() -> Data {
        (try? JSONSerialization.data(withJSONObject: ["qualified":qualified, "stage":stage, "errorCode":errorCode], options:[.sortedKeys])) ?? Data()
    }
}

@MainActor public enum MigrationRuntimeUpgradeDiagnostics {
    public static func runCLI(arguments: [String]) -> MigrationRuntimeUpgradeDiagnosticReport {
        // App.init has not entered NSApplication.run yet. Its own process must
        // remain responsive while the broker verifies every console AX window.
        _ = NSApplication.shared
        return runResponsive(arguments: arguments, source: { MigrationSignedPackageSource.enrolled() })
    }
    static func runResponsive(arguments: [String], source: () -> MigrationSignedPackageSource?, timeout: TimeInterval = 30,
                              capture: @escaping (MigrationReviewedUpgradePackage) throws -> Void = { package in try package.makePreservationObserver().capture() }) -> MigrationRuntimeUpgradeDiagnosticReport {
        guard arguments == ["--check-runtime-upgrade"] else { return .init(qualified:false, stage:"setup", errorCode:"invalidArguments") }
        guard let source = source() else { return .init(qualified:false, stage:"setup", errorCode:"enrollmentUnavailable") }
        let package: MigrationReviewedUpgradePackage
        do { package = try source.selectedPackageSynchronously() }
        catch { return .init(qualified:false, stage:"package", errorCode:"packageUnavailable") }
        guard package.observerEnrollment.preservedChrome != nil else { return .init(qualified:false, stage:"package", errorCode:"preservationRequired") }
        let result = MigrationDiagnosticResult()
        DispatchQueue.global(qos:.userInitiated).async {
            let report: MigrationRuntimeUpgradeDiagnosticReport
            do { try capture(package); report = .init(qualified:true, stage:"complete", errorCode:"") }
            catch let error as MigrationObserverReadinessError { report = .init(qualified:false, stage:"observer", errorCode:error.rawValue) }
            catch { report = .init(qualified:false, stage:"observer", errorCode:"observationUnavailable") }
            result.store(report)
            CFRunLoopWakeUp(CFRunLoopGetMain())
        }
        let deadline = Date().addingTimeInterval(max(0,min(30,timeout)))
        while Date() < deadline {
            if let report = result.load() { return report }
            if !RunLoop.current.run(mode:.default,before:min(deadline,Date().addingTimeInterval(0.01))) { Thread.sleep(forTimeInterval:0.001) }
        }
        return .init(qualified:false, stage:"observer", errorCode:"observationUnavailable")
    }
    static func run(arguments: [String], source: () -> MigrationSignedPackageSource?,
                    capture: (MigrationReviewedUpgradePackage) throws -> Void = { package in try package.makePreservationObserver().capture() }) -> MigrationRuntimeUpgradeDiagnosticReport {
        guard arguments == ["--check-runtime-upgrade"] else { return .init(qualified:false, stage:"setup", errorCode:"invalidArguments") }
        guard let source = source() else { return .init(qualified:false, stage:"setup", errorCode:"enrollmentUnavailable") }
        let package: MigrationReviewedUpgradePackage
        do { package = try source.selectedPackageSynchronously() }
        catch { return .init(qualified:false, stage:"package", errorCode:"packageUnavailable") }
        guard package.observerEnrollment.preservedChrome != nil else { return .init(qualified:false, stage:"package", errorCode:"preservationRequired") }
        do { try capture(package) }
        catch let error as MigrationObserverReadinessError { return .init(qualified:false, stage:"observer", errorCode:error.rawValue) }
        catch { return .init(qualified:false, stage:"observer", errorCode:"observationUnavailable") }
        return .init(qualified:true, stage:"complete", errorCode:"")
    }
}

private final class MigrationDiagnosticResult: @unchecked Sendable {
    private let lock = NSLock()
    private var report: MigrationRuntimeUpgradeDiagnosticReport?
    func store(_ value: MigrationRuntimeUpgradeDiagnosticReport) { lock.lock(); report=value; lock.unlock() }
    func load() -> MigrationRuntimeUpgradeDiagnosticReport? { lock.lock(); defer { lock.unlock() }; return report }
}
