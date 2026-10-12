import Foundation
import os
import Darwin
import MechanizeNativeCore

/// Owned by one serialized doctor call. This logger never performs observations
/// and never writes to stdout, which remains exclusively the framed protocol.
final class ManagedControlReadinessLog {
    private var probes: [ControlReadinessRoute: ControlReadinessProbeResult] = [:]
    private static let logger = Logger(subsystem: "com.viant.mechanize.native", category: "control-readiness")
    func record(_ route: ControlReadinessRoute, _ result: ControlReadinessProbeResult) { probes[route] = result }
    func emit(authenticated: Bool, requestID: String, doctor: [String: Any]) {
        guard let line = ControlReadinessDiagnostic.line(authenticated: authenticated, requestID: requestID,
            doctor: doctor, probes: probes, expectedUID: getuid()) else { return }
        Self.logger.notice("\(line, privacy: .public)")
    }
}
