import Foundation

/// One doctor reply observes one shared foreground/session fact. No instance or
/// probe result is retained between replies or reused by action admission.
public struct DoctorInputReadiness {
    public let enabled: [ControlReadinessRoute: Bool]
    public let probes: [ControlReadinessRoute: ControlReadinessProbeResult]

    public static func evaluate(semantic: Bool, eventPost: Bool,
                                requested: Set<ControlReadinessRoute>,
                                probe: () throws -> ControlReadinessProbeResult) -> Self {
        var enabled: [ControlReadinessRoute: Bool] = [:]
        var probes: [ControlReadinessRoute: ControlReadinessProbeResult] = [:]
        let eligible = semantic && eventPost && !requested.isEmpty
        let shared: ControlReadinessProbeResult
        if eligible {
            do { shared = try probe() }
            catch { shared = ControlReadinessProbeResult.failure(error) }
        } else { shared = .notEvaluated }
        for route in ControlReadinessRoute.allCases {
            let evaluated = eligible && requested.contains(route)
            enabled[route] = evaluated && shared == .ready
            if evaluated { probes[route] = shared }
        }
        return Self(enabled: enabled, probes: probes)
    }
}
