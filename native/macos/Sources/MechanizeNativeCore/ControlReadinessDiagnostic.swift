import Foundation
import CoreFoundation

public enum ControlReadinessRoute: String, CaseIterable {
    case targetedKeyboard, sessionKeyboard, sessionText
}
public enum ControlReadinessProbeResult: String, CaseIterable {
    case notEvaluated, ready, sessionUnqualified
    case foregroundRefreshUnavailable, foregroundUnavailable, foregroundNotActive
    case foregroundOwnerUnqualified, foregroundCorroborationConflict, deadlineExceeded
    case probeUnavailable

    /// Native errors may contain values. Only this closed code set may be logged.
    public static func failure(_ error: Error) -> Self {
        guard let native = error as? NativeFailure else { return .probeUnavailable }
        switch native.code {
        case "foregroundRefreshUnavailable": return .foregroundRefreshUnavailable
        case "foregroundUnavailable": return .foregroundUnavailable
        case "foregroundNotActive": return .foregroundNotActive
        case "foregroundOwnerUnqualified": return .foregroundOwnerUnqualified
        case "foregroundCorroborationConflict": return .foregroundCorroborationConflict
        case "deadlineExceeded": return .deadlineExceeded
        default: return .probeUnavailable
        }
    }
}

/// A value-free log projection, not admission evidence. Unknown/malformed fields
/// stay unknown. No arbitrary keys, UI values, process IDs or raw errors survive.
public enum ControlReadinessDiagnostic {
    public static func line(authenticated: Bool, requestID: String, doctor: [String: Any],
                            probes: [ControlReadinessRoute: ControlReadinessProbeResult], expectedUID: UInt32) -> String? {
        guard authenticated, requestID == "launch-readiness" else { return nil }
        func flag(_ value: Any?) -> String {
            guard let number = value as? NSNumber, CFGetTypeID(number) == CFBooleanGetTypeID() else { return "unknown" }
            return number.boolValue ? "true" : "false"
        }
        var fields: [String] = []
        for (label, key) in [("brokerAuth", "brokerIdentityAuthenticated"), ("AX", "axTrusted"),
                             ("secureInput", "secureInputEnabled"), ("watchdog", "watchdogLive"),
                             ("fence", "physicalFenceEnrolled"), ("semantic", "semanticEnabled"),
                             ("rawMutation", "mutationEnabled"), ("launch", "launchEnabled"),
                             ("targetedKeyboard", "targetedKeyboardEnabled"), ("sessionKeyboard", "sessionKeyboardEnabled"),
                             ("sessionText", "sessionTextEnabled"), ("frameClick", "windowFrameClickEnabled"),
                             ("eventPost", "eventPostGranted"), ("capture", "captureGranted")] {
            fields.append(label + "=" + flag(doctor[key]))
        }
        let session = doctor["windowSession"] as? [String: Any] ?? [:]
        for (label, key) in [("sessionAvailable", "available"), ("sessionOnConsole", "onConsole"), ("sessionLoginDone", "loginDone")] {
            fields.append(label + "=" + flag(session[key]))
        }
        var uidMatch = "unknown"
        if let uid = session["uid"] as? NSNumber, CFGetTypeID(uid) == CFNumberGetTypeID(),
           uid.doubleValue.isFinite, uid.doubleValue >= 0, uid.doubleValue <= Double(UInt32.max),
           uid.doubleValue.rounded(.towardZero) == uid.doubleValue {
            uidMatch = uid.uint32Value == expectedUID ? "true" : "false"
        }
        fields.append("sessionUIDMatch=" + uidMatch)
        for route in ControlReadinessRoute.allCases {
            fields.append(route.rawValue + "Probe=" + (probes[route] ?? .notEvaluated).rawValue)
        }
        return "launch-readiness{" + fields.joined(separator: ";") + "}"
    }
}
