import Foundation

/// Owned-channel metadata only: no page values, account names or secret resources.
public struct BrowserConnectionStatus: Decodable {
    public let available: Bool
    public let attentionCode: String?
    public var processQualificationFailed: Bool { attentionCode == "chromeProcessUnqualified" }
    public let channels: [BrowserConnectionChannel]
}
public struct BrowserConnectionChannel: Decodable {
    public let profileChannel: String?
    public let browserInstance: String?
    public let allWebsites: Bool?
    public var websiteAccessDescription: String { allWebsites == true ? "All websites" : "Selected websites" }
    public let trustScope: String
    public let connected: Bool
    public let fixtureOnly: Bool
    public let processQualified: Bool
    public let scopeQualified: Bool
    public let profileQualified: Bool
    public let executorQualified: Bool
    public let inventoryComplete: Bool
    public let documentCount: Int
    public let pendingCount: Int
    public let unknownCount: Int
    public let attentionCode: String?
    public let reconnectPhase: String?
    public let reconnectReason: String?
    public var reconnectExplanation: String? {
        guard attentionCode == "storedFenceMismatch",
              let phase = reconnectPhase, let reason = reconnectReason,
              ["idle", "scope", "barriers", "journal", "inventory", "inspect", "prepare", "adopt", "commit"].contains(phase) else { return nil }
        let reasons = ["none", "portChanged", "deadline", "busy", "unknownReceipts", "privateProtection", "lifecycle", "scopeChanged", "journalChanged", "inventoryChanged", "storageFailure", "rendererUnavailable", "executorRefused", "injectionUnavailable", "restrictedBrowserPage", "packagedExecutorUnavailable", "documentChanged", "websitePermissionMissing", "extensionContextInvalidated", "restrictedFrame", "injectionArgumentsRejected", "executorEvaluationFailed"]
        guard reasons.contains(reason) else { return nil }
        switch reason {
        case "restrictedBrowserPage": return "Chrome’s internal pages cannot accept the website executor. Open a normal website, then reconnect."
        case "websitePermissionMissing": return "Chrome website access is missing. Review extension access, then reconnect."
        case "privateProtection": return "Protected credential activity requires verified cleanup before reconnecting."
        case "unknownReceipts": return "An uncertain browser action requires reconciliation before reconnecting."
        case "extensionContextInvalidated": return "The extension changed while reconnecting. Reload it and reconnect."
        case "deadline": return "The reconnect check timed out during \(phase). Retry after the browser settles."
        default: return "Reconnect stopped during \(phase): \(reason). Refresh after resolving the connection issue."
        }
    }
    public var readiness: String {
        if unknownCount > 0 { return "Recovery required" }
        if pendingCount > 0 { return "Operation pending" }
        if !connected { return "Disconnected" }
        if !["desktop", "profile"].contains(trustScope) || (trustScope == "profile" && !profileQualified) { return "Needs attention" }
        if fixtureOnly || !processQualified || !scopeQualified || !executorQualified || !inventoryComplete || !(attentionCode ?? "").isEmpty { return "Needs attention" }
        return documentCount > 0 ? "Ready" : "Open an approved website"
    }
    public var ready: Bool { readiness == "Ready" }
}
