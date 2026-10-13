import Foundation
import Darwin
import AppKit
import Carbon
import ApplicationServices
import ScreenCaptureKit
import ImageIO
import UniformTypeIdentifiers
import MechanizeNativeCore

// Desktop-wide authority belongs only to this login desktop, never to an app
// inventory or a wildcard target. JSON numbers/strings cannot impersonate Bool.
func concreteApplicationBundle(_ bundle: String) -> Bool {
    !bundle.isEmpty && bundle.utf8.count <= 255 && bundle.range(of: #"^[A-Za-z0-9][A-Za-z0-9-]*(\.[A-Za-z0-9][A-Za-z0-9-]*)+$"#, options: .regularExpression) != nil
}
func applicationLoginUID(_ pid: pid_t) -> uid_t? {
    guard pid > 0 else { return nil }
    var info = proc_bsdinfo()
    let size = Int32(MemoryLayout<proc_bsdinfo>.size)
    guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size) == size, info.pbi_pid == UInt32(pid) else { return nil }
    return info.pbi_uid
}
func fenceScopeAllows(_ scope: [String: Any], _ bundle: String) -> Bool {
    guard concreteApplicationBundle(bundle), let bundles = scope["allowedBundles"] as? [String] else { return false }
    var all = false
    if let raw = scope["allApplications"] {
        guard CFGetTypeID(raw as CFTypeRef) == CFBooleanGetTypeID(), let value = raw as? Bool else { return false }
        all = value
    }
    if all { return bundles.isEmpty }
    guard !bundles.isEmpty, bundles.count <= 64, Set(bundles).count == bundles.count, bundles.allSatisfy(concreteApplicationBundle) else { return false }
    return bundles.contains(bundle)
}

struct Reference {
    let owner: AXElementOwner
    let element: AXUIElement
    let pid: pid_t
    let bundleID: String
    let startToken: String
    let generation: Int
    let observedAt: UInt64
    let scopedRoot: ScopedNativeRoot?
    func validateProcess() throws {
        guard let app = NSRunningApplication(processIdentifier: pid), app.bundleIdentifier == bundleID,
              applicationProcessStartToken(pid) == startToken, applicationLoginUID(pid) == getuid() else {
            throw NativeFailure("staleReference", "Target process fingerprint changed")
        }
    }
    func validateInputScope(_ budget: Budget) throws {
        try budget.check(); try validateProcess()
        if let scopedRoot {
            AXUIElementSetMessagingTimeout(scopedRoot.application, min(0.1, budget.remainingSeconds))
            AXUIElementSetMessagingTimeout(scopedRoot.element, min(0.1, budget.remainingSeconds))
            try scopedRoot.validate(referenceElement: element, check: { try budget.check() })
            guard applicationProcessStartToken(pid) == startToken, applicationLoginUID(pid) == getuid() else {
                throw NativeFailure("staleReference", "Scoped application process changed during root qualification")
            }
        }
    }
}

@main struct Main {
    static func main() async {
        let brokerAuthenticated: Bool
        do {
            brokerAuthenticated = try authenticateLaunch()
        } catch {
            // Never expose the rendezvous path or nonce in diagnostics.
            FileHandle.standardError.write(Data("mechanize-native: launch identity rejected\n".utf8))
            exit(78)
        }
        // AppKit's public mouse-down hit test requires an application connection
        // to WindowServer. No windows, activation or input are created here.
        await MainActor.run {
            let application = NSApplication.shared
            _ = application.setActivationPolicy(.accessory)
        }
        let helper = Helper(brokerAuthenticated: brokerAuthenticated)
        do {
            let reader=FramedInputReader(.standardInput)
            while let data = try await reader.read() {
                guard let request = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { throw FramingError.invalid }
                let reply = await helper.handle(request)
                try FrameCodec.writeResponse(reply, to: .standardOutput, requestMethod: request["method"] as? String ?? "", brokerAuthenticated: brokerAuthenticated)
            }
        } catch { FileHandle.standardError.write(Data("mechanize-native: protocol terminated\n".utf8)) }
        await MainActor.run {BrowserControlBadge.shared.releaseAll();AutomationPointer.stopControl()}
        helper.stopRecordingOnExit()
        _ = helper.inputs.inhibitAndRelease()
    }
}



final class RecordingConsentLease {
    private let lock = NSLock()
    private var binding: [String: String]?
    private var deadline: UInt64 = 0
    private var maximumEnd: UInt64 = 0
    private var expiry: Int64 = 0
    private var withdrawn = false
    static func integer(_ value: Any?, maximum: UInt64) throws -> UInt64 {
        guard let value = value as? NSNumber, CFGetTypeID(value) == CFNumberGetTypeID(), value.doubleValue.isFinite,
              value.doubleValue >= 0, value.doubleValue <= Double(maximum), value.doubleValue.rounded(.towardZero) == value.doubleValue else { throw NativeFailure("invalidRecording", "Bounded integer recording field required") }
        return value.uint64Value
    }
    static func bounded(_ value: Any?, maximum: Int) -> String? {
        guard let value = value as? String, !value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty, value.utf8.count <= maximum, !value.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else { return nil }
        return value
    }
    static func scope(_ params: [String: Any]) throws -> [String: String] {
        guard let id = bounded(params["recordingId"], maximum: 128), id.utf8.allSatisfy({ (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || [45,95].contains($0) }),
              let namespace = bounded(params["namespace"], maximum: 64), namespace.utf8.count == 64, namespace.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }),
              let client = bounded(params["clientId"], maximum: 128), let session = bounded(params["sessionId"], maximum: 128),
              let nonce = bounded(params["consentNonce"], maximum: 64), nonce.utf8.count == 64, nonce.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else { throw NativeFailure("invalidRecording", "Exact bounded recording owner and consent binding required") }
        return ["recordingId": id, "namespace": namespace, "clientId": client, "sessionId": session, "consentNonce": nonce]
    }
    func begin(_ params: [String: Any], expectedUID: UInt32) throws -> NativeRecordingOptions {
        let scope = try Self.scope(params)
        guard Set(params.keys) == Set(["recordingId", "namespace", "clientId", "sessionId", "consentNonce", "expectedUID", "maxEvents", "maxDurationMs", "grantRemainingMs"]),
              try Self.integer(params["expectedUID"], maximum: UInt64(UInt32.max)) == expectedUID else { throw NativeFailure("invalidRecording", "Current-user recording scope required") }
        let capacity = try Self.integer(params["maxEvents"], maximum: 4096), duration = try Self.integer(params["maxDurationMs"], maximum: 900_000), ttl = try Self.integer(params["grantRemainingMs"], maximum: 30_000)
        guard capacity >= 4, duration >= 1000, ttl >= 1000 else { throw NativeFailure("invalidRecording", "Bounded recording duration, capacity and grant TTL required") }
        lock.lock(); defer { lock.unlock() }
        guard binding == nil else { throw NativeFailure("recordingConflict", "Helper already bound to recording") }
        let now = DispatchTime.now().uptimeNanoseconds
        binding = scope; maximumEnd = now + duration * 1_000_000; deadline = min(maximumEnd, now + ttl * 1_000_000)
        expiry = Int64(Date().timeIntervalSince1970 * 1000) + Int64(min(duration, ttl))
        return NativeRecordingOptions(recordingID: scope["recordingId"]!, expectedUID: expectedUID, maxEvents: Int(capacity), durationMs: Int(duration))
    }
    func check(_ params: [String: Any], method: String) throws {
        let supplied = try Self.scope(params)
        var keys = Set(["recordingId", "namespace", "clientId", "sessionId", "consentNonce"])
        if method == "record.renew" { keys.insert("grantRemainingMs") }
        if ["record.events", "record.pause", "record.stop"].contains(method) { keys.formUnion(["afterSequence", "limit"]) }
        lock.lock(); defer { lock.unlock() }
        guard supplied == binding, Set(params.keys) == keys else { throw NativeFailure("recordingDenied", "Recording owner or consent binding differs") }
    }
    func renew(_ params: [String: Any]) throws {
        try check(params, method: "record.renew")
        let ttl = try Self.integer(params["grantRemainingMs"], maximum: 30_000)
        guard ttl >= 1000 else { throw NativeFailure("invalidRecording", "Live recording grant TTL required") }
        lock.lock(); defer { lock.unlock() }
        let now = DispatchTime.now().uptimeNanoseconds
        guard !withdrawn, now < deadline, now < maximumEnd else { throw NativeFailure("recordingDenied", "Recording consent expired or withdrawn") }
        deadline = min(maximumEnd, now + ttl * 1_000_000)
        expiry = Int64(Date().timeIntervalSince1970 * 1000) + Int64((deadline-now)/1_000_000)
    }
    func alive() -> Bool { lock.lock(); defer { lock.unlock() }; return binding != nil && !withdrawn && DispatchTime.now().uptimeNanoseconds < deadline }
    func withdraw() { lock.lock(); withdrawn = true; lock.unlock() }
    func owner() -> [String: String]? {
        lock.lock(); defer { lock.unlock() }
        guard let binding else { return nil }
        return ["namespace": binding["namespace"]!, "clientId": binding["clientId"]!, "sessionId": binding["sessionId"]!]
    }
    func expiryUnixMS() -> Int64 { lock.lock(); defer { lock.unlock() }; return expiry }
}

final class Helper {
    let brokerAuthenticated: Bool
    let epoch = UUID().uuidString
    var hierarchyObserver: HierarchyObserver?
    var hierarchyRevision: UInt64 = 0
    deinit { hierarchyObserver?.stop() }
    func refreshHierarchyInvalidation() {
        if let observer = hierarchyObserver, observer.signal.revision != hierarchyRevision {
            hierarchyRevision = observer.signal.revision
            generation += 1; refs.removeAll()
        }
    }
    var generation = 0
    var refs: [String: Reference] = [:]
    var lease: (String, Int)?
    var launchUncertain = false
    let ledger = MutationLedger()
    let inputs = InputSafety()
    let framePermits = WindowFramePermitStore()
    let frameImages = WindowFrameImageStore()
    lazy var watchdog: Watchdog? = brokerAuthenticated ? Watchdog(inputs: inputs, beforeExit: { [weak self] in self?.clearWindowFrame(); self?.stopRecordingOnExit(); self?.hierarchyObserver?.stop() }) : nil
    let recordingConsent = RecordingConsentLease()
    let recordingLock = NSLock()
    var nativeRecorder: NativeRecorder?
    var recordingEnabled: Bool { brokerAuthenticated && ProcessInfo.processInfo.arguments.contains("--allow-recording") && watchdog?.live() == true }
    func installRecordingInstance(_ recorder: NativeRecorder) throws {
        recordingLock.lock(); defer { recordingLock.unlock() }
        guard nativeRecorder == nil else { recordingConsent.withdraw(); throw NativeFailure("recordingConflict", "Helper already assigned a recording") }
        nativeRecorder = recorder
    }
    func recordingInstance() -> NativeRecorder? { recordingLock.lock(); defer { recordingLock.unlock() }; return nativeRecorder }
    func stopRecordingOnExit() {
        recordingConsent.withdraw()
        recordingLock.lock(); let recorder = nativeRecorder; recordingLock.unlock()
        _ = try? recorder?.stop()
    }
    func recordingResult(_ batch: NativeRecordingBatch) throws -> [String: Any] {
        let encoded = try JSONEncoder().encode(batch)
        guard var result = try JSONSerialization.jsonObject(with: encoded) as? [String: Any], let owner = recordingConsent.owner() else { throw NativeFailure("invalidRecording", "Recording owner unavailable") }
        result["owner"] = owner
        result["leaseExpiresUnixMs"] = recordingConsent.expiryUnixMS()
        return result
    }
    var mutationsEnabled: Bool { brokerAuthenticated && ProcessInfo.processInfo.arguments.contains("--allow-mutations") && watchdog != nil && fenceLease() != nil }
    var semanticEnabled: Bool { brokerAuthenticated && ProcessInfo.processInfo.arguments.contains("--allow-semantic") && AXIsProcessTrusted() && !IsSecureEventInputEnabled() && watchdog?.live() == true && fenceLease() != nil }
    var targetedKeyboardEnabled: Bool { targetedKeyboardEnabled(diagnostic: nil) }
    func targetedKeyboardEnabled(diagnostic: ((ControlReadinessProbeResult) -> Void)?) -> Bool {
        semanticEnabled && ProcessInfo.processInfo.arguments.contains("--allow-targeted-keyboard") && CGPreflightPostEventAccess() && targetedKeyboardSessionAvailable(diagnostic: diagnostic)
    }
    var sessionKeyboardEnabled: Bool { sessionKeyboardEnabled(diagnostic: nil) }
    func sessionKeyboardEnabled(diagnostic: ((ControlReadinessProbeResult) -> Void)?) -> Bool {
        semanticEnabled && ProcessInfo.processInfo.arguments.contains("--allow-session-keyboard") && CGPreflightPostEventAccess() && targetedKeyboardSessionAvailable(diagnostic: diagnostic)
    }
    var sessionTextEnabled: Bool { sessionTextEnabled(diagnostic: nil) }
    func sessionTextEnabled(diagnostic: ((ControlReadinessProbeResult) -> Void)?) -> Bool {
        semanticEnabled && ProcessInfo.processInfo.arguments.contains("--allow-session-text") && CGPreflightPostEventAccess() && targetedKeyboardSessionAvailable(diagnostic: diagnostic)
    }
    var windowFrameClickEnabled: Bool { semanticEnabled && ProcessInfo.processInfo.arguments.contains("--allow-window-frame-click") && CGPreflightPostEventAccess() && CGPreflightScreenCaptureAccess() && sessionKeyReleaseAllowed() }
    var launchEnabled: Bool { brokerAuthenticated && (ProcessInfo.processInfo.arguments.contains("--allow-launch") || ProcessInfo.processInfo.arguments.contains("--allow-mutations") || ProcessInfo.processInfo.arguments.contains("--allow-semantic")) && watchdog?.live() == true && fenceLease() != nil }
    init(brokerAuthenticated: Bool) { self.brokerAuthenticated = brokerAuthenticated; _ = watchdog }
    let iso = ISO8601DateFormatter()
    let preciseISO: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter
    }()
    func handle(_ request: [String: Any]) async -> [String: Any] {
        refreshHierarchyInvalidation()
        let id = request["requestId"] as? String ?? ""
        let method = request["method"] as? String ?? ""
        var reply: [String: Any] = ["protocolVersion": 1, "requestId": id, "helperEpoch": epoch]
        let mutation = ["app.launch", "app.activate", "app.quit", "elements.press", "elements.showMenu", "elements.setValue", "elements.submit", "elements.focus", "elements.pressKey", "elements.pressSessionKey", "windows.setPosition", "windows.pressSessionKey", "windows.typeText", "windows.clickFrame", "elements.replaceText", "input.key", "input.text", "input.pointer"].contains(method)
        var reserved = false,businessReserved=false
        var foregroundRevalidate:(()throws->Void)?
 var controlBadge:UInt64?
 let presentationSession=request["presentationSession"] as? String
 let badgeActionDeadline=ProcessInfo.processInfo.systemUptime + Double(max(1,min(30000,request["deadlineRemainingMs"] as? Int ?? 1)))/1000
 defer {if let controlBadge {AutomationPointer.endControl(controlBadge)}}
        let requestObserver = hierarchyObserver
        var requestRevision = requestObserver?.signal.revision
        let requestStructuralRevision=requestObserver?.signal.structuralRevision
        func reserveMutation() throws {
            try foregroundRevalidate?()
            if let requestObserver, let originalRevision=requestRevision,
               requestObserver.signal.revision != originalRevision {
                if let revalidate=foregroundRevalidate,let structural=requestStructuralRevision,requestObserver.signal.structuralRevision==structural {
                    requestRevision=try confirmNativeFocusTransition(requestObserver.signal,structural:structural,revalidate:revalidate)
                } else {refreshHierarchyInvalidation();throw NativeFailure("staleReference", "Application hierarchy changed before dispatch; reobserve")}
            }
            guard !businessReserved else{throw NativeFailure("duplicateRequest","Business dispatch already reserved")}
            if !reserved {try ledger.reserve(id)}
            reserved = true;businessReserved=true
            if !NativeControlBadgeRoutes.delayUntilDispatch(method) {startRequestBadge()}
        }
        func startRequestBadge() {
            if controlBadge != nil {return}
            let badgeParams = request["params"] as? [String: Any] ?? [:]
            if let refID = badgeParams["elementRef"] as? String, let ref = refs[refID],
               applicationProcessStartToken(ref.pid) == ref.startToken, applicationLoginUID(ref.pid) == getuid(),
               let bounds = AutomationPointer.windowBounds(element: ref.element, pid: ref.pid) {
                controlBadge = AutomationPointer.beginOwnedControl(pid:ref.pid,birth:ref.startToken,bundle:ref.bundleID,window:bounds,sessionToken:presentationSession,actionDeadline:badgeActionDeadline)
            } else if ["windows.typeText", "windows.pressSessionKey"].contains(method),
                      let pid = badgeParams["pid"] as? Int, let birth = badgeParams["processStartToken"] as? String,
                      let bundle = badgeParams["expectedApp"] as? String, let windowID = badgeParams["windowId"] as? UInt32,
                      let bounds = AutomationPointer.ownedWindowBounds(pid: pid_t(pid), birth: birth, bundle: bundle, windowID: windowID) {
                controlBadge = AutomationPointer.beginOwnedControl(pid:pid_t(pid),birth:birth,bundle:bundle,window:bounds,windowID:windowID,sessionToken:presentationSession,actionDeadline:badgeActionDeadline)
            } else if ["app.activate", "app.quit"].contains(method), let pid = badgeParams["pid"] as? Int,
                      let birth = badgeParams["startToken"] as? String, let bundle = badgeParams["expectedApp"] as? String,
                      applicationProcessStartToken(pid_t(pid)) == birth, applicationLoginUID(pid_t(pid)) == getuid(),
                      NSRunningApplication(processIdentifier: pid_t(pid))?.bundleIdentifier == bundle {
                let app = AXUIElementCreateApplication(pid_t(pid))
                AXUIElementSetMessagingTimeout(app, 0.05)
                if let focused = attribute(app, kAXFocusedWindowAttribute), CFGetTypeID(focused) == AXUIElementGetTypeID(),
                   let bounds = AutomationPointer.windowBounds(element: focused as! AXUIElement, pid: pid_t(pid)) {
                    controlBadge = AutomationPointer.beginOwnedControl(pid:pid_t(pid),birth:birth,bundle:bundle,window:bounds,sessionToken:presentationSession,actionDeadline:badgeActionDeadline)
                }
            }
        }
        let started = iso.string(from: Date())
        do {
            guard request["protocolVersion"] as? Int == 1, !id.isEmpty, id.utf8.count <= 128 else { throw NativeFailure("invalidRequest", "Invalid version or request ID") }
            if request["presentationSession"] != nil && (presentationSession==nil || !ControlBadgeScope.validToken(presentationSession!)) {throw NativeFailure("invalidRequest","Invalid presentation ownership") }
            let budget = try Budget(milliseconds: request["deadlineRemainingMs"] as? Int ?? 0)
            let params = request["params"] as? [String: Any] ?? [:]
            if method != "doctor" && method != "apps.list" {
                guard request["helperEpoch"] as? String == epoch else { throw NativeFailure("staleEpoch", "Helper epoch differs; reobserve") }
            }
            if mutation {
                if method != "windows.clickFrame" { clearWindowFrame() }
                if let prior = ledger.reply(for: id) { return prior }
                let semantic = ["app.activate", "app.quit", "elements.press", "elements.showMenu", "elements.setValue", "elements.submit", "elements.focus", "windows.setPosition", "elements.replaceText"].contains(method)
                guard method == "windows.typeText" ? sessionTextEnabled : method == "windows.clickFrame" ? windowFrameClickEnabled : (method == "elements.pressSessionKey" || method == "windows.pressSessionKey") ? sessionKeyboardEnabled : (method == "elements.pressKey" ? targetedKeyboardEnabled : (method == "app.launch" ? launchEnabled : (semantic ? semanticEnabled || mutationsEnabled : mutationsEnabled))) else { throw NativeFailure("mutationDisabled", "Signed helper requires explicit authority for this action route") }
                guard watchdog?.live() == true, let persisted = fenceLease(), let offered = request["lease"] as? [String: Any], let lease,
                      persisted["id"] as? String == lease.0, persisted["generation"] as? Int == lease.1,
                      let scope = persisted["scope"] as? [String: Any],
                      let expectedApp = params["expectedApp"] as? String, fenceScopeAllows(scope, expectedApp),
                      offered["id"] as? String == lease.0, offered["generation"] as? Int == lease.1 else { throw NativeFailure("staleLease", "Control lease is absent or stale") }
            }
            try budget.check()
            let privateAdministration = ProcessInfo.processInfo.arguments.contains("--private-administration")
            if privateAdministration && !["doctor","private.consoleWindows","private.managementProof"].contains(method) {
                throw NativeFailure("privateProfileOnly", "Private profile rejects ordinary automation")
            }
            func acquisitionAuthority(_ bundle:String)throws {
                try budget.check()
                guard watchdog?.live()==true,let persisted=fenceLease(),let held=lease,let offered=request["lease"] as? [String:Any],persisted["id"] as? String==held.0,persisted["generation"] as? Int==held.1,offered["id"] as? String==held.0,offered["generation"] as? Int==held.1,let scope=persisted["scope"] as? [String:Any],fenceScopeAllows(scope,bundle) else{throw NativeFailure("staleLease","Foreground preparation authority changed")}
                if let requestObserver,requestObserver.signal.structuralRevision != requestStructuralRevision {throw NativeFailure("staleReference","Application structure changed during foreground preparation")}
            }
            func acquire(_ target:NativeForegroundTarget)throws {
                try target.acquire(budget,authorize:{try acquisitionAuthority(target.bundle)},reserve:{
                    if !reserved {try ledger.reserve(id);reserved=true}
                },publish:{state in reply["foregroundAcquisition"]=state.metadata;if state.activationRequested{startRequestBadge()}})
                try acquisitionAuthority(target.bundle);try target.validate(budget)
                foregroundRevalidate={
                    try acquisitionAuthority(target.bundle);try target.validate(budget)
                    guard try target.ready(budget) else{throw NativeFailure("foregroundChanged","Original foreground/window changed before input")}
                    if let ref=target.reference,["elements.pressKey","elements.pressSessionKey","input.key","input.text"].contains(method){try validateTargetedFocus(ref,budget)}
                    try acquisitionAuthority(target.bundle)
                }
                if let requestObserver,let structural=requestStructuralRevision,let revalidate=foregroundRevalidate {requestRevision=try confirmNativeFocusTransition(requestObserver.signal,structural:structural,revalidate:revalidate)}
            }
            if let target=try foregroundTarget(method:method,params:params,budget:budget){try acquire(target)}
            switch method {
            case "controlBadge.begin", "controlBadge.renew", "controlBadge.end", "controlBadge.stop", "controlBadge.releaseSession":
                guard brokerAuthenticated, method=="controlBadge.releaseSession" || watchdog?.live() == true else {throw NativeFailure("badgeUnavailable", "Authenticated presentation unavailable")}
                try budget.check()
                reply["result"] = try await MainActor.run { try BrowserControlBadge.shared.handle(method:method,params:params) }

            case "private.consoleWindows", "private.managementProof":
                guard privateAdministration, brokerAuthenticated, watchdog?.live() == true else { throw NativeFailure("privateProfileRequired", "Authenticated private profile required") }
                reply["result"] = try privateAdministrationResult(method:method,params:params,budget:budget)

            case "input.releasedState":
                guard params.isEmpty, brokerAuthenticated, AXIsProcessTrusted(),
                      CGPreflightListenEventAccess(), sessionKeyReleaseAllowed(), !IsSecureEventInputEnabled() else {
                    throw NativeFailure("inputStateUnqualified", "Qualified nonsecure console input state required")
                }
                func releasedState() throws -> Bool {
                    try budget.check()
                    for key in 0..<128 {
                        if CGEventSource.keyState(.combinedSessionState, key: CGKeyCode(key)) { return false }
                    }
                    for button in [CGMouseButton.left, .right, .center] {
                        if CGEventSource.buttonState(.combinedSessionState, button: button) { return false }
                    }
                    return true
                }
                let first = try releasedState()
                try await Task.sleep(nanoseconds:20_000_000)
                guard sessionKeyReleaseAllowed(), !IsSecureEventInputEnabled(), CGPreflightListenEventAccess() else {
                    throw NativeFailure("inputStateUnqualified", "Console input qualification changed")
                }
                let second = try releasedState()
                reply["result"] = ["released": first && second]

            case "doctor":
                let readinessLog = brokerAuthenticated && id == "launch-readiness" ? ManagedControlReadinessLog() : nil
                let doctorArguments = ProcessInfo.processInfo.arguments
                var requestedReadiness = Set<ControlReadinessRoute>()
                if doctorArguments.contains("--allow-targeted-keyboard") { requestedReadiness.insert(.targetedKeyboard) }
                if doctorArguments.contains("--allow-session-keyboard") { requestedReadiness.insert(.sessionKeyboard) }
                if doctorArguments.contains("--allow-session-text") { requestedReadiness.insert(.sessionText) }
                let doctorSemantic = semanticEnabled
                let doctorEventPost = doctorSemantic && !requestedReadiness.isEmpty && CGPreflightPostEventAccess()
                let inputReadiness = DoctorInputReadiness.evaluate(semantic: doctorSemantic,
                    eventPost: doctorEventPost, requested: requestedReadiness) {
                    var result: ControlReadinessProbeResult = .probeUnavailable
                    let available = targetedKeyboardSessionAvailable(diagnostic: { result = $0 })
                    return available ? .ready : result
                }
                for (route, result) in inputReadiness.probes { readinessLog?.record(route, result) }
                reply["result"] = ["privateAdministrationVersion": privateAdministration ? 1 : 0, "osVersion": ProcessInfo.processInfo.operatingSystemVersionString, "helperVersion": "0.1.0-dev", "axTrusted": AXIsProcessTrusted(), "captureGranted": CGPreflightScreenCaptureAccess(), "listenGranted": CGPreflightListenEventAccess(), "eventPostGranted": CGPreflightPostEventAccess(), "secureInputEnabled": IsSecureEventInputEnabled(), "watchdogLive": watchdog?.live() ?? false, "physicalFenceEnrolled": fenceLease() != nil, "mutationEnabled": mutationsEnabled, "semanticEnabled": semanticEnabled, "targetedKeyboardEnabled": inputReadiness.enabled[.targetedKeyboard] == true, "sessionKeyboardEnabled": inputReadiness.enabled[.sessionKeyboard] == true, "sessionTextEnabled": inputReadiness.enabled[.sessionText] == true, "developmentSemanticOnly": ProcessInfo.processInfo.arguments.contains("--allow-semantic") && !ProcessInfo.processInfo.arguments.contains("--allow-targeted-keyboard") && !ProcessInfo.processInfo.arguments.contains("--allow-session-keyboard") && !ProcessInfo.processInfo.arguments.contains("--allow-session-text"), "launchEnabled": launchEnabled,  "windowSession": windowSession(), "productionIdentityQualified": false, "brokerIdentityAuthenticated": brokerAuthenticated, "activeGraphicalSessionQualified": false, "displays": displays(), "nativeRootScopes": NativeRootScope.allCases.map { $0.rawValue }, "nativeMenuScopeVersion": 1, "nativeWindowScopes": ["exactTitle"], "nativeWindowActions": ["setPosition", "pressSessionKey", "typeText", "captureFrame", "clickFrame"], "nativeTextActions": ["replaceText"], "nativeTextReads": ["valueMatches"], "nativeBooleanReads": ["checked"], "nativeForegroundAcquisitionVersion": 1, "controlBadgePresentationVersion": 2, "supportedMethods": ["controlBadge.begin", "controlBadge.renew", "controlBadge.end", "controlBadge.stop", "controlBadge.releaseSession", "doctor", "apps.list", "app.launch", "app.activate", "windows.list", "windows.setPosition", "windows.pressSessionKey", "windows.typeText", "elements.snapshot", "elements.read", "elements.replaceText", "elements.valueMatches", "elements.press", "elements.showMenu", "elements.setValue", "elements.submit", "elements.focus", "elements.pressKey", "elements.pressSessionKey", "input.key", "input.text", "input.pointer", "input.releaseAll", "capture.image", "capture.windows", "lease.install", "lease.revoke", "record.start", "record.renew", "record.pause", "record.stop", "record.events"], "unsupported": [ "subscriptions", "ocr", "windowUpdate", "clipboard"]] as [String: Any]
                if var doctor = reply["result"] as? [String: Any] {
                    doctor["windowFrameClickEnabled"] = windowFrameClickEnabled
                    doctor["windowFrameClickBackend"] = "robotgo"
                    doctor["windowFrameClickBackendVersion"] = "1.3.5"
                    doctor["quitEnabled"] = semanticEnabled || mutationsEnabled
                    doctor["nativeSemanticMenus"] = ["AXShowMenu"]
                    doctor["supportedMethods"] = (doctor["supportedMethods"] as? [String] ?? []) + ["windows.captureFrame", "windows.clickFrame", "app.quit", "app.exitStatus"]
                    doctor["recordingEnabled"] = recordingEnabled
                    doctor["passiveRecordingOnly"] = ProcessInfo.processInfo.arguments.contains("--allow-recording")
                    reply["result"] = doctor
                }
                readinessLog?.emit(authenticated: brokerAuthenticated, requestID: id, doctor: reply["result"] as? [String: Any] ?? [:])
            case "record.start":
                guard recordingEnabled else { throw NativeFailure("recordingDenied", "Signed recording-only profile and live watchdog required") }
                let options = try recordingConsent.begin(params, expectedUID: getuid())
                let heldWatchdog = watchdog
                let recorder = NativeRecorder(runtime: .live(authorizedLive: { [recordingConsent] in recordingConsent.alive() }, watchdogLive: { heldWatchdog?.live() == true }))
                try installRecordingInstance(recorder)
                do { reply["result"] = try recordingResult(recorder.start(options)) }
                catch { recordingConsent.withdraw(); _ = try? recorder.stop(); throw error }
            case "record.renew", "record.pause", "record.stop", "record.events":
                try recordingConsent.check(params, method: method)
                guard let recorder = recordingInstance() else { throw NativeFailure("recordingUnavailable", "Owned recording not started") }
                if method == "record.renew" {
                    guard recordingEnabled else { recordingConsent.withdraw(); _ = try? recorder.stop(); throw NativeFailure("recordingDenied", "Recording watchdog is not live") }
                    try recordingConsent.renew(params)
                    reply["result"] = try recordingResult(recorder.poll(after: 0))
                } else {
                    let after = try RecordingConsentLease.integer(params["afterSequence"], maximum: 4096)
                    let limit = try RecordingConsentLease.integer(params["limit"], maximum: 64)
                    guard limit > 0 else { throw NativeFailure("invalidRecording", "Recording poll limit required") }
                    if method == "record.pause" { recordingConsent.withdraw(); recorder.pause() }
                    if method == "record.stop" { recordingConsent.withdraw(); _ = try recorder.stop() }
                    reply["result"] = try recordingResult(recorder.poll(after: UInt64(after), limit: Int(limit)))
                }
            case "lease.install":
                guard mutationsEnabled || launchEnabled || semanticEnabled || windowFrameClickEnabled, let leaseID = params["id"] as? String, !leaseID.isEmpty, let version = params["generation"] as? Int, version > (lease?.1 ?? 0) else { throw NativeFailure("invalidLease", "Requires enabled native action authority and increasing lease generation") }
                guard let persisted = fenceLease(), persisted["id"] as? String == leaseID, persisted["generation"] as? Int == version, watchdog?.live() == true else { throw NativeFailure("staleLease", "Inherited physical fence differs or watchdog is inhibited") }
                clearWindowFrame(); lease = (leaseID, version); if mutationsEnabled || targetedKeyboardEnabled || sessionKeyboardEnabled || sessionTextEnabled || windowFrameClickEnabled { inputs.enable() }; reply["result"] = ["installed": true]
            case "lease.revoke", "input.releaseAll":
                AutomationPointer.hide(); clearWindowFrame(); lease = nil; let released = inputs.cleanupOutcome(businessOutcomeUnknown: launchUncertain); reply["result"] = ["revoked": true, "releasesDispatched": released.releasesDispatched, "unknownReleases": released.unknownReleases, "businessOutcomeUnknown": released.businessOutcomeUnknown, "businessSuccess": false]
            case "apps.list":
                reply["result"] = try applicationInventory(params)
            case "app.exitStatus":
                reply["result"] = try applicationExitStatus(params)
            case "app.quit":
                let outcome = try quitApplication(params, budget) {
                    try budget.check()
                    guard self.semanticEnabled || self.mutationsEnabled, self.watchdog?.live() == true,
                          let held = self.lease, let persisted = self.fenceLease(),
                          persisted["id"] as? String == held.0, persisted["generation"] as? Int == held.1,
                          let scope = persisted["scope"] as? [String: Any],
                          let bundle = params["expectedApp"] as? String, fenceScopeAllows(scope, bundle) else {
                        throw NativeFailure("staleLease", "Quit authority changed before dispatch")
                    }
                    try reserveMutation()
                    self.refs.removeAll(); self.generation += 1; self.clearWindowFrame()
                }
                launchUncertain = launchUncertain || outcome.dispatchState == "unknown"
                if outcome.failure == nil,outcome.dispatchState == "dispatched",let pid=outcome.result["pid"] as? Int32,let birth=outcome.result["startToken"] as? String,let bundle=outcome.result["bundleID"] as? String {controlBadge=AutomationPointer.beginApplicationControl(pid:pid,birth:birth,bundle:bundle,sessionToken:presentationSession,actionDeadline:badgeActionDeadline)}
                reply["result"] = outcome.result
                reply["receipt"] = ["dispatchState": outcome.dispatchState, "startedAt": started, "returnedAt": iso.string(from: Date()), "businessSuccess": false]
                if let failure = outcome.failure { reply["error"] = ["code": failure.code, "message": failure.message, "stage": "native", "retryableRead": false, "dispatchState": outcome.dispatchState] }
            case "app.activate":
                let outcome = try activateApplication(params, budget) {
                    try budget.check(); try reserveMutation()
                }
                launchUncertain = launchUncertain || outcome.dispatchState == "unknown"
                if outcome.failure == nil,outcome.dispatchState == "dispatched",let pid=outcome.result["pid"] as? Int32,let birth=outcome.result["startToken"] as? String,let bundle=outcome.result["bundleID"] as? String {controlBadge=AutomationPointer.beginApplicationControl(pid:pid,birth:birth,bundle:bundle,sessionToken:presentationSession,actionDeadline:badgeActionDeadline)}
                reply["result"] = outcome.result
                reply["receipt"] = ["dispatchState": outcome.dispatchState, "startedAt": started, "returnedAt": iso.string(from: Date()), "businessSuccess": false]
                if let failure = outcome.failure { reply["error"] = ["code": failure.code, "message": failure.message, "stage": "native", "retryableRead": false, "dispatchState": "unknown"] }
                refs.removeAll(); generation += 1
            case "app.launch":
                let outcome = try await launchApplication(params, budget) {
                    try budget.check(); try reserveMutation()
                }
                launchUncertain = launchUncertain || outcome.dispatchState == "unknown"
                if outcome.failure == nil,outcome.dispatchState == "dispatched",let pid=outcome.result["pid"] as? Int32,let birth=outcome.result["startToken"] as? String,let bundle=outcome.result["bundleID"] as? String {controlBadge=AutomationPointer.beginApplicationControl(pid:pid,birth:birth,bundle:bundle,sessionToken:presentationSession,actionDeadline:badgeActionDeadline)}
                reply["result"] = outcome.result
                reply["receipt"] = ["dispatchState": outcome.dispatchState, "startedAt": started, "returnedAt": iso.string(from: Date()), "businessSuccess": false]
                if let failure = outcome.failure {
                    reply["error"] = ["code": failure.code, "message": failure.message, "stage": "native", "retryableRead": false, "dispatchState": "unknown"]
                }
                refs.removeAll(); generation += 1
            case "windows.list", "elements.snapshot":
                let (app, root) = try scopedApp(params, budget)
                guard let processStartToken = applicationProcessStartToken(app.processIdentifier) else { throw NativeFailure("staleReference", "Process identity disappeared before snapshot") }
                if let expected = params["processStartToken"] as? String, expected != processStartToken { throw NativeFailure("staleReference", "Process identity changed before snapshot") }
                if ProcessInfo.processInfo.arguments.contains("--allow-ax-observer-invalidation") {
                    if hierarchyObserver?.pid != app.processIdentifier || hierarchyObserver?.birth != processStartToken {
                        hierarchyObserver?.stop()
                        let observer = HierarchyObserver(pid: app.processIdentifier, birth: processStartToken)
                        if observer.start() { hierarchyObserver = observer } else { hierarchyObserver = nil }
                    }
                    refreshHierarchyInvalidation()
                }
                let observationRevision = hierarchyObserver?.signal.revision
                generation += 1; refs.removeAll()
                let roots: [AXUIElement]
                let rootScope = try NativeRootScope.requested(in: params, method: method)
                let windowScope = try NativeWindowScope.requested(in: params, method: method)
                let scopedRoot: ScopedNativeRoot?
                if let rootScope {
                    scopedRoot = try ScopedNativeRoot.resolve(rootScope, application: root, pid: app.processIdentifier, uid: getuid(), birth: processStartToken, bundle: app.bundleIdentifier!, nativeMenu:params["nativeMenu"] as? String, check: { try budget.check() })
                    roots = [scopedRoot!.element]
                } else if let windowScope {
                    scopedRoot = try ScopedNativeRoot.resolveWindow(windowScope, application: root, pid: app.processIdentifier, uid: getuid(), birth: processStartToken, bundle: app.bundleIdentifier!, check: { try budget.check() })
                    roots = [scopedRoot!.element]
                } else if method == "windows.list" { scopedRoot = nil; roots = try windows(root, pid: app.processIdentifier, uid: getuid(), birth: processStartToken, bundle: app.bundleIdentifier!, check: { try budget.check() }) }
                else if let windowRef = params["windowRef"] as? String { throw NativeFailure("staleReference", "Use windowIndex with a fresh scoped snapshot; windowRef \(windowRef.prefix(32)) expired") }
                else if let index = params["windowIndex"] as? Int {
                    scopedRoot = nil
                    let windows = try windows(root, pid: app.processIdentifier, uid: getuid(), birth: processStartToken, bundle: app.bundleIdentifier!, check: { try budget.check() })
                    guard windows.indices.contains(index) else { throw NativeFailure("targetNotFound", "Window index not available") }; roots = [windows[index]]
                } else { scopedRoot = nil; roots = [root] }
                // Observation owns the same presentation as AX actions. Choose
                // the exact resolved window when present; broad app/menu roots
                // use only that application's foreground window.
                if let bounds = roots.compactMap({ AutomationPointer.windowBounds(element: $0, pid: app.processIdentifier) }).first {
                    controlBadge = AutomationPointer.beginOwnedControl(pid: app.processIdentifier, birth: processStartToken, bundle: app.bundleIdentifier!, window: bounds, sessionToken: presentationSession, actionDeadline: badgeActionDeadline)
                } else {
                    controlBadge = AutomationPointer.beginApplicationControl(pid: app.processIdentifier, birth: processStartToken, bundle: app.bundleIdentifier!, sessionToken: presentationSession, actionDeadline: badgeActionDeadline)
                }
                let maxNodes = min(max(params["maxNodes"] as? Int ?? 200, 1), 1000)
                let maxDepth = min(max(params["maxDepth"] as? Int ?? 6, 0), 20)
                var queue = roots.map { ($0, 0, "") }; var nodes: [[String: Any]] = []; var partial = false
                var selfChildEdges = 0; var duplicateChildEdges = 0
                while !queue.isEmpty, nodes.count < maxNodes {
                    try budget.check(); let (element, depth, parent) = queue.removeFirst()
                    AXUIElementSetMessagingTimeout(element, min(0.2, budget.remainingSeconds))
                    let ref = UUID().uuidString
                    let owner=inspectAXElementOwner(element)
                    try budget.check()
                    if scopedRoot != nil && (owner.pid != app.processIdentifier || owner.uid != getuid() || owner.birth != processStartToken || owner.bundle != app.bundleIdentifier) { partial = true }
                    refs[ref] = Reference(owner:owner,element: element, pid: app.processIdentifier, bundleID: app.bundleIdentifier!, startToken: processStartToken, generation: generation, observedAt: DispatchTime.now().uptimeNanoseconds, scopedRoot: scopedRoot)
                    let roleAttribute = readAXAttribute(element, kAXRoleAttribute)
                    let roleRead = typedAXString(roleAttribute.0, roleAttribute.1)
                    var node: [String: Any] = ["ref": ref, "parentRef": parent, "depth": depth, "generation": generation, "nativeRole": roleRead.resolved ?? "", "unavailable": [String]()]
                    if roleRead.failed { partial = true }
                    let ownerFields=owner.metadata(root:app.processIdentifier)
                    for (key,value) in ownerFields where key != "unavailable" {node[key]=value}
                    node["unavailable"] = ownerFields["unavailable"] as? [String] ?? []
                    for (key, attr) in [("name", kAXTitleAttribute), ("identifier", kAXIdentifierAttribute), ("subrole", kAXSubroleAttribute), ("enabled", kAXEnabledAttribute)] {
                        var copied: CFTypeRef?
                        let code: AXError
                        if key == "name" { (code, copied) = accessibleName(element) }
                        else { code = AXUIElementCopyAttributeValue(element, attr as CFString, &copied) }
                        if code == .success, let value = copied {
                            node[key] = (value as? String).map { String($0.prefix(256)) } ?? value
                            if let text = value as? String, text.count > 256 { node["truncatedAttributes"] = (node["truncatedAttributes"] as? [String] ?? []) + [key] }
                        } else if code == .noValue || code == .attributeUnsupported {
                            node["absent"] = (node["absent"] as? [String] ?? []) + [key]
                        } else { node["unavailable"] = (node["unavailable"] as! [String]) + [key] }
                    }
                    // Values are withheld unless positively classified; secure/unknown fields never leak.
                    var actions: CFArray?; let actionError = AXUIElementCopyActionNames(element, &actions)
                    node["actions"] = actionError == .success ? Array((actions as? [String] ?? []).prefix(32)).map { String($0.prefix(128)) } : []
                    var settable: DarwinBoolean = false
                    node["valueSettable"] = AXUIElementIsAttributeSettable(element, kAXValueAttribute as CFString, &settable) == .success && settable.boolValue
                    for (key, attribute) in [("selectedTextSettable", kAXSelectedTextAttribute), ("selectedTextRangeSettable", kAXSelectedTextRangeAttribute)] {
                        var selectedSettable: DarwinBoolean = false
                        node[key] = AXUIElementIsAttributeSettable(element, attribute as CFString, &selectedSettable) == .success && selectedSettable.boolValue
                    }
                    var focusSettable: DarwinBoolean = false
                    node["focusSettable"] = AXUIElementIsAttributeSettable(element, kAXFocusedAttribute as CFString, &focusSettable) == .success && focusSettable.boolValue
                    let focusedAttribute = readAXAttribute(element, kAXFocusedAttribute)
                    let focusedRead = typedAXBoolean(focusedAttribute.0, focusedAttribute.1)
                    if let focused = focusedRead.resolved { node["focused"] = focused }
                    if focusedRead.failed { partial = true }
                    node["valueUnavailable"] = "withheldByPolicy"
                    if let position = attribute(element, kAXPositionAttribute), CFGetTypeID(position) == AXValueGetTypeID(), let size = attribute(element, kAXSizeAttribute), CFGetTypeID(size) == AXValueGetTypeID() {
                        var point = CGPoint.zero; var dimensions = CGSize.zero
                        if AXValueGetValue(position as! AXValue, .cgPoint, &point), AXValueGetValue(size as! AXValue, .cgSize, &dimensions) {
                            node["bounds"] = ["x": point.x, "y": point.y, "width": dimensions.width, "height": dimensions.height, "coordinateSpace": "globalLogicalPoints"]
                        }
                    }
                    nodes.append(node)
                    if method == "elements.snapshot" {
                        let childRead = try boundedSnapshotChildren(element, check: { try budget.check() })
                        partial = partial || !childRead.complete
                        let normalized = snapshotChildren(childRead.elements, of: element)
                        let children = normalized.elements
                        partial = partial || normalized.truncated
                        selfChildEdges += normalized.selfEdges; duplicateChildEdges += normalized.duplicateEdges
                        if depth < maxDepth { let available = max(0, maxNodes - nodes.count - queue.count)
                            queue.append(contentsOf: children.prefix(available).map { ($0, depth + 1, ref) })
                            partial = partial || children.count > available } else if !children.isEmpty { partial = true }
                    }
                }
                partial = partial || !queue.isEmpty
                if let observationRevision, hierarchyObserver?.signal.revision != observationRevision {
                    refreshHierarchyInvalidation()
                    throw NativeFailure("staleReference", "Application hierarchy changed during snapshot; reobserve")
                }
                guard applicationProcessStartToken(app.processIdentifier) == processStartToken else { refs.removeAll(); throw NativeFailure("staleReference", "Target process fingerprint changed during snapshot") }
                if let scopedRoot {
                    do { try scopedRoot.validate(check: { try budget.check() }) } catch { refs.removeAll(); throw error }
                }
                var snapshot: [String: Any] = ["observationId": UUID().uuidString, "generation": generation, "startedAt": started, "returnedAt": iso.string(from: Date()), "bundleID": app.bundleIdentifier!, "pid": app.processIdentifier, "nodes": nodes, "complete": !partial, "truncated": partial]
                if let rootScope { snapshot["rootScope"] = rootScope.rawValue }
                if let nativeMenu=scopedRoot?.nativeMenu {snapshot["nativeMenu"]=nativeMenu}
                snapshot["selfChildEdges"] = selfChildEdges
                snapshot["duplicateChildEdges"] = duplicateChildEdges
                if let windowScope { snapshot["windowScope"] = windowScope.metadata }
                if method == "windows.list" { snapshot["windowRootsOnly"] = true }
                reply["result"] = snapshot
            case "elements.pressKey", "elements.pressSessionKey", "input.key", "input.text", "input.pointer":
                guard AXIsProcessTrusted() else { throw NativeFailure("permissionDenied", "Accessibility permission absent") }
                if let refID = params["elementRef"] as? String, let ref = refs[refID], applicationProcessStartToken(ref.pid) != ref.startToken { throw NativeFailure("staleReference", "Target process fingerprint changed") }
                guard let refID = params["elementRef"] as? String, let ref = refs[refID], ref.generation == generation,
                      params["generation"] as? Int == generation, params["expectedApp"] as? String == ref.bundleID,
                      DispatchTime.now().uptimeNanoseconds - ref.observedAt < 5_000_000_000,
                      let app = NSRunningApplication(processIdentifier: ref.pid), app.bundleIdentifier == ref.bundleID, applicationProcessStartToken(ref.pid) == ref.startToken else { throw NativeFailure("staleFocus", "Exact target, launch, observation and foreground app are required") }
                try freshTargetedForeground(ref,budget)
                AXUIElementSetMessagingTimeout(ref.element, min(0.2, budget.remainingSeconds))
                if method != "input.pointer", attribute(ref.element, kAXFocusedAttribute) as? Bool != true { throw NativeFailure("staleFocus", "Keyboard target is not focused") }
                if attribute(ref.element, kAXSubroleAttribute) as? String == kAXSecureTextFieldSubrole { throw NativeFailure("secureInput", "Secure target input is not supported") }
                try budget.check(); try ref.validateInputScope(budget); try reserveMutation()
                var inputAttempted = false
                do {
                    if method == "elements.pressKey" || method == "elements.pressSessionKey" {
                        guard Set(params.keys) == Set(["elementRef", "generation", "expectedApp", "key"]), let raw = params["key"] as? String else { throw NativeFailure("invalidKey", "Exact typed chord parameters required") }
                        let chord = try TargetedKeyChord(raw)
                        var typed = params
                        let resolvedKeyCode = try targetedKeyCode(chord.key)
                        typed["keyCode"] = resolvedKeyCode
                        typed["modifiers"] = chord.modifiers.map { $0.lowercased() }
                        let delivery:KeyboardDelivery = method == "elements.pressSessionKey" ? .session:.process
                        if delivery == .session {try validateSessionKeyboardWindow(ref,budget)}
                        try await dispatchInput("input.key", typed, ref, budget, delivery:delivery,preflight: {
                            guard (delivery == .session ? self.sessionKeyboardEnabled:self.targetedKeyboardEnabled), self.watchdog?.live() == true, let current = self.lease, let persisted = self.fenceLease(), persisted["id"] as? String == current.0, persisted["generation"] as? Int == current.1, let currentScope = persisted["scope"] as? [String:Any], fenceScopeAllows(currentScope,ref.bundleID) else { throw NativeFailure("staleLease", "Targeted keyboard lease revoked") }
                            try budget.check()
                            guard try targetedKeyCode(chord.key) == resolvedKeyCode else { throw NativeFailure("keyboardLayoutChanged", "Named key mapping changed before dispatch") }
                            try validateTargetedFocus(ref,budget)
                            if delivery == .session {try validateSessionKeyboardWindow(ref,budget)}
                        }, willPost: { inputAttempted = true;startRequestBadge() })
                    } else { try await dispatchInput(method, params, ref, budget, preflight:{try foregroundRevalidate?()}, willPost: { inputAttempted = true;startRequestBadge() }) }
                    reply["receipt"] = ["dispatchState": "dispatched", "startedAt": started, "returnedAt": iso.string(from: Date()), "targetRef": refID, "businessSuccess": false]
                } catch {
                    let failure = error as? NativeFailure ?? NativeFailure("inputDispatchUnknown", "Input dispatch failed")
                    let state = inputAttempted ? "unknown" : "notDispatched"
                    reply["receipt"] = ["dispatchState": state, "startedAt": started, "returnedAt": iso.string(from: Date()), "targetRef": refID, "businessSuccess": false]
                    reply["error"] = ["code": failure.code, "message": failure.message, "stage": "native", "retryableRead": false, "dispatchState": state]
                    _ = inputs.inhibitAndRelease(); lease = nil
                }
                refs.removeAll(); generation += 1
            case "elements.read":
                guard AXIsProcessTrusted() else { throw NativeFailure("permissionDenied", "Accessibility permission absent") }
                if let refID = params["elementRef"] as? String, let ref = refs[refID], applicationProcessStartToken(ref.pid) != ref.startToken { throw NativeFailure("staleReference", "Target process fingerprint changed") }
                guard let refID = params["elementRef"] as? String, let ref = refs[refID], ref.generation == generation,
                      params["generation"] as? Int == generation, params["expectedApp"] as? String == ref.bundleID,
                      DispatchTime.now().uptimeNanoseconds - ref.observedAt < 5_000_000_000,
                      let app = NSRunningApplication(processIdentifier: ref.pid), app.bundleIdentifier == ref.bundleID, applicationProcessStartToken(ref.pid) == ref.startToken else { throw NativeFailure("staleReference", "Target identity or generation changed") }
                guard let attributes = params["attributes"] as? [String], !attributes.isEmpty, attributes.count <= 5 else { throw NativeFailure("invalidAttribute", "Bounded explicit read attributes required") }
                try ref.validateInputScope(budget)
                startRequestBadge()
                AXUIElementSetMessagingTimeout(ref.element, min(0.2, budget.remainingSeconds))
                var values: [String: Any] = [:]; var unavailable: [String] = []
                defer {if attributes.contains("focused") {logKeyboardRoutingDiagnostic(requestID:id,ref:ref,budget:budget)}}
                for name in attributes {
                    try budget.check()
                    let native: String
                    switch name {
                    case "role": native = kAXRoleAttribute
                    case "name":
                        let (status, value) = accessibleName(ref.element)
                        guard status == .success, let text = value as? String, text.utf8.count <= 65_536 else {
                            throw NativeFailure("attributeUnavailable", "Accessible name unavailable")
                        }
                        try ref.validateInputScope(budget)
                        values[name] = text
                        continue
                    case "identifier": native = kAXIdentifierAttribute
                    case "enabled": native = kAXEnabledAttribute
                    case "checked":
                        func readStateAttribute(_ attributeName: String) -> (AXError, Any?) {
                            var raw: CFTypeRef?
                            let status = AXUIElementCopyAttributeValue(ref.element, attributeName as CFString, &raw)
                            return (status, raw)
                        }
                        values[name] = try readCheckedState(role: attribute(ref.element, kAXRoleAttribute) as? String,
                            value: { readStateAttribute(kAXValueAttribute) }, selected: { readStateAttribute(kAXSelectedAttribute) })
                        try ref.validateInputScope(budget)
                        continue
                    case "focused":
                        do {values[name]=try observedTargetedFocus(ref,budget)} catch let failure as NativeFailure {
                            let diagnostics=focusFailureDiagnostics(ref,budget)
                            throw NativeFailure(failure.code,failure.message+"; "+diagnostics)
                        }
                        try budget.check();try ref.validateInputScope(budget)
                        continue
                    case "staticText":
                        var subroleValue: CFTypeRef?
                        let subroleCode = AXUIElementCopyAttributeValue(ref.element, kAXSubroleAttribute as CFString, &subroleValue)
                        let subroleKnown = (subroleCode == .success && subroleValue is String) || subroleCode == .noValue || subroleCode == .attributeUnsupported
                        var settable: DarwinBoolean = false
                        let settableCode = AXUIElementIsAttributeSettable(ref.element, kAXValueAttribute as CFString, &settable)
                        try StaticTextRead.authorize(allowed: params["allowStaticTextRead"] as? Bool == true,
                            role: attribute(ref.element, kAXRoleAttribute) as? String,
                            subrole: subroleValue as? String, subroleKnown: subroleKnown,
                            valueSettable: settableCode == .success ? settable.boolValue : nil)
                        values[name] = try StaticTextRead.bounded(attribute(ref.element, kAXValueAttribute) as? String)
                        continue
                    case "value":
                        var subroleValue: CFTypeRef?
                        let subroleCode = AXUIElementCopyAttributeValue(ref.element, kAXSubroleAttribute as CFString, &subroleValue)
                        let subroleKnown = (subroleCode == .success && subroleValue is String) ||
                            ((subroleCode == .noValue || subroleCode == .attributeUnsupported) && subroleValue == nil)
                        guard TextValueRead.permitted(allowed: params["allowValueRead"] as? Bool == true,
                            expectedIdentifier: params["expectedIdentifier"] as? String,
                            identifier: attribute(ref.element, kAXIdentifierAttribute) as? String,
                            role: attribute(ref.element, kAXRoleAttribute) as? String,
                            subrole: subroleValue as? String, subroleKnown: subroleKnown) else {
                            throw NativeFailure("valueReadDenied", "Value requires explicit nonsecure text field identifier policy")
                        }
                        values[name] = try readNativeTextValue(ref.element) { try ref.validateInputScope(budget) }
                        continue
                    default: throw NativeFailure("unsupportedAttribute", "Read attribute not supported")
                    }
                    if name == "enabled", let value = attribute(ref.element, native) as? Bool { values[name] = value }
                    else if let value = attribute(ref.element, native) as? String, value.utf8.count <= 65_536 { values[name] = value }
                    else { unavailable.append(name) }
                }
                try ref.validateInputScope(budget)
                reply["result"] = ["values": values, "unavailable": unavailable, "generation": generation, "returnedAt": iso.string(from: Date())]
            case "windows.typeText":
                let outcome = try typeWindowText(params, budget: budget,present:{startRequestBadge()}) { try budget.check(); try reserveMutation() }
                var result = outcome.result
                result["requestId"] = id; result["observedAt"] = preciseISO.string(from: Date())
                reply["result"] = result
                reply["receipt"] = ["dispatchState": outcome.dispatchState, "startedAt": started,
                    "returnedAt": iso.string(from: Date()), "targetRef": "window:\(params["windowId"]!)", "businessSuccess": false]
                if let failure = outcome.failure {
                    reply["error"] = ["code": failure.code, "message": failure.message, "stage": "native",
                                      "dispatchState": outcome.dispatchState, "retryableRead": false]
                }
                refs.removeAll(); generation += 1
            case "windows.pressSessionKey":
                guard Set(params.keys) == Set(["expectedApp", "pid", "processStartToken", "windowId", "key"]),
                      let bundle = params["expectedApp"] as? String, concreteApplicationBundle(bundle),
                      let birth = params["processStartToken"] as? String, validApplicationProcessStartToken(birth),
                      let key = params["key"] as? String else { throw NativeFailure("invalidScope", "Exact process, physical window and named chord required") }
                let rawPID = try RecordingConsentLease.integer(params["pid"], maximum: UInt64(Int32.max))
                let rawWindowID = try RecordingConsentLease.integer(params["windowId"], maximum: UInt64(UInt32.max))
                guard rawPID > 0, rawWindowID > 0 else { throw NativeFailure("invalidScope", "Positive process and window identities required") }
                let pid = Int32(rawPID), windowID = UInt32(rawWindowID)
                let chord = try TargetedKeyChord(key)
                let keyCode = try targetedKeyCode(chord.key)
                var namedEvents: (CGEvent, CGEvent)?
                let validate = {
                    try qualifyWindowSessionKey(pid: pid, uid: getuid(), birth: birth, bundle: bundle, windowID: windowID, check: { try budget.check() })
                    guard self.sessionKeyboardEnabled, self.watchdog?.live() == true, let held = self.lease, let persisted = self.fenceLease(),
                          persisted["id"] as? String == held.0, persisted["generation"] as? Int == held.1, let scope = persisted["scope"] as? [String: Any], fenceScopeAllows(scope, bundle) else { throw NativeFailure("staleLease", "Explicit session-window keyboard authority changed") }
                    guard try targetedKeyCode(chord.key) == keyCode else { throw NativeFailure("keyboardLayoutChanged", "Named chord mapping changed") }
                    if let events = namedEvents { try validateNamedWindowKeyText(events.0, key: chord.key, keyCode: keyCode, modifiers: chord.modifiers) }
                    try budget.check()
                }
                try validate()
                let (down, up) = try namedWindowKeyEvents(key: chord.key, keyCode: keyCode, modifiers: chord.modifiers)
                namedEvents = (down, up)
                try reserveMutation()
                var attempted = false
                do {
                    try KeyboardPosting.press(inputs: inputs, token: "key:\(keyCode)", delivery: .session, preflight: validate,
                        down: { _ in attempted = true;startRequestBadge(); down.post(tap: .cgSessionEventTap); return true },
                        up: { _ in guard sessionKeyReleaseAllowed() else { return false }; up.post(tap: .cgSessionEventTap); return true })
                    reply["result"] = ["pid": pid, "startToken": birth, "bundleID": bundle, "windowId": windowID, "identity": "window:\(windowID)", "key": key, "requestId": id, "observedAt": preciseISO.string(from: Date()), "businessSuccess": false]
                    reply["receipt"] = ["dispatchState": "dispatched", "startedAt": started, "returnedAt": iso.string(from: Date()), "targetRef": "window:\(windowID)", "businessSuccess": false]
                } catch {
                    let failure = error as? NativeFailure ?? NativeFailure("windowKeyboardUnknown", "Session chord outcome unknown")
                    let state = attempted ? "unknown" : "notDispatched"
                    reply["error"] = ["code": failure.code, "message": failure.message, "stage": "native", "dispatchState": state, "retryableRead": false]
                    reply["receipt"] = ["dispatchState": state, "targetRef": "window:\(windowID)", "startedAt": started, "returnedAt": iso.string(from: Date()), "businessSuccess": false]
                    _ = inputs.inhibitAndRelease(); lease = nil
                }
                refs.removeAll(); generation += 1
            case "elements.valueMatches", "elements.replaceText":
                guard AXIsProcessTrusted() else { throw NativeFailure("permissionDenied", "Accessibility permission absent") }
                let replace = method == "elements.replaceText"
                let keys: Set<String> = replace ? Set(["elementRef", "generation", "expectedApp", "value", "verifyReplacement"]) : Set(["elementRef", "generation", "expectedApp", "expected"])
                guard Set(params.keys).isSubset(of: keys), Set(["elementRef", "generation", "expectedApp", replace ? "value" : "expected"]).isSubset(of: Set(params.keys)),
                      let refID = params["elementRef"] as? String, let ref = refs[refID], ref.generation == generation,
                      params["generation"] as? Int == generation, params["expectedApp"] as? String == ref.bundleID,
                      DispatchTime.now().uptimeNanoseconds - ref.observedAt < 5_000_000_000 else { throw NativeFailure("staleReference", "Fresh exact text reference required") }
                let expected = try boundedTextLiteral(params[replace ? "value" : "expected"])
                if let raw = params["verifyReplacement"] { guard CFGetTypeID(raw as CFTypeRef) == CFBooleanGetTypeID() else { throw NativeFailure("invalidValue", "Literal verification flag must be boolean") } }
                AXUIElementSetMessagingTimeout(ref.element, min(0.1, budget.remainingSeconds))
                let validate = {
                    try budget.check(); try ref.validateInputScope(budget)
                    let owner = inspectAXElementOwner(ref.element)
                    guard owner.status == AXError.success.rawValue, owner.pid == ref.pid, owner.uid == getuid(), owner.birth == ref.startToken, owner.bundle == ref.bundleID else {
                        throw NativeFailure("staleReference", "Text target must remain owned by the exact application process")
                    }
                    try budget.check()
                    if replace {
                        guard self.semanticEnabled || self.mutationsEnabled, self.watchdog?.live() == true, let held = self.lease,
                              let persisted = self.fenceLease(), persisted["id"] as? String == held.0, persisted["generation"] as? Int == held.1,
                              let scope = persisted["scope"] as? [String: Any], fenceScopeAllows(scope, ref.bundleID) else { throw NativeFailure("staleLease", "Text replacement authority changed") }
                    }
                }
                var result: [String: Any] = ["pid": ref.pid, "startToken": ref.startToken, "bundleID": ref.bundleID, "targetRef": refID, "generation": ref.generation, "requestId": id]
                if replace {
                    let outcome = try replaceNativeText(ref.element, expected: expected, verify: params["verifyReplacement"] as? Bool == true,
                        revalidate: validate, willMutate: { try budget.check(); try reserveMutation() })
                    if outcome.matches == true { result["replacementMatches"] = true }
                    result["observedAt"] = iso.string(from: Date())
                    reply["result"] = result
                    reply["receipt"] = ["dispatchState": outcome.dispatchState, "startedAt": started, "returnedAt": iso.string(from: Date()), "targetRef": refID, "nativeCode": outcome.nativeCode, "businessSuccess": false]
                    if let failure = outcome.failure { reply["error"] = ["code": failure.code, "message": failure.message, "stage": "native", "dispatchState": "unknown", "retryableRead": false] }
                    refs.removeAll(); generation += 1
                } else {
                    try validate()
                    startRequestBadge()
                    result["matches"] = try nativeValueMatches(ref.element, expected: expected, revalidate: validate)
                    result["observedAt"] = iso.string(from: Date()); reply["result"] = result
                }
            case "windows.setPosition":
                guard AXIsProcessTrusted() else { throw NativeFailure("permissionDenied", "Accessibility permission absent") }
                guard Set(params.keys) == Set(["elementRef", "generation", "expectedApp", "position"]),
                      let refID = params["elementRef"] as? String, let ref = refs[refID], ref.generation == generation,
                      params["generation"] as? Int == generation, params["expectedApp"] as? String == ref.bundleID,
                      DispatchTime.now().uptimeNanoseconds - ref.observedAt < 5_000_000_000 else {
                    throw NativeFailure("staleReference", "Window position requires an exact fresh reference and generation")
                }
                let position = try NativeWindowPosition(params["position"])
                let application = AXUIElementCreateApplication(ref.pid)
                AXUIElementSetMessagingTimeout(application, min(0.1, budget.remainingSeconds))
                AXUIElementSetMessagingTimeout(ref.element, min(0.1, budget.remainingSeconds))
                let outcome = try positionExactNativeWindow(ref.element, application: application, pid: ref.pid, uid: getuid(), birth: ref.startToken, bundle: ref.bundleID,
                    position: position, revalidate: {
                        try budget.check(); try ref.validateInputScope(budget)
                        guard self.semanticEnabled || self.mutationsEnabled, self.watchdog?.live() == true, let held = self.lease,
                              let persisted = self.fenceLease(), persisted["id"] as? String == held.0, persisted["generation"] as? Int == held.1,
                              let scope = persisted["scope"] as? [String: Any], fenceScopeAllows(scope, ref.bundleID) else {
                            throw NativeFailure("staleLease", "Window position authority changed")
                        }
                    }, willSet: { try budget.check(); try reserveMutation() })
                var result: [String: Any] = ["positionVerified": outcome.verified, "pid": ref.pid, "startToken": ref.startToken,
                    "bundleID": ref.bundleID, "targetRef": refID, "generation": ref.generation, "requestId": id, "observedAt": iso.string(from: Date())]
                if let actual = outcome.positionFields(requested: position) { result["position"] = actual }
                if outcome.verified,let badge=controlBadge,let bounds=AutomationPointer.windowBounds(element:ref.element,pid:ref.pid) {AutomationPointer.repositionControl(badge,window:bounds)}
                reply["result"] = result
                reply["receipt"] = ["dispatchState": outcome.dispatchState, "startedAt": started, "returnedAt": iso.string(from: Date()), "targetRef": refID, "nativeCode": outcome.nativeCode, "businessSuccess": false]
                if let failure = outcome.failure { reply["error"] = ["code": failure.code, "message": failure.message, "stage": "native", "dispatchState": "unknown", "retryableRead": false] }
                refs.removeAll(); generation += 1
            case "elements.focus", "elements.press", "elements.showMenu", "elements.setValue", "elements.submit":
                guard AXIsProcessTrusted() else { throw NativeFailure("permissionDenied", "Accessibility permission absent") }
                if let refID = params["elementRef"] as? String, let ref = refs[refID], applicationProcessStartToken(ref.pid) != ref.startToken { throw NativeFailure("staleReference", "Target process fingerprint changed") }
                guard let refID = params["elementRef"] as? String, let ref = refs[refID], ref.generation == generation, DispatchTime.now().uptimeNanoseconds - ref.observedAt < 5_000_000_000, params["generation"] as? Int == generation,
                      params["expectedApp"] as? String == ref.bundleID,
                      let app = NSRunningApplication(processIdentifier: ref.pid), app.bundleIdentifier == ref.bundleID, applicationProcessStartToken(ref.pid) == ref.startToken else { throw NativeFailure("staleReference", "Target identity or observation generation changed") }
                AXUIElementSetMessagingTimeout(ref.element, min(0.2, budget.remainingSeconds))
                guard attribute(ref.element, kAXEnabledAttribute) as? Bool != false, attribute(ref.element, kAXSubroleAttribute) as? String != kAXSecureTextFieldSubrole else { throw NativeFailure("targetNotActionable", "Disabled or secure target cannot be mutated") }
                let code: AXError
                if method == "elements.focus" {
                    guard Set(params.keys) == Set(["elementRef", "generation", "expectedApp"]) else { throw NativeFailure("staleFocus", "Explicit focus requires exact typed target") }
                    try freshTargetedForeground(ref,budget)
                    var settable: DarwinBoolean = false
                    guard AXUIElementIsAttributeSettable(ref.element, kAXFocusedAttribute as CFString, &settable) == .success, settable.boolValue else { throw NativeFailure("focusUnsupported", "Target does not independently support setting AXFocused") }
                    try budget.check(); try ref.validateInputScope(budget); try reserveMutation()
                    code = AXUIElementSetAttributeValue(ref.element, kAXFocusedAttribute as CFString, kCFBooleanTrue)
                    if code == .success { do { try settleTargetedFocus(ref,budget) } catch {
                        reply["receipt"] = ["dispatchState": "unknown", "startedAt": started, "returnedAt": iso.string(from: Date()), "targetRef": refID, "businessSuccess": false]
                        let detail=error as? NativeFailure
                        reply["error"] = ["code":"focusUnconfirmed", "message":"Focus write returned; observational verification failed: \(detail?.code ?? "focusProbeFailed"). \(detail?.message ?? "Exact focus proof unavailable")", "reasonCode":detail?.code ?? "focusProbeFailed", "dispatchState":"unknown", "stage":"native"]
                        refs.removeAll(); generation += 1; ledger.finish(id, reply:reply); return reply
                    } }
                } else if method == "elements.press" || method == "elements.submit" || method == "elements.showMenu" {
                    var actions: CFArray?
                    guard AXUIElementCopyActionNames(ref.element, &actions) == .success,
                          let advertised = actions as? [String] else {
                        throw NativeFailure("unsupported", "Exact semantic action metadata unavailable")
                    }
                    let role = attribute(ref.element, kAXRoleAttribute) as? String ?? ""
                    if method == "elements.showMenu" {
                        guard Set(params.keys) == Set(["elementRef", "generation", "expectedApp"]),
                              let enabled = attribute(ref.element, kAXEnabledAttribute), CFGetTypeID(enabled) == CFBooleanGetTypeID(), enabled as? Bool == true else {
                            throw NativeFailure("menuUnqualified", "Exact enabled menu control required")
                        }
                    }
                    let action = try qualifiedSemanticAXAction(method: method, role: role, advertised: advertised)
                    let cuePoint = AutomationPointer.center(of:ref.element)
                    code = try dispatchSemanticAXAction(ref.element, action: action, budget: budget,
                        revalidate: { try ref.validateInputScope(budget) }, reserve: reserveMutation)
                    if let cuePoint {AutomationPointer.show(at:cuePoint)}
                } else {
                    guard let value = params["value"] as? String, value.utf8.count <= 65_536 else { throw NativeFailure("invalidValue", "Value must be a bounded string") }
                    var settable: DarwinBoolean = false
                    guard AXUIElementIsAttributeSettable(ref.element, kAXValueAttribute as CFString, &settable) == .success, settable.boolValue else { throw NativeFailure("unsupported", "Target value is not settable") }
                    try budget.check(); try ref.validateInputScope(budget); try reserveMutation()
                    var setterCode:AXError = .failure
                    let permitted = params["verifyReplacement"] as? Bool == true && replacementClassification(ref)
                    let matched = try ReplacementProof.perform(expected:value,permitted:permitted,set:{
                        try budget.check();try ref.validateInputScope(budget)
                        guard self.semanticEnabled || self.mutationsEnabled, self.watchdog?.live() == true, let held=self.lease, let persisted=self.fenceLease(), persisted["id"] as? String == held.0, persisted["generation"] as? Int == held.1, let scope=persisted["scope"] as? [String:Any], fenceScopeAllows(scope,ref.bundleID) else {throw NativeFailure("staleLease","Replacement write authority changed")}
                        startRequestBadge()
                        setterCode=AXUIElementSetAttributeValue(ref.element,kAXValueAttribute as CFString,value as CFString)
                        return setterCode == .success
                    },read:{
                        var observed:CFTypeRef?
                        guard AXUIElementCopyAttributeValue(ref.element,kAXValueAttribute as CFString,&observed) == .success else {return nil}
                        return observed as? String
                    },revalidate:{
                        try budget.check();try ref.validateInputScope(budget)
                        guard replacementClassification(ref) else {throw NativeFailure("replacementUnconfirmed","Text field classification changed")}
                        try budget.check()
                        guard ref.generation == self.generation, self.semanticEnabled || self.mutationsEnabled, self.watchdog?.live() == true,
                              let held=self.lease, let persisted=self.fenceLease(), persisted["id"] as? String == held.0, persisted["generation"] as? Int == held.1,
                              let currentScope=persisted["scope"] as? [String:Any],fenceScopeAllows(currentScope,ref.bundleID) else {throw NativeFailure("staleLease","Replacement observation authority changed")}
                    })
                    code=setterCode
                    if matched == true {
                        reply["result"] = ["replacementMatches":true,"pid":ref.pid,"startToken":ref.startToken,"bundleID":ref.bundleID,"targetRef":refID,"generation":ref.generation,"requestId":id,"observedAt":iso.string(from:Date())]
                    }
                }
                if method == "elements.focus", code == .success {
                    reply["result"] = ["focused":true,"pid":ref.pid,"startToken":ref.startToken,"bundleID":ref.bundleID,"targetRef":refID,"generation":ref.generation]
                }
                reply["receipt"] = ["dispatchState": code == .success ? "dispatched" : "unknown", "startedAt": started, "returnedAt": iso.string(from: Date()), "nativeCode": code.rawValue, "targetRef": params["elementRef"] ?? "", "businessSuccess": false]
                if code != .success { reply["error"] = ["code": "nativeActionFailed", "message": "AX action returned error \(code.rawValue); outcome requires observation", "stage": "native", "retryableRead": false, "dispatchState": "unknown"] }
                refs.removeAll(); generation += 1
            case "windows.captureFrame":
                reply["result"] = try await captureWindowFrame(request, params, budget)
            case "windows.clickFrame":
                let (permit, point) = try await prepareWindowFrameClick(request, params, budget, acquire:{target in try acquire(target)})
                try budget.check(); try reserveMutation()
                var attempted = false
                do {
                    try postWindowFrameClick(inputs: inputs, point: point, preflight: { try self.validateWindowFrameClick(request, permit, point, budget) }, willPost: { attempted = true; controlBadge = AutomationPointer.beginOwnedControl(pid:permit.pid,birth:permit.processStartToken,bundle:permit.bundleId,window:permit.bounds,windowID:permit.windowId,sessionToken:presentationSession,actionDeadline:badgeActionDeadline); AutomationPointer.show(at: point) })
                    AutomationPointer.show(at:point)
                    reply["result"] = ["permitId": permit.id, "owner": permit.owner.metadata, "pid": permit.pid, "startToken": permit.processStartToken, "bundleID": permit.bundleId, "windowId": permit.windowId, "identity": "window:\(permit.windowId)", "point": ["x": params["x"]!, "y": params["y"]!], "requestId": id, "observedAt": preciseISO.string(from: Date()), "businessSuccess": false]
                    reply["receipt"] = ["dispatchState": "dispatched", "startedAt": started, "returnedAt": iso.string(from: Date()), "targetRef": "window:\(permit.windowId)", "businessSuccess": false]
                } catch {
                    AutomationPointer.hide()
                    let failure = error as? NativeFailure ?? NativeFailure("windowClickUnknown", "Window click outcome unknown")
                    let state = attempted ? "unknown" : "notDispatched"
                    reply["error"] = ["code": failure.code, "message": failure.message, "stage": "native", "dispatchState": state, "retryableRead": false]
                    reply["receipt"] = ["dispatchState": state, "targetRef": "window:\(permit.windowId)", "startedAt": started, "returnedAt": iso.string(from: Date()), "businessSuccess": false]
                    _ = inputs.inhibitAndRelease(); lease = nil
                }
                refs.removeAll(); generation += 1
            case "capture.windows":
                reply["result"] = try await captureWindows(params, budget)
            case "capture.image":
                guard params["captureNonce"] as? String == id else { throw NativeFailure("invalidRequest", "Capture correlation must match request identity") }
                reply["result"] = try await capture(params, budget)
            default: throw NativeFailure("unsupported", "Method is not implemented")
            }
        } catch {
            if mutation { AutomationPointer.hide() }
            if method == "windows.clickFrame" || method == "windows.captureFrame" { clearWindowFrame() }
            let failure = error as? NativeFailure ?? NativeFailure("nativeFailure", "Native operation failed")
            reply["error"] = ["code": failure.code, "message": failure.message, "stage": "native", "retryableRead": !mutation, "dispatchState": "notDispatched"]
            if mutation { reply["receipt"] = ["dispatchState": "notDispatched", "startedAt": started, "returnedAt": iso.string(from: Date())] }
        }
        if reserved { ledger.finish(id, reply: reply) }
        return reply
    }
    func fenceLease() -> [String: Any]? {
        var descriptor = stat()
        guard fstat(5, &descriptor) == 0, descriptor.st_mode & S_IFMT == S_IFREG, descriptor.st_uid == getuid(), descriptor.st_size > 0, descriptor.st_size <= 65_536 else { return nil }
        var bytes = [UInt8](repeating: 0, count: Int(descriptor.st_size))
        let count = bytes.withUnsafeMutableBytes { pread(5, $0.baseAddress, $0.count, 0) }
        guard count == bytes.count, let record = try? JSONSerialization.jsonObject(with: Data(bytes)) as? [String: Any] else { return nil }
        guard let helper = record["helper"] as? [String: Any], helper["pid"] as? Int32 == getpid(), helper["uid"] as? UInt32 == getuid(), let start = helper["startToken"] as? String, !start.isEmpty else { return nil }
        return record["lease"] as? [String: Any]
    }
    func dispatchInput(_ method: String, _ params: [String: Any], _ ref: Reference, _ budget: Budget, delivery:KeyboardDelivery = .process,preflight: () throws -> Void = {}, willPost: () -> Void) async throws {
        let marker: Int64 = 0x4d454348
        try ref.validateInputScope(budget)
        guard !IsSecureEventInputEnabled() else { throw NativeFailure("secureInput", "Secure event input inhibits synthetic input") }
        guard CGPreflightPostEventAccess() else { throw NativeFailure("permissionDenied", "Event posting permission absent") }
        if method == "input.pointer" {
            guard let x = params["x"] as? Double, let y = params["y"] as? Double, x.isFinite, y.isFinite,
                  let displayID = params["displayID"] as? UInt32, CGDisplayIsActive(displayID) != 0,
                  let rawPosition = attribute(ref.element, kAXPositionAttribute), CFGetTypeID(rawPosition) == AXValueGetTypeID(),
                  let rawSize = attribute(ref.element, kAXSizeAttribute), CFGetTypeID(rawSize) == AXValueGetTypeID() else { throw NativeFailure("invalidCoordinates", "Explicit active display and current AX bounds required") }
            var origin = CGPoint.zero; var size = CGSize.zero
            guard AXValueGetValue(rawPosition as! AXValue, .cgPoint, &origin), AXValueGetValue(rawSize as! AXValue, .cgSize, &size) else { throw NativeFailure("invalidCoordinates", "AX bounds unavailable") }
            let point = CGPoint(x: x, y: y)
            guard CGDisplayBounds(displayID).contains(point), CGRect(origin: origin, size: size).contains(point), params["button"] as? String == "left" else { throw NativeFailure("invalidCoordinates", "Only scoped left click within current element and display is supported") }
            guard let down = CGEvent(mouseEventSource: nil, mouseType: .leftMouseDown, mouseCursorPosition: point, mouseButton: .left), let up = CGEvent(mouseEventSource: nil, mouseType: .leftMouseUp, mouseCursorPosition: point, mouseButton: .left) else { throw NativeFailure("eventUnavailable", "Mouse events could not be constructed") }
            down.setIntegerValueField(.eventSourceUserData, value: marker); up.setIntegerValueField(.eventSourceUserData, value: marker)
            try budget.check(); try ref.validateInputScope(budget)
            try inputs.press(token: "mouse:left", preflight:{try preflight();try ref.validateInputScope(budget);try budget.check()}, down: { willPost(); down.post(tap: .cghidEventTap); return true }, up: { up.post(tap: .cghidEventTap); return true })
            AutomationPointer.show(at:point)
            return
        }
        guard CGPreflightPostEventAccess() else { throw NativeFailure("permissionDenied", "Event posting permission absent") }
        let key: CGKeyCode
        var text: [UniChar] = []
        if method == "input.text" {
            guard let value = params["text"] as? String, value.utf16.count <= 1024, !value.isEmpty else { throw NativeFailure("invalidValue", "Unicode input requires 1...1024 UTF16 units") }
            text = Array(value.utf16); key = 0
        } else {
            guard let code = params["keyCode"] as? UInt16, code <= 127 else { throw NativeFailure("invalidKey", "Explicit supported virtual key code required") }; key = code
        }
        guard let down = CGEvent(keyboardEventSource: nil, virtualKey: key, keyDown: true), let up = CGEvent(keyboardEventSource: nil, virtualKey: key, keyDown: false) else { throw NativeFailure("eventUnavailable", "Keyboard events could not be constructed") }
        var flags: CGEventFlags = []
        for modifier in params["modifiers"] as? [String] ?? [] {
            switch modifier { case "command": flags.insert(.maskCommand); case "shift": flags.insert(.maskShift); case "option": flags.insert(.maskAlternate); case "control": flags.insert(.maskControl); default: throw NativeFailure("invalidModifier", "Modifier is not supported") }
        }
        down.flags = flags; up.flags = []
        if !text.isEmpty { text.withUnsafeBufferPointer { down.keyboardSetUnicodeString(stringLength: $0.count, unicodeString: $0.baseAddress!); up.keyboardSetUnicodeString(stringLength: $0.count, unicodeString: $0.baseAddress!) } }
        down.setIntegerValueField(.eventSourceUserData, value: marker); up.setIntegerValueField(.eventSourceUserData, value: marker)
        try budget.check()
        try KeyboardPosting.press(inputs:inputs,token:"key:\(key)",delivery:delivery,preflight:{try preflight();try ref.validateInputScope(budget);try budget.check();guard !IsSecureEventInputEnabled(),CGPreflightPostEventAccess() else {throw NativeFailure("inputInhibited","Input permission or secure state changed")}},down:{route in
            willPost()
            switch route {case .process:down.postToPid(ref.pid);case .session:down.post(tap:.cgSessionEventTap)}
            return true
        },up:{route in
            // Root changes inhibit down events; cleanup key releases still use
            // the exact original process birth, without acquiring new authority.
            switch route {
            case .process:do {try ref.validateProcess();guard CGPreflightPostEventAccess() else{return false};up.postToPid(ref.pid);return true}catch{return false}
            case .session:guard sessionKeyReleaseAllowed() else{return false};up.post(tap:.cgSessionEventTap);return true
            }
        })
    }
    func displays() -> [[String: Any]] {
        var ids = [CGDirectDisplayID](repeating: 0, count: 32); var count: UInt32 = 0
        guard CGGetActiveDisplayList(32, &ids, &count) == .success else { return [] }
        return ids.prefix(Int(count)).map { id in
            let rect = CGDisplayBounds(id)
            return ["displayID": id, "x": rect.minX, "y": rect.minY, "widthPoints": rect.width, "heightPoints": rect.height, "widthPixels": CGDisplayPixelsWide(id), "heightPixels": CGDisplayPixelsHigh(id)]
        }
    }
    func windows(_ root: AXUIElement, pid: pid_t, uid: uid_t, birth: String, bundle: String, check: () throws -> Void) throws -> [AXUIElement] {
        try OwnedAXWindows.enumerate(application: root, pid: pid, uid: uid, birth: birth, bundle: bundle, check: check)
    }
    func attribute(_ element: AXUIElement, _ name: String) -> AnyObject? {
        var value: CFTypeRef?; return AXUIElementCopyAttributeValue(element, name as CFString, &value) == .success ? value : nil
    }
    func scopedApp(_ params: [String: Any], _ budget: Budget) throws -> (NSRunningApplication, AXUIElement) {
        guard AXIsProcessTrusted() else { throw NativeFailure("permissionDenied", "Accessibility permission absent") }
        if let token = params["processStartToken"] {
            guard let pid = params["pid"] as? Int32, let expected = token as? String, validApplicationProcessStartToken(expected), applicationProcessStartToken(pid) == expected else { throw NativeFailure("staleReference", "Exact process fingerprint changed") }
        }
        guard let pid = params["pid"] as? Int32, let bundle = params["bundleID"] as? String, let app = NSRunningApplication(processIdentifier: pid), app.bundleIdentifier == bundle, concreteApplicationBundle(bundle), applicationProcessStartToken(pid) != nil else { throw NativeFailure("invalidScope", "Exact live PID, bundleID and current login user ownership are required") }
        let root = AXUIElementCreateApplication(pid)
        AXUIElementSetMessagingTimeout(root, min(0.5, budget.remainingSeconds))
        return (app, root)
    }
    func captureWindows(_ params: [String: Any], _ budget: Budget) async throws -> [String: Any] {
        guard let bundleID = params["bundleId"] as? String, !bundleID.isEmpty, bundleID.utf8.count <= 512,
              let limit = params["limit"] as? Int, limit > 0, limit <= 128 else {
            throw NativeFailure("invalidScope", "Window discovery requires one exact application and bounded limit")
        }
        let narrowedPID = params["processId"] as? Int32
        let narrowedToken = params["processStartToken"] as? String
        if params["processId"] != nil || params["processStartToken"] != nil {
            guard let pid = narrowedPID, pid > 0, let token = narrowedToken, validApplicationProcessStartToken(token), applicationProcessStartToken(pid) == token, NSRunningApplication(processIdentifier: pid)?.bundleIdentifier == bundleID else { throw NativeFailure("staleReference", "Discovery process fingerprint changed") }
        }
        guard CGPreflightScreenCaptureAccess() else { throw NativeFailure("permissionDenied", "Screen capture permission absent") }
        let content = try await SCShareableContent.excludingDesktopWindows(true, onScreenWindowsOnly: true)
        try budget.check()
        // SCK discovery enumerates internally; return no displays or foreign app facts.
        let scoped = content.windows.filter { window in window.owningApplication?.bundleIdentifier == bundleID && (narrowedPID == nil || window.owningApplication?.processID == narrowedPID) && window.owningApplication.map { applicationProcessStartToken($0.processID) != nil } == true && window.frame.width > 0 && window.frame.height > 0 }.sorted { $0.windowID < $1.windowID }
        var rows: [[String: Any]] = []
        for window in scoped.prefix(limit) {
            try budget.check()
            guard let owner = window.owningApplication,
                  let app = NSRunningApplication(processIdentifier: owner.processID), app.bundleIdentifier == bundleID, let startToken = applicationProcessStartToken(owner.processID) else {
                throw NativeFailure("staleReference", "Discovery application identity changed")
            }
            if let token = narrowedToken, token != startToken { throw NativeFailure("staleReference", "Discovery process fingerprint changed") }
            let bounds = window.frame
            guard bounds.minX.isFinite, bounds.minY.isFinite, bounds.width.isFinite, bounds.height.isFinite else {
                throw NativeFailure("invalidCoordinates", "Window bounds unavailable")
            }
            let rawTitle = window.title ?? ""
            var title = String(rawTitle.prefix(256))
            while title.utf8.count > 1024 { title.removeLast() }
            rows.append(["bundleId": bundleID, "pid": owner.processID, "processStartToken": startToken, "windowId": window.windowID, "title": title, "titleTruncated": title != rawTitle,
                         "bounds": ["x": bounds.minX, "y": bounds.minY, "width": bounds.width, "height": bounds.height]])
        }
        if let pid = narrowedPID, let token = narrowedToken, applicationProcessStartToken(pid) != token { throw NativeFailure("staleReference", "Discovery process fingerprint changed") }
        return ["bundleId": bundleID, "windows": rows, "truncated": scoped.count > limit, "returnedAt": iso.string(from: Date())]
    }
    func capture(_ params: [String: Any], _ budget: Budget) async throws -> [String: Any] {
        if let expected = params["processStartToken"] {
            guard let pid = params["pid"] as? Int32, let token = expected as? String, validApplicationProcessStartToken(token), applicationProcessStartToken(pid) == token else { throw NativeFailure("staleReference", "Capture process fingerprint changed") }
        }
        guard let nonce = params["captureNonce"] as? String,
              nonce.range(of: "^[0-9a-f]{32}$", options: .regularExpression) != nil,
              let maxBytes = params["maxBytes"] as? Int, maxBytes > 0, maxBytes <= 32 * 1024 * 1024,
              let bundleID = params["bundleId"] as? String, !bundleID.isEmpty,
              let pid = params["pid"] as? Int32, pid > 0,
              let expectedWindowID = params["windowID"] as? UInt32, expectedWindowID > 0,
              let app = NSRunningApplication(processIdentifier: pid), app.bundleIdentifier == bundleID, concreteApplicationBundle(bundleID), applicationProcessStartToken(pid) != nil else {
            throw NativeFailure("invalidScope", "Capture requires exact application, PID, window and bounded correlated transport")
        }
        guard let captureStartToken = applicationProcessStartToken(pid) else { throw NativeFailure("staleReference", "Capture process identity unavailable") }
        if let expected = params["processStartToken"] {
            guard let token = expected as? String, validApplicationProcessStartToken(token), token == captureStartToken else { throw NativeFailure("staleReference", "Capture process fingerprint changed") }
        }
        guard CGPreflightScreenCaptureAccess() else { throw NativeFailure("permissionDenied", "Screen capture permission absent") }
        guard let fd = params["artifactFD"] as? Int32, fd == 3, fcntl(fd, F_GETFD) != -1 else { throw NativeFailure("invalidArtifact", "Capture requires broker-owned inherited descriptor 3") }
        let content = try await SCShareableContent.excludingDesktopWindows(false, onScreenWindowsOnly: true)
        try budget.check()
        let identity: String
        let bounds: CGRect
        guard let window = content.windows.first(where: { $0.windowID == expectedWindowID && $0.owningApplication?.processID == pid && $0.owningApplication?.bundleIdentifier == bundleID }) else { throw NativeFailure("targetNotFound", "Exact capture application, window and PID not available") }
        let exact = try ExactWindowCapture(window: window, displays: content.displays)
        identity = "window:\(expectedWindowID)"; bounds = exact.geometry.bounds
        let scale = exact.scale
        guard applicationProcessStartToken(pid) == captureStartToken else { throw NativeFailure("staleReference", "Capture process fingerprint changed") }
        let image = try await SCScreenshotManager.captureImage(contentFilter: exact.filter, configuration: exact.configuration)
        try budget.check()
        try exact.geometry.validateImage(width: image.width, height: image.height)
        let refreshedContent = try await SCShareableContent.excludingDesktopWindows(false, onScreenWindowsOnly: true)
        try budget.check()
        guard let refreshedWindow = refreshedContent.windows.first(where: { $0.windowID == expectedWindowID && $0.owningApplication?.processID == pid && $0.owningApplication?.bundleIdentifier == bundleID }), refreshedWindow.frame == bounds else {
            throw NativeFailure("captureUnqualified", "Requested window disappeared or changed bounds during screenshot capture")
        }
        let refreshed = try ExactWindowCapture(window: refreshedWindow, displays: refreshedContent.displays)
        guard refreshed.displayID == exact.displayID, refreshed.geometry.sourceRect == exact.geometry.sourceRect, refreshed.scale == exact.scale else {
            throw NativeFailure("captureUnqualified", "Requested window display geometry changed during screenshot capture")
        }
        let data = NSMutableData()
        guard let destination = CGImageDestinationCreateWithData(data, UTType.png.identifier as CFString, 1, nil) else { throw NativeFailure("nativeFailure", "PNG encoder unavailable") }
        CGImageDestinationAddImage(destination, image, nil)
        guard CGImageDestinationFinalize(destination), data.length <= maxBytes else { throw NativeFailure("captureTooLarge", "Encoded capture byte budget exceeded") }
        try budget.check()
        guard let currentApp = NSRunningApplication(processIdentifier: pid), currentApp.bundleIdentifier == bundleID, applicationProcessStartToken(pid) == captureStartToken else { throw NativeFailure("staleReference", "Capture application identity changed") }
        var header = Data("MCAP".utf8)
        for offset in stride(from: 0, to: 32, by: 2) {
            let start = nonce.index(nonce.startIndex, offsetBy: offset)
            let end = nonce.index(start, offsetBy: 2)
            guard let byte = UInt8(nonce[start..<end], radix: 16) else { throw NativeFailure("invalidRequest", "Capture correlation invalid") }
            header.append(byte)
        }
        var length = UInt32(data.length).bigEndian
        withUnsafeBytes(of: &length) { header.append(contentsOf: $0) }
        let output = FileHandle(fileDescriptor: fd, closeOnDealloc: false)
        try output.write(contentsOf: header)
        try output.write(contentsOf: data as Data)
        return ["captureId": UUID().uuidString, "captureNonce": nonce, "identity": identity, "bundleId": bundleID, "pid": pid, "processStartToken": captureStartToken, "windowId": expectedWindowID, "widthPixels": image.width, "heightPixels": image.height, "scale": scale, "coordinateSpace": "globalLogicalPoints", "bounds": ["x": bounds.minX, "y": bounds.minY, "width": bounds.width, "height": bounds.height], "bytes": data.length, "returnedAt": iso.string(from: Date()), "axAtomic": false]
    }
}
