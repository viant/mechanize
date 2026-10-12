import Foundation
import MechanizeNativeCore
import AppKit
import ApplicationServices

// Local to the reviewed migration collector, never a general AX/MCP value API.
struct PrivateManagementNode: Equatable {
    let role: String, identifier: String
    let parent: Int?
}
struct PrivateManagementReceipt {
    let nodes: [PrivateManagementNode]
    let observedAt: Date
    init(_ data: Data, pid: Int32, birth: String, title: String) throws {
        guard let root = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              root["truncated"] as? Bool == false, (root["unavailable"] as? [String] ?? []).isEmpty,
              root["nativeRoot"] == nil, root["windowRootsOnly"] as? Bool != true,
              let surface = root["surface"] as? [String: Any], surface["kind"] as? String == "native",
              surface["bundleId"] as? String == "com.google.Chrome", surface["processId"] as? Int32 == pid,
              surface["processStartToken"] as? String == birth,
              let scope = root["windowScope"] as? [String: String], scope == ["title": title, "role": "AXWindow"],
              let started = root["started"] as? String, let at = PrivateManagementOS.date(started),
              let ended = root["ended"] as? String, let end = PrivateManagementOS.date(ended),
              at <= end, PrivateManagementOS.fresh(at), PrivateManagementOS.fresh(end),
              let raw = root["nodes"] as? [[String: Any]], !raw.isEmpty, raw.count <= 1000 else { throw privateManagementFailure() }
        var indexes: [String: Int] = [:], result: [PrivateManagementNode] = []
        for (index, node) in raw.enumerated() {
            guard let ref = node["ref"] as? [String: Any], let id = ref["id"] as? String, !id.isEmpty, indexes[id] == nil,
                  let role = node["nativeRole"] as? String, !role.isEmpty,
                  (node["unavailable"] as? [String] ?? []).isEmpty,
                  node["nativeOwnerMatchesRoot"] as? Bool == true, node["nativeOwnerProcessId"] as? Int32 == pid,
                  node["nativeOwnerStartToken"] as? String == birth, node["nativeOwnerBundleId"] as? String == "com.google.Chrome",
                  node["nativeOwnerUid"] as? UInt32 == getuid() else { throw privateManagementFailure() }
            let parentID = node["parentId"] as? String ?? ""
            let parent = parentID.isEmpty ? nil : indexes[parentID]
            guard (index == 0 && parentID.isEmpty && role == "AXWindow") || (index > 0 && parent != nil) else { throw privateManagementFailure() }
            indexes[id] = index
            result.append(.init(role: role, identifier: node["identifier"] as? String ?? "", parent: parent))
        }
        guard result.filter({ $0.role == "AXWebArea" }).count == 1 else { throw privateManagementFailure() }
        nodes = result; observedAt = at
    }
    // Match the complete topology BEFORE reading text. Only Chrome section
    // headings, the ID value, and the Loaded-from label/link are read locally;
    // extension descriptions are never scanned for plausible strings or paths.
    func path(local: [PrivateManagementNode], address: String, extensionID: String,
              text: (Int) throws -> String) throws -> String {
        guard local == nodes, extensionID.count == 32,
              extensionID.allSatisfy({ ("a"..."p").contains(String($0)) }),
              address == "chrome://extensions/?id=\(extensionID)",
              let web = nodes.firstIndex(where: { $0.role == "AXWebArea" }) else { throw privateManagementFailure() }
        func children(_ i: Int) -> [Int] { nodes.indices.filter { nodes[$0].parent == i } }
        func inside(_ i: Int) -> Bool {
            var parent = nodes[i].parent, count = 0
            while let p = parent, count < 64 { if p == web { return true }; parent = nodes[p].parent; count += 1 }
            return false
        }
        func bounded(_ i: Int) throws -> String {
            guard nodes[i].role == "AXStaticText" else { throw privateManagementFailure() }
            let value = try text(i)
            guard !value.isEmpty, value.utf8.count <= 4096,
                  !value.contains("\0"), !value.contains("\n"), !value.contains("\r"), !value.contains("…") else { throw privateManagementFailure() }
            return value
        }
        var headings: [Int: String] = [:]
        for i in nodes.indices where nodes[i].role == "AXHeading" && inside(i) {
            let items = children(i)
            guard items.count == 1, nodes[items[0]].role == "AXStaticText" else { throw privateManagementFailure() }
            headings[i] = try bounded(items[0])
        }
        let ids = headings.filter { $0.value == "ID" }.map(\.key)
        let sources = headings.filter { $0.value == "Source" }.map(\.key)
        guard ids.count == 1, sources.count == 1, let panel = nodes[ids[0]].parent,
              panel == nodes[sources[0]].parent, nodes[panel].role == "AXGroup", inside(panel) else { throw privateManagementFailure() }
        let identified = nodes.indices.filter { nodes[$0].identifier == "details-view" }
        guard identified.isEmpty || identified == [panel] else { throw privateManagementFailure() }
        let siblings = children(panel)
        guard let idPosition = siblings.firstIndex(of: ids[0]), idPosition + 1 < siblings.count,
              let sourcePosition = siblings.firstIndex(of: sources[0]), sourcePosition > idPosition,
              sourcePosition + 2 < siblings.count else { throw privateManagementFailure() }
        let idGroup = siblings[idPosition + 1], kindGroup = siblings[sourcePosition + 1], pathGroup = siblings[sourcePosition + 2]
        let idValues = children(idGroup), kindValues = children(kindGroup), parts = children(pathGroup)
        guard nodes[idGroup].role == "AXGroup", idValues.count == 1, nodes[idValues[0]].role == "AXStaticText",
              try bounded(idValues[0]) == extensionID,
              nodes[kindGroup].role == "AXGroup", kindValues.count == 1, nodes[kindValues[0]].role == "AXStaticText",
              nodes[pathGroup].role == "AXGroup", parts.count == 2, nodes[parts[0]].role == "AXStaticText",
              nodes[parts[1]].role == "AXLink", try bounded(parts[0]) == "Loaded from" else { throw privateManagementFailure() }
        let pathValues = children(parts[1])
        guard pathValues.count == 1, nodes[pathValues[0]].role == "AXStaticText" else { throw privateManagementFailure() }
        let result = try bounded(pathValues[0])
        guard PrivateManagementOS.path(result) else { throw privateManagementFailure() }
        return result
    }
}

extension PrivateManagementOS {
    static func loadedManagementPath(_ data: Data, _ pid: Int32, _ token: String, _ title: String, _ extensionID: String) throws -> (String, Date) {
        let receipt = try PrivateManagementReceipt(data, pid: pid, birth: token, title: title)
        let deadline = min(Date().addingTimeInterval(10), receipt.observedAt.addingTimeInterval(30))
        func check() throws {
            guard AXIsProcessTrusted() else { throw privateManagementFailure() }
            guard Date() < deadline, try birth(pid) == token,
                  NSRunningApplication(processIdentifier: pid)?.bundleIdentifier == "com.google.Chrome" else { throw privateManagementFailure() }
        }
        func owner(_ element: AXUIElement) throws {
            try check(); var actual: pid_t = 0
            guard AXUIElementGetPid(element, &actual) == .success, actual == pid else { throw privateManagementFailure() }
            AXUIElementSetMessagingTimeout(element, 0.05)
        }
        func value(_ element: AXUIElement, _ name: String, optional: Bool = false) throws -> CFTypeRef? {
            try owner(element); var raw: CFTypeRef?
            let code = AXUIElementCopyAttributeValue(element, name as CFString, &raw); try check()
            if optional && (code == .noValue || code == .attributeUnsupported) && raw == nil { return nil }
            guard code == .success, let raw else { throw privateManagementFailure() }; return raw
        }
        func string(_ element: AXUIElement, _ name: String, optional: Bool = false) throws -> String {
            guard let raw = try value(element, name, optional: optional) else { return "" }
            guard let text = raw as? String, text.utf8.count <= 4096, !text.contains("\0") else { throw privateManagementFailure() }; return text
        }
        func array(_ element: AXUIElement, _ name: String, _ limit: Int) throws -> [AXUIElement] {
            try owner(element); var before = 0
            let code = AXUIElementGetAttributeValueCount(element, name as CFString, &before)
            if (code == .noValue || code == .attributeUnsupported) && before == 0 { return [] }
            guard code == .success, before >= 0, before <= limit else { throw privateManagementFailure() }
            if before == 0 { return [] }
            var raw: CFArray?
            guard AXUIElementCopyAttributeValues(element, name as CFString, 0, before, &raw) == .success,
                  let values = raw as? [AXUIElement], values.count == before else { throw privateManagementFailure() }
            var after = 0
            guard AXUIElementGetAttributeValueCount(element, name as CFString, &after) == .success, after == before else { throw privateManagementFailure() }
            try check(); return values
        }
        let app = AXUIElementCreateApplication(pid)
        func selectedWindow() throws -> AXUIElement {
            let windows = try array(app, kAXWindowsAttribute, 64)
            let matching = try windows.filter { try string($0, kAXTitleAttribute) == title }
            guard matching.count == 1 else { throw privateManagementFailure() }; return matching[0]
        }
        let window = try selectedWindow()
        func snapshot() throws -> ([PrivateManagementNode], [AXUIElement], String) {
            guard CFEqual(try selectedWindow(), window) else { throw privateManagementFailure() }
            var elements = [window], parents: [Int?] = [nil], nodes: [PrivateManagementNode] = [], cursor = 0
            while cursor < elements.count {
                guard elements.count <= 1000 else { throw privateManagementFailure() }
                let current = elements[cursor]
                nodes.append(.init(role: try string(current, kAXRoleAttribute), identifier: try string(current, kAXIdentifierAttribute, optional: true), parent: parents[cursor]))
                var children: [AXUIElement] = []
                for child in try array(current, kAXChildrenAttribute, 1000) {
                    if CFEqual(child, current) || children.contains(where: { CFEqual($0, child) }) { continue }
                    guard !elements.contains(where: { CFEqual($0, child) }) else { throw privateManagementFailure() }
                    children.append(child)
                }
                elements.append(contentsOf: children); parents.append(contentsOf: children.map { _ in cursor }); cursor += 1
            }
            let areas = nodes.indices.filter { nodes[$0].role == "AXWebArea" }
            guard areas.count == 1 else { throw privateManagementFailure() }
            let area = elements[areas[0]], raw = try value(area, "AXURL", optional: true)
            let address: String
            if let url = raw as? URL { address = url.absoluteString }
            else if let text = raw as? String { address = text }
            else if raw == nil { address = try string(area, kAXDocumentAttribute) }
            else { throw privateManagementFailure() }
            return (nodes, elements, address)
        }
        func readStatic(_ tree: ([PrivateManagementNode],[AXUIElement],String), _ index:Int) throws -> String {
            guard tree.0[index].role == "AXStaticText", let web=tree.0.firstIndex(where:{$0.role == "AXWebArea"}) else {throw privateManagementFailure()}
            func documentStillMatches() throws {
                guard CFEqual(try selectedWindow(),window) else {throw privateManagementFailure()}
                let raw=try value(tree.1[web],"AXURL",optional:true)
                let address:String
                if let url=raw as? URL {address=url.absoluteString}
                else if let text=raw as? String {address=text}
                else if raw == nil {address=try string(tree.1[web],kAXDocumentAttribute)}
                else {throw privateManagementFailure()}
                guard address == "chrome://extensions/?id=\(extensionID)" else {throw privateManagementFailure()}
            }
            try documentStillMatches()
            guard try string(tree.1[index],kAXRoleAttribute)=="AXStaticText" else {throw privateManagementFailure()}
            let result=try string(tree.1[index],kAXValueAttribute)
            try documentStillMatches();return result
        }
        let first = try snapshot()
        let path = try receipt.path(local: first.0, address: first.2, extensionID: extensionID) { try readStatic(first,$0) }
        let second = try snapshot()
        guard first.1.count == second.1.count, zip(first.1, second.1).allSatisfy({ CFEqual($0.0, $0.1) }) else { throw privateManagementFailure() }
        let repeated = try receipt.path(local: second.0, address: second.2, extensionID: extensionID) { try readStatic(second,$0) }
        guard path == repeated else { throw privateManagementFailure() }; try check()
        return (path, receipt.observedAt)
    }
}

private func privateManagementFailure() -> NativeFailure { NativeFailure("privateManagementUnavailable","Management proof unavailable") }
enum PrivateManagementOS {
    static func birth(_ pid:Int32) throws -> String { guard let value = applicationProcessStartToken(pid), applicationLoginUID(pid) == getuid() else { throw privateManagementFailure() }; return value }
    static func fresh(_ at:Date)->Bool { let age=Date().timeIntervalSince(at); return age >= -1 && age <= 30 }
    static func date(_ text:String)->Date? { let f=ISO8601DateFormatter(); f.formatOptions=[.withInternetDateTime,.withFractionalSeconds];return f.date(from:text) ?? ISO8601DateFormatter().date(from:text) }
    static func path(_ text:String)->Bool { text.hasPrefix("/") && text.utf8.count <= 4096 && !text.contains("\0") && !text.contains("\n") && !text.contains("\r") && text.split(separator:"/",omittingEmptySubsequences:false).dropFirst().allSatisfy{ !$0.isEmpty && $0 != "." && $0 != ".." } }
}
