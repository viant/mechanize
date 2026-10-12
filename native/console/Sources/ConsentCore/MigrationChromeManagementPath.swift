import Foundation
import AppKit
import ApplicationServices
import Darwin

enum MigrationLoadedPath {
    static func userHome() throws -> String {
        var record = passwd(), result: UnsafeMutablePointer<passwd>?
        var buffer = [CChar](repeating:0,count:65536)
        return try buffer.withUnsafeMutableBufferPointer { bytes in
            guard getpwuid_r(getuid(),&record,bytes.baseAddress,bytes.count,&result)==0, result != nil,
                  record.pw_uid==getuid(), let raw=record.pw_dir else { throw MigrationConsoleError.unavailable }
            let home=String(cString:raw)
            guard MigrationRuntimeConsoleManifest.path(home), home != "/" else { throw MigrationConsoleError.unavailable }
            return home
        }
    }
    static func normalize(_ value:String, home:() throws -> String = userHome) throws -> String {
        guard !value.isEmpty, value.utf8.count<=4096, !value.contains("…"), !value.contains("..."),
              !value.unicodeScalars.contains(where:{CharacterSet.controlCharacters.contains($0)}) else {throw MigrationConsoleError.unavailable}
        let result:String
        if value.hasPrefix("~/") {
            let base=try home()
            guard MigrationRuntimeConsoleManifest.path(base), base != "/" else{throw MigrationConsoleError.unavailable}
            result=base+"/"+value.dropFirst(2)
        } else { result=value }
        // No URL decoding, named-user expansion, path cleanup or traversal.
        // The collector subsequently requires exact equality to the signed path.
        guard MigrationRuntimeConsoleManifest.path(result) else {throw MigrationConsoleError.unavailable}
        return result
    }
}

// Local to the reviewed migration collector, never a general AX/MCP value API.
struct MigrationManagementNode: Equatable {
    let role: String, identifier: String
    let parent: Int?
}
struct MigrationManagementReceipt {
    let nodes: [MigrationManagementNode]
    let observedAt: Date
    init(_ data: Data, pid: Int32, birth: String, title: String) throws {
        guard let root = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              root["truncated"] as? Bool == false, (root["unavailable"] as? [String] ?? []).isEmpty,
              root["nativeRoot"] == nil, root["windowRootsOnly"] as? Bool != true,
              let surface = root["surface"] as? [String: Any], surface["kind"] as? String == "native",
              surface["bundleId"] as? String == "com.google.Chrome", surface["processId"] as? Int32 == pid,
              surface["processStartToken"] as? String == birth,
              let scope = root["windowScope"] as? [String: String], scope == ["title": title, "role": "AXWindow"],
              let started = root["started"] as? String, let at = MigrationRuntimeObserverCollector.date(started),
              let ended = root["ended"] as? String, let end = MigrationRuntimeObserverCollector.date(ended),
              at <= end, MigrationRuntimeObserverCollector.fresh(at), MigrationRuntimeObserverCollector.fresh(end),
              let raw = root["nodes"] as? [[String: Any]], !raw.isEmpty, raw.count <= 1000 else { throw MigrationConsoleError.unavailable }
        var indexes: [String: Int] = [:], result: [MigrationManagementNode] = []
        for (index, node) in raw.enumerated() {
            guard let ref = node["ref"] as? [String: Any], let id = ref["id"] as? String, !id.isEmpty, indexes[id] == nil,
                  let role = node["nativeRole"] as? String, !role.isEmpty,
                  (node["unavailable"] as? [String] ?? []).isEmpty,
                  node["nativeOwnerMatchesRoot"] as? Bool == true, node["nativeOwnerProcessId"] as? Int32 == pid,
                  node["nativeOwnerStartToken"] as? String == birth, node["nativeOwnerBundleId"] as? String == "com.google.Chrome",
                  node["nativeOwnerUid"] as? UInt32 == getuid() else { throw MigrationConsoleError.unavailable }
            let parentID = node["parentId"] as? String ?? ""
            let parent = parentID.isEmpty ? nil : indexes[parentID]
            guard (index == 0 && parentID.isEmpty && role == "AXWindow") || (index > 0 && parent != nil) else { throw MigrationConsoleError.unavailable }
            indexes[id] = index
            result.append(.init(role: role, identifier: node["identifier"] as? String ?? "", parent: parent))
        }
        guard result.filter({ $0.role == "AXWebArea" }).count == 1 else { throw MigrationConsoleError.unavailable }
        nodes = result; observedAt = at
    }
    // Match the complete topology BEFORE reading text. Only Chrome section
    // headings, the ID value, and the Loaded-from label/link are read locally;
    // extension descriptions are never scanned for plausible strings or paths.
    func path(local: [MigrationManagementNode], address: String, extensionID: String,
              text: (Int) throws -> String) throws -> String {
        guard local == nodes, extensionID.count == 32,
              extensionID.allSatisfy({ ("a"..."p").contains(String($0)) }),
              address == "chrome://extensions/?id=\(extensionID)",
              let web = nodes.firstIndex(where: { $0.role == "AXWebArea" }) else { throw MigrationConsoleError.unavailable }
        func children(_ i: Int) -> [Int] { nodes.indices.filter { nodes[$0].parent == i } }
        func inside(_ i: Int) -> Bool {
            var parent = nodes[i].parent, count = 0
            while let p = parent, count < 64 { if p == web { return true }; parent = nodes[p].parent; count += 1 }
            return false
        }
        func bounded(_ i: Int) throws -> String {
            guard nodes[i].role == "AXStaticText" else { throw MigrationConsoleError.unavailable }
            let value = try text(i)
            guard !value.isEmpty, value.utf8.count <= 4096,
                  !value.contains("\0"), !value.contains("\n"), !value.contains("\r"), !value.contains("…") else { throw MigrationConsoleError.unavailable }
            return value
        }
        var headings: [Int: String] = [:]
        for i in nodes.indices where nodes[i].role == "AXHeading" && inside(i) {
            let items = children(i)
            guard items.count == 1, nodes[items[0]].role == "AXStaticText" else { throw MigrationConsoleError.unavailable }
            headings[i] = try bounded(items[0])
        }
        let ids = headings.filter { $0.value == "ID" }.map(\.key)
        let sources = headings.filter { $0.value == "Source" }.map(\.key)
        guard ids.count == 1, sources.count == 1, let panel = nodes[ids[0]].parent,
              panel == nodes[sources[0]].parent, nodes[panel].role == "AXGroup", inside(panel) else { throw MigrationConsoleError.unavailable }
        let identified = nodes.indices.filter { nodes[$0].identifier == "details-view" }
        guard identified.isEmpty || identified == [panel] else { throw MigrationConsoleError.unavailable }
        let siblings = children(panel)
        guard let idPosition = siblings.firstIndex(of: ids[0]), idPosition + 1 < siblings.count,
              let sourcePosition = siblings.firstIndex(of: sources[0]), sourcePosition > idPosition,
              sourcePosition + 2 < siblings.count else { throw MigrationConsoleError.unavailable }
        let idGroup = siblings[idPosition + 1], kindGroup = siblings[sourcePosition + 1], pathGroup = siblings[sourcePosition + 2]
        let idValues = children(idGroup), kindValues = children(kindGroup), parts = children(pathGroup)
        guard nodes[idGroup].role == "AXGroup", idValues.count == 1, nodes[idValues[0]].role == "AXStaticText",
              try bounded(idValues[0]) == extensionID,
              nodes[kindGroup].role == "AXGroup", kindValues.count == 1, nodes[kindValues[0]].role == "AXStaticText",
              nodes[pathGroup].role == "AXGroup", parts.count == 2, nodes[parts[0]].role == "AXStaticText",
              nodes[parts[1]].role == "AXLink", try bounded(parts[0]) == "Loaded from" else { throw MigrationConsoleError.unavailable }
        let pathValues = children(parts[1])
        guard pathValues.count == 1, nodes[pathValues[0]].role == "AXStaticText" else { throw MigrationConsoleError.unavailable }
        return try MigrationLoadedPath.normalize(bounded(pathValues[0]))
    }
}

extension MigrationObserverOS {
    static func loadedManagementPath(_ data: Data, _ pid: Int32, _ token: String, _ title: String, _ extensionID: String) throws -> (String, Date) {
        let receipt = try MigrationManagementReceipt(data, pid: pid, birth: token, title: title)
        let deadline = min(Date().addingTimeInterval(10), receipt.observedAt.addingTimeInterval(30))
        func check() throws {
            guard AXIsProcessTrusted() else { throw MigrationObserverReadinessError.accessibilityRequired }
            guard Date() < deadline, try birth(pid) == token,
                  NSRunningApplication(processIdentifier: pid)?.bundleIdentifier == "com.google.Chrome" else { throw MigrationConsoleError.unavailable }
        }
        func owner(_ element: AXUIElement) throws {
            try check(); var actual: pid_t = 0
            guard AXUIElementGetPid(element, &actual) == .success, actual == pid else { throw MigrationConsoleError.unavailable }
            AXUIElementSetMessagingTimeout(element, 0.05)
        }
        func value(_ element: AXUIElement, _ name: String, optional: Bool = false) throws -> CFTypeRef? {
            try owner(element); var raw: CFTypeRef?
            let code = AXUIElementCopyAttributeValue(element, name as CFString, &raw); try check()
            if optional && (code == .noValue || code == .attributeUnsupported) && raw == nil { return nil }
            guard code == .success, let raw else { throw MigrationConsoleError.unavailable }; return raw
        }
        func string(_ element: AXUIElement, _ name: String, optional: Bool = false) throws -> String {
            guard let raw = try value(element, name, optional: optional) else { return "" }
            guard let text = raw as? String, text.utf8.count <= 4096, !text.contains("\0") else { throw MigrationConsoleError.unavailable }; return text
        }
        func array(_ element: AXUIElement, _ name: String, _ limit: Int) throws -> [AXUIElement] {
            try owner(element); var before = 0
            let code = AXUIElementGetAttributeValueCount(element, name as CFString, &before)
            if (code == .noValue || code == .attributeUnsupported) && before == 0 { return [] }
            guard code == .success, before >= 0, before <= limit else { throw MigrationConsoleError.unavailable }
            if before == 0 { return [] }
            var raw: CFArray?
            guard AXUIElementCopyAttributeValues(element, name as CFString, 0, before, &raw) == .success,
                  let values = raw as? [AXUIElement], values.count == before else { throw MigrationConsoleError.unavailable }
            var after = 0
            guard AXUIElementGetAttributeValueCount(element, name as CFString, &after) == .success, after == before else { throw MigrationConsoleError.unavailable }
            try check(); return values
        }
        let app = AXUIElementCreateApplication(pid)
        func selectedWindow() throws -> AXUIElement {
            let windows = try array(app, kAXWindowsAttribute, 64)
            let matching = try windows.filter { try string($0, kAXTitleAttribute) == title }
            guard matching.count == 1 else { throw MigrationConsoleError.unavailable }; return matching[0]
        }
        let window = try selectedWindow()
        func snapshot() throws -> ([MigrationManagementNode], [AXUIElement], String) {
            guard CFEqual(try selectedWindow(), window) else { throw MigrationConsoleError.unavailable }
            var elements = [window], parents: [Int?] = [nil], nodes: [MigrationManagementNode] = [], cursor = 0
            while cursor < elements.count {
                guard elements.count <= 1000 else { throw MigrationConsoleError.unavailable }
                let current = elements[cursor]
                nodes.append(.init(role: try string(current, kAXRoleAttribute), identifier: try string(current, kAXIdentifierAttribute, optional: true), parent: parents[cursor]))
                var children: [AXUIElement] = []
                for child in try array(current, kAXChildrenAttribute, 1000) {
                    if CFEqual(child, current) || children.contains(where: { CFEqual($0, child) }) { continue }
                    guard !elements.contains(where: { CFEqual($0, child) }) else { throw MigrationConsoleError.unavailable }
                    children.append(child)
                }
                elements.append(contentsOf: children); parents.append(contentsOf: children.map { _ in cursor }); cursor += 1
            }
            let areas = nodes.indices.filter { nodes[$0].role == "AXWebArea" }
            guard areas.count == 1 else { throw MigrationConsoleError.unavailable }
            let area = elements[areas[0]], raw = try value(area, "AXURL", optional: true)
            let address: String
            if let url = raw as? URL { address = url.absoluteString }
            else if let text = raw as? String { address = text }
            else if raw == nil { address = try string(area, kAXDocumentAttribute) }
            else { throw MigrationConsoleError.unavailable }
            return (nodes, elements, address)
        }
        func readStatic(_ tree: ([MigrationManagementNode],[AXUIElement],String), _ index:Int) throws -> String {
            guard tree.0[index].role == "AXStaticText", let web=tree.0.firstIndex(where:{$0.role == "AXWebArea"}) else {throw MigrationConsoleError.unavailable}
            func documentStillMatches() throws {
                guard CFEqual(try selectedWindow(),window) else {throw MigrationConsoleError.unavailable}
                let raw=try value(tree.1[web],"AXURL",optional:true)
                let address:String
                if let url=raw as? URL {address=url.absoluteString}
                else if let text=raw as? String {address=text}
                else if raw == nil {address=try string(tree.1[web],kAXDocumentAttribute)}
                else {throw MigrationConsoleError.unavailable}
                guard address == "chrome://extensions/?id=\(extensionID)" else {throw MigrationConsoleError.unavailable}
            }
            try documentStillMatches()
            guard try string(tree.1[index],kAXRoleAttribute)=="AXStaticText" else {throw MigrationConsoleError.unavailable}
            let result=try string(tree.1[index],kAXValueAttribute)
            try documentStillMatches();return result
        }
        let first = try snapshot()
        let path = try receipt.path(local: first.0, address: first.2, extensionID: extensionID) { try readStatic(first,$0) }
        let second = try snapshot()
        guard first.1.count == second.1.count, zip(first.1, second.1).allSatisfy({ CFEqual($0.0, $0.1) }) else { throw MigrationConsoleError.unavailable }
        let repeated = try receipt.path(local: second.0, address: second.2, extensionID: extensionID) { try readStatic(second,$0) }
        guard path == repeated else { throw MigrationConsoleError.unavailable }; try check()
        return (path, receipt.observedAt)
    }
}
