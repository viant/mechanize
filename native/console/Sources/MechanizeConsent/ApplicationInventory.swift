import Foundation

struct InstalledApplication: Identifiable, Equatable {
    let bundleID: String
    let displayName: String
    let url: URL
    var id: String { bundleID }
}

/// Reads bundle metadata from known application folders. It never opens or traverses an app bundle.
enum ApplicationInventory {
    private static let maximumTraversalCount = 20_000
    private static let maximumDepth = 6

    static func scan(fileManager: FileManager = .default, homeDirectory: URL = FileManager.default.homeDirectoryForCurrentUser,
                     maximumCount: Int = 1_200) -> [InstalledApplication] {
        let roots = [URL(fileURLWithPath: "/Applications", isDirectory: true),
                     homeDirectory.appendingPathComponent("Applications", isDirectory: true),
                     URL(fileURLWithPath: "/System/Applications", isDirectory: true),
                     URL(fileURLWithPath: "/System/Applications/Utilities", isDirectory: true)]
        return scan(roots: roots, fileManager: fileManager, maximumCount: maximumCount,
                    maximumTraversalCount: maximumTraversalCount, maximumDepth: maximumDepth)
    }

    // Kept parameterized so traversal limits and filesystem fixtures can be exercised independently.
    static func scan(roots: [URL], fileManager: FileManager, maximumCount: Int,
                     maximumTraversalCount: Int, maximumDepth: Int) -> [InstalledApplication] {
        guard maximumCount > 0, maximumTraversalCount > 0, maximumDepth >= 0 else { return [] }
        var found: [String: InstalledApplication] = [:]
        var queue = roots.map { ($0, 0) }
        var cursor = 0
        var traversed = 0

        while cursor < queue.count, traversed < maximumTraversalCount, found.count < maximumCount {
            let (directory, depth) = queue[cursor]
            cursor += 1
            guard let values = try? directory.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey]),
                  values.isDirectory == true, values.isSymbolicLink != true else { continue }
            guard let children = try? fileManager.contentsOfDirectory(at: directory,
                    includingPropertiesForKeys: [.isDirectoryKey, .isSymbolicLinkKey, .isPackageKey],
                    options: [.skipsHiddenFiles]) else { continue }
            for url in children {
                traversed += 1
                guard traversed <= maximumTraversalCount,
                      let child = try? url.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey, .isPackageKey]),
                      child.isSymbolicLink != true, child.isDirectory == true else { continue }

                if url.pathExtension.lowercased() == "app" {
                    if let bundle = Bundle(url: url), let bundleID = bundle.bundleIdentifier,
                       isValidBundleID(bundleID), found[bundleID] == nil {
                        let displayName = (bundle.object(forInfoDictionaryKey: "CFBundleDisplayName") as? String)
                            ?? (bundle.object(forInfoDictionaryKey: "CFBundleName") as? String)
                            ?? url.deletingPathExtension().lastPathComponent
                        found[bundleID] = InstalledApplication(bundleID: bundleID, displayName: displayName, url: url)
                    }
                } else if depth < maximumDepth, child.isPackage != true {
                    queue.append((url, depth + 1))
                }
                if found.count >= maximumCount || traversed >= maximumTraversalCount { break }
            }
        }
        return found.values.sorted { $0.displayName.localizedCaseInsensitiveCompare($1.displayName) == .orderedAscending }
    }

    static func isValidBundleID(_ value: String) -> Bool {
        guard value.utf8.count <= 256, !value.contains("*"), !value.contains("?") else { return false }
        let parts = value.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count >= 2 else { return false }
        return parts.allSatisfy { part in
            !part.isEmpty && part.utf8.count <= 63 && part.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-") }
        }
    }
}
