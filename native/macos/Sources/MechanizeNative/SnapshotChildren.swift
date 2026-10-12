import ApplicationServices

/// AXChildren sometimes includes the element itself (observed in Outlook's
/// search field). That edge adds no descendant. Compare AX identity, never a
/// title/identifier: distinct controls with identical labels must survive.
/// Longer cycles and shared descendants are deliberately left to the bounded
/// traversal; this does not invent or rewrite containment across parents.
func snapshotChildren(_ children: [AXUIElement], of parent: AXUIElement) -> (elements: [AXUIElement], selfEdges: Int, duplicateEdges: Int, truncated: Bool) {
    var result: [AXUIElement] = []
    var selfEdges = 0
    var duplicateEdges = 0
    // Bound identity comparisons even when an app returns an enormous array of
    // aliases. Uninspected edges remain incomplete, even if all might be repeats.
    for child in children.prefix(1001) {
        if CFEqual(child, parent) { selfEdges += 1; continue }
        if result.contains(where: { CFEqual($0, child) }) { duplicateEdges += 1; continue }
        result.append(child)
    }
    return (result, selfEdges, duplicateEdges, children.count > 1001)
}
