import ApplicationServices

/// Public AXDescription identifies a control's purpose when AXTitle is absent.
/// Never substitute its value or help text, and never conceal a failed title read.
func accessibleName(_ element: AXUIElement,
                    read: (AXUIElement, String) -> (AXError, CFTypeRef?) = { element, name in
                        var value: CFTypeRef?
                        let status = AXUIElementCopyAttributeValue(element, name as CFString, &value)
                        return (status, value)
                    }) -> (AXError, CFTypeRef?) {
    let title = read(element, kAXTitleAttribute)
    if title.0 == .success {
        guard let text = title.1 as? String else { return (.failure, nil) }
        if !text.isEmpty { return title }
    } else if !((title.0 == .noValue || title.0 == .attributeUnsupported) && title.1 == nil) {
        return title
    }
    let description = read(element, kAXDescriptionAttribute)
    if description.0 == .success {
        guard description.1 is String else { return (.failure, nil) }
        return description
    }
    if (description.0 == .noValue || description.0 == .attributeUnsupported) && description.1 == nil { return title }
    return description
}
