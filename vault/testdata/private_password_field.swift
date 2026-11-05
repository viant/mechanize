// Synthetic, off-screen AppKit fixture only. Never targets another application,
// reads a password back, or uses the general/user pasteboard.
import AppKit
let app = NSApplication.shared
let name = CommandLine.arguments.dropFirst().first ?? ""
guard name.hasPrefix("com.viant.mechanize.private-field-test.") else { exit(2) }
let board = NSPasteboard(name: NSPasteboard.Name(name))
let window = NSWindow(contentRect: NSRect(x: -10000, y: -10000, width: 300, height: 100), styleMask: [.borderless], backing: .buffered, defer: false)
let field = NSSecureTextField(frame: NSRect(x: 10, y: 10, width: 250, height: 24))
window.contentView?.addSubview(field)
guard window.makeFirstResponder(field), let editor = field.currentEditor() as? NSTextView else { exit(3) }
defer { board.clearContents(); board.releaseGlobally(); window.close() }
func reply(_ ok: Bool) { print(ok ? "true" : "false"); fflush(stdout) }
reply(true)
while let line = readLine() {
    guard line.utf8.count < 256, let data = line.data(using: .utf8),
          let request = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
          Set(request.keys) == ["operation", "count"], let operation = request["operation"] as? String,
          let count = request["count"] as? Int, (0...4096).contains(count),
          field.currentEditor() === editor else { reply(false); continue }
    switch operation {
    case "count": reply(editor.accessibilityNumberOfCharacters() == count)
    case "probe":
        guard editor.accessibilityNumberOfCharacters() == 0 else { reply(false); continue }
        editor.insertText("x", replacementRange: NSRange(location: 0, length: 0)); reply(true)
    case "removeProbe":
        guard editor.accessibilityNumberOfCharacters() == 1 else { reply(false); continue }
        editor.insertText("", replacementRange: NSRange(location: 0, length: 1)); reply(true)
    case "paste":
        guard editor.accessibilityNumberOfCharacters() == 0 else { reply(false); continue }
        reply(editor.readSelection(from: board))
    case "clipboardEmpty": reply(board.types?.isEmpty == true)
    default: reply(false)
    }
}
