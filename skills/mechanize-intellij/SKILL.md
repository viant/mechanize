---
name: mechanize-intellij
description: "Operate IntelliJ IDEA through Mechanize accessibility for project navigation and authorized Git commit/push workflows."
---

# IntelliJ through Mechanize

Discover the current app, process birth token, windows and advertised capabilities through Mechanize. Follow the desktop skill for session ownership and action receipts. Never reuse process or window identifiers from a previous run.

For large IDE menus, use `native:menuScope` when advertised: observe `nativeRoot: "menuBar"` with `nativeMenu` equal to an observed top-level menu name. Use the same named scope in the action DSL, for example `.menuBar(name:"Git")`. This bounds discovery to that menu and preserves exact lookup. A truncated whole-menu observation cannot prove uniqueness; repeating it or increasing unrelated traversal is ineffective.

Before Git actions, verify the selected project and repository, branch, staged files and existing HEAD. Commit only the authorized changes. Existing commits must be pushed without recommitting or amending. Confirm the resulting commit and remote SHA independently; a clicked button alone does not establish success. IntelliJ's configured Git authentication may differ from terminal authentication; verify the push result rather than assuming credentials work.

Activation, complete named Git/Window menu observation, project selection, and a capture-bound Cancel click closing a no-outgoing Push dialog have been verified live. Physical-window shortcuts can reject stale or unavailable windows before input; reacquire fresh scope and inspect the finite failure code. Do not repeat an uncertain mutation. Use a fresh menu observation when window-bound keyboard control is unavailable.

Commit and Push have been verified live: exact staged files were reviewed, Amend and tags stayed unchecked, and independent local/remote Git evidence confirmed the resulting commits. Direct AX fill of the focused public Commit Message field also passed after semantic AX recipient qualification was separated from physical-window geometry.

Use the already focused Commit pane when present; opening it again adds no evidence. Prefer a complete focused-element observation for the message, then verify the literal value. If a dialog's AX tree is incomplete, capture its exact owned physical window and use a fresh capture-bound click at the visually verified control. Consume the frame permit promptly; avoid unrelated calls between capture and input. For guarded physical text entry, `focusRole` is the raw observed AX role, such as `AXTextArea`, rather than a normalized locator role like `textbox`.

Review only the authorized staged files and commit options. Standard formatting checks on already formatted files need not be disabled; verify the resulting tree instead of exploring unrelated options. Unsupported popup layers are not an invitation to bypass input guards. Named menu scoping does not establish that every IntelliJ dialog is controllable.
