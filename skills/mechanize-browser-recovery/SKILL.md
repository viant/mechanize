---
name: mechanize-browser-recovery
description: Recover a Mechanize browser workflow after a locator timeout, unsupported locator, or native fallback requirement, while preserving the current session and input receipts.
---

# Recover browser interaction

Use this guide when browser interaction fails. Keep the original task and its
submission limits unchanged. Reuse an authenticated session; a navigation failure
is not a reason to log in again.

Check the original operation's structured execution failure. `notDispatched`
permits choosing a corrected action after checking fresh state. A generic failure
or `unknown` does not prove absence: inspect the original receipt first. Keep the
original request ID for retrieving a lost result; use a new request ID for a
corrected plan after confirmed non-dispatch.

Use only advertised locator capabilities for mutations. A name visible in an
observation is not proof that every locator method can act on it. In particular,
do not replace a failed role locator with `getByText` when `web:textLocator` is
unavailable. Choose an advertised exact role, ID, test ID or label where supported.

After a semantic action times out before dispatch, inspect the existing target
tab and use the native screenshot/frame route when available. Discover the
physical window, activate the target tab, capture a fresh frame, inspect its
image, and use its coordinate mapping and one-use permit for the intended action.
Use the native API syntax in `mechanize-desktop` and `mechanize_describe`; do not
invent arguments. Verify the new page state before continuing. A policy or
protected-entry refusal still needs its stated issue resolved; changing transport
does not override it.

`needsNativeAction` is not by itself a request for human approval. Use the
available native tools within the user's authorized task. Ask for participation
only when the observed page or an explicit permission result requires it.

For short run calls, use `waitMs: 5000` and named `outputBindings` for reads.
Inspect returned completion/outputs before polling again. If still running,
follow that same operation rather than starting another action.
