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

After an uncertain navigation, inspect the existing tab's location and fresh
image. If the intended destination is visibly open, continue from that state
with a different next action. Keep the original receipt unchanged and do not
repeat its input. Visible navigation is sufficient to choose the next control;
it does not prove that a submission succeeded. For an uncertain save, send,
payment or deletion, resolve that specific change before repeating or depending
on it. An old uncertain navigation is not a reason to abandon the whole task.

Use only advertised locator capabilities for mutations. A name visible in an
observation is not proof that every locator method can act on it. In particular,
do not replace a failed role locator with `getByText` when `web:textLocator` is
unavailable. Choose an advertised exact role, ID, test ID or label where supported.

After a semantic action times out before dispatch, inspect the existing target
tab with `mechanize_capture_windows` followed by `mechanize_capture`. Plain
inspection does not need a retained click permit. Reuse saved access and the
current session. A stale window means refresh window discovery, not request
approval again. If discovery returns no window because Chrome is in the
background, activate the intended Chrome application once and rediscover it.
Activate the target tab when necessary before interpreting its image.

Only when the next action needs a visual click, acquire
`mechanize_capture_window_frame`, inspect that fresh image, and use its coordinate
mapping and one-use permit for the intended action. Do not spend the permit's
lifetime on unrelated status calls.
Use the native API syntax in `mechanize-desktop` and `mechanize_describe`; do not
invent arguments. Verify the new page state before continuing.

`privateDOMUnavailable` restricts the web DOM route. It does not by itself forbid
native screenshots, accessibility or pointer input. On a visibly signed-in
page, use those advertised native tools for ordinary navigation and public form
controls. A failed credential-recovery check is not a prerequisite for this
native route. Use Vault tools for secret entry; do not reveal masked values or
copy secrets into public input tools. An actual secure-entry window, explicit
denied permission, or input still in flight remains a boundary for the affected
operation. Follow that operation's result rather than treating every protection
message as a desktop-wide stop.

`needsNativeAction` means choose the available native route. Ask for participation
only for an observed human-only challenge, missing permission, or a required
capability that is unavailable through all advertised routes.

For short run calls, use `waitMs: 5000` and named `outputBindings` for reads.
Inspect returned completion/outputs before polling again. If still running,
follow that same operation rather than starting another action.
