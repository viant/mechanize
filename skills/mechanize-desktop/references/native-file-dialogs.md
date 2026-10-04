# Native file dialogs

Use this reference when a macOS app or browser opens a system file chooser and
the task needs to navigate to a path or choose an item. Native dialogs are
owned by the target application, and their controls and keyboard routing vary.
Start from current advertised capabilities and a fresh, complete observation;
the control names below describe one tested Chrome/macOS case, not a universal
dialog API.

## Establish a scoped target

Use the exact app/process identity supplied by fresh discovery. For native
keyboard routing, bind both the numeric process PID and process birth/start
token; a PID alone can refer to a later process. Scope locators to the observed
dialog/window and require one match. Refresh observations when a dialog opens,
changes, or a mutation invalidates element references. Read current native
`identifier` and `role` strings as observed. `focused` and `enabled` are native
booleans and are useful only when returned as such by the current observation.
They are evidence about current UI state, not authorization or durable refs.

The accepted source grammar uses typed DSL actions such as `focus()`,
`fill("...")`, `click()` and, when explicitly advertised and enabled,
`pressSessionKey("Cmd+Shift+G")`. Validate proposed syntax with
`mechanize_script_validate` and confirm action support through live
capabilities. In a durable workflow each mutating step still needs its own
business key and immutable, independently observable postcondition as described
in the parent skill. Do not copy fixture selectors into another app without
observing them there.

## Choose one route before dispatch

For a file chooser whose list view is focused, a session-key chord can open the
Go To Folder sheet in some tested configurations. The explicit
`pressSessionKey` route requires the exact native PID and process birth token,
current focused target, and the separately enabled `sessionKeyboard`
capability. It is a distinct route from targeted keyboard input and semantic
accessibility actions. Select the route from current capability and observed
state before dispatch. If its outcome becomes unknown, stop and reconcile that
same effect; do not switch routes or resend the chord as a fallback.

In the tested disposable Chrome/macOS flow, focusing the observed `ListView`
and sending `Cmd+Shift+G` through `pressSessionKey` opened `GoToWindow`, and
`PathTextField` was observed as editable. A literal path fill was verified by
the helper's exact replacement proof. These observations establish that fixture's
route, not a promise that another app, macOS release, or dialog will behave the
same way.

`submit()` means the advertised semantic accessibility action (`AXConfirm`).
It does not mean “press Return” or “accept this dialog.” In the Chrome fixture,
`AXConfirm` on `PathTextField` was dispatched, but the expected return to the
file list did not verify; the run remained unresolved and a fresh observation
still showed `GoToWindow`. That original outcome remains unknown even though a
separate later phase succeeded. Do not rewrite its history, mark it absent,
repeat it, or infer success from a later phase.

A separate tested phase used activation, explicit path-field focus, and a
session Return key only after a fresh precondition showed the exact staged path
as the suggestion identifier under `GoToWindow`. Its postcondition verified
that `OKButton` became enabled. A subsequent explicit selection click was verified by observing the `Mechanize`
heading. Treat this sequence as evidence for that staged fixture and its exact
precondition, not as a general retry recipe. The precondition must be freshly
observed before any comparable action, and the acceptance route must be chosen
before dispatch. If a chosen action may have dispatched but its result is
unknown, reconcile the original immutable predicate; never fall back to another
acceptance mechanism.

## Reconcile without changing the claim

For an uncertain mutation, call `mechanize_effect_reconcile` with the exact
run, plan, attempt, effect, and revision references from current state. The host
selects an enrolled contract, such as `plan.effect.reconcile` or
`plan.postcondition.reconcile`, using an original immutable predicate and the
normal scope, provenance, and freshness guards. The caller supplies neither a
replacement predicate nor a success claim.
Positive fresh evidence can confirm that original effect; negative, incomplete,
stale, or unavailable evidence leaves it unresolved. Never replay merely
because a later observation does not show the control, and never treat a later
successful action as proof of an earlier unknown effect.

Keep business completion distinct from UI execution. A visible selected file or
changed app screen can establish only the specific UI predicate that was
observed; it does not establish the user's wider business objective by itself.

## Capture is separate evidence

AX observation and screenshot capture are independent evidence channels. A
screenshot can show visual state at capture time and help diagnose a dialog;
it does not by itself prove action causality or a business result. The tested screenshot
helper crop fix uses the exact child display-relative crop; do not rederive that
rectangle from the rendered preview. Preserve the helper's returned crop and
coordinate metadata when interpreting the image. A capture that looks correct
does not resolve an unknown mutation without matching authoritative evidence.

For credential-bearing destinations, use resource URLs/references only. Never
place passwords, access tokens, or other secrets in a file path, locator, DSL
literal, screenshot annotation, or workflow input.
