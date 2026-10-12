# Bounded window text input

`typeWindowText` is a separate, opt-in native action for literal single-line text.
It is implemented in source and requires live qualification before an app guide
can claim support. It does not reinterpret `pressWindowKey` or use raw input as
an automatic fallback.

Example for an already observed Excel window and focused content area:

```text
app("com.microsoft.Excel", processId: 123, processStartToken: "100:1").typeWindowText(windowId: 456, text: "=SUM(17,23)", focusRole: "AXLayoutArea", focusName: "Content Area")
```

Replace the illustrative identities with fresh observations. The desktop host
must explicitly enroll `nativeLaunch.sessionText: true` in semantic mode.
Existing `sessionKeyboard` enrollment does not authorize text. The signed helper
requires `--allow-session-text`; the host advertises `native:windowSessionText`
only after its native control readiness checks pass. Read-only, launch-only and
raw profiles do not implicitly gain this route.

The closed request contains `windowId`, `text`, `focusRole`, `focusIdentifier`
and `focusName`; the DSL supplies an empty value for an omitted identifier or
name, but at least one must be explicit. Text is bounded to 4,096 UTF-8 bytes;
control characters, tabs, line breaks and empty text are rejected. Use a separate
explicit key action for Return or Tab. Bound inputs remain typed data, never
executable workflow source. Do not put secrets into text literals or logs.

Before input the helper checks the exact PID/birth, user, foreground application,
top owned physical window, current console, event permission, released physical
modifiers, secure-input state,
watchdog and held fence. It positively identifies the app's current focused AX
element and compares its declared role/name/identifier and actual ownership.
Standard nonsecure text fields/areas are supported targets. Custom canvas
profiles are limited to Excel's `Content Area` (`AXLayoutArea`) and Word's
`Document Pane` (`AXSplitGroup`); other custom controls fail closed.

Unicode is divided into at most 20 UTF-16 units per event without splitting a
surrogate pair. Every chunk revalidates window/fence/focus identity, including
CF identity of the original focused element. Down/up use the same login-session
route and existing held-input cleanup. Cancellation, focus change or release
failure stops the sequence. Once a down was attempted, subsequent failure is
unknown; no chunk or remainder is automatically replayed. Any mutation retires
existing capture-click permits.

The helper receipt binds request, process, window, focus metadata, text hash,
helper epoch and timestamp. It proves dispatch correlation only. The durable
intent still commits before dispatch; a separate declared postcondition and
independent artifact checks are needed for a qualified outcome. Unknown effects
retain their original plan and text; changing the request ID is not a retry path.

Focus stability does not detect a human typing into the same focused field.
Use an uninterrupted input interval and a fresh document/content precondition,
then verify the resulting content. This first implementation does not claim
arbitrary app support, background text delivery, safe secret entry or business
completion.

## Formatting state observations

The helper advertises `nativeBooleanReads: ["checked"]` for exact `AXCheckBox`
and `AXRadioButton` state. The gateway exposes `checkedObservation`; older helpers
without this advertisement cannot service a checked-state read. Use
`read("checked")`, `toBeChecked()` or its negation, or a native UI predicate with
`attribute: "checked"` and a Boolean `expected` value. This is read-only metadata
and does not authorize input or require a value-read identifier enrollment.

The native reader accepts only numeric/Boolean zero or one. Mixed state, missing
AXValue, unsupported roles and malformed responses remain unavailable, never an
assumed `false`. Readback revalidates the element scope. Office formatting still
requires a fresh uniquely selected control, a declared postcondition, and live
qualification before being claimed in its app guide.
