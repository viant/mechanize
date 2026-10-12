# Native queries and outcome checks

Use the live MCP contract and capability policy before choosing a route. Source
support does not prove that the installed broker advertises or admits it.

## Exact window boundaries

Use named window options, for example
`excel.window(title: observedTitle, role: "AXWindow")`. Keep the same title and
role in a native result predicate's `windowTitle` and `windowRole` inputs.
An omitted role and an explicit role are different declared boundaries under
durable admission, even when both currently identify the same window. Current
source validation rejects this mismatch before dispatch.

For actions that open another window, select a supported route whose declared
scope admits that transition. Do not rewrite the predicate of an existing
unresolved run to accommodate the window that appeared.

## Private text comparisons

Use `native.literalValueMatches` for an exact expected text value. It compares
locally and returns boolean evidence, without exporting the AX value. A
`native.valueEquals` read of an unqualified value can return unknown even when
the field is present and writable. Do not treat that as permission to read or
log the field through another channel. Credentials must come from opaque Vault
references; never supply them as literal expectations.

Boolean JSON values use `{"kind":"boolean","boolean":true}`. An element
being enabled, a successful key dispatch, or an unchanged title does not verify
the intended document edit.

## Anonymous and duplicate controls

An indexed role query uses an explicit order, for example
`.getByRole("AXPopUpButton", exact: true).nth(0, order: "tree")`. It requires
fresh PID/birth identity, an exact window, a complete AX tree and the advertised
`native:indexedQuery` capability. Use the observed tree order, not an index
remembered from another app launch. Mutation consent and target qualification
remain required after selecting a control.

The disposable Excel Sort dialog exposed the Region menu item along two native
containment paths. A whole-dialog Region locator was therefore ambiguous. Do
not choose a duplicate by its label or presume that two paths represent one
object. Qualify a unique scoped selector or a fresh capture-bound target before
selection. The original popup-opening predicate remains unresolved; neither
sorting nor saved row order has been qualified by this observation.

The installed broker omitted indexed-query capability discovery despite gateway
support. The source policy now advertises it only with fresh Accessibility and
exact-window support, and removes it when either is unavailable. Deploy and
rediscover before relying on that correction. A predispatch capability rejection
can justify an already-authorized, supported pointer route; an unknown dispatch
cannot justify replaying the same input through another route.

## Foreground and focus

Do not use an AX window's `focused` value as a general test of whether its app is
foreground. The Excel Sort window reported false while an independently
qualified frame capture succeeded after activation. Preserve the original
activation predicate and its unknown result. Use the runtime's foreground,
ownership and recipient checks for capture/input, and a freshly observed exact
control for a focus-dependent shortcut.
