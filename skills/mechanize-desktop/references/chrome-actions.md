# Typed Chrome actions

Check `mechanize_browser_status` and `mechanize_capabilities` before using a
browser adapter. `web:localPlaywright` means the local relay is configured and
the connected worker advertises it. It does not prove that a particular website
or action succeeds. Use a fresh opaque tab handle from `mechanize_browser_tabs`.

If the requested approved origin has no tab, use `mechanize_browser_open_origin`
with the owned session and a unique `clientRequestId` to open its HTTP(S) origin
root in a new background tab. It needs no existing document and preserves other
tabs. Use the returned opaque handle; reuse the same request ID to inspect a
pending or unknown result, never create another tab to retry uncertainty.

Playwright runs inside the local runtime. MCP callers use Mechanize's typed DSL;
they do not send JavaScript, CDP commands, credentials, or a browser endpoint.
Accessibility and native frame clicks remain separate advertised routes.

## Locator grammar

Require `exact: true` for mutations. Prefer a unique observed role and name,
label, ID, or a documented application test ID. A role without an accessible
name can still be selected exactly, but inspect its cardinality first.

```text
web.tab(origin:"https://example.test").getByRole("button",name:"Review",exact:true).click(timeout:3s)
web.tab(origin:"https://example.test").getByTestId("message-input",exact:true).fill("Public test message",timeout:3s)
```

When the page deliberately repeats an identical control, refresh the observation
and bind its position explicitly. Indexed actions require `web:indexedQuery`.

```text
web.tab(origin:"https://example.test").getByRole("button",name:"Expand row",exact:true).nth(1,order:"document").click(timeout:3s)
```

`nth(1)` alone is rejected. Native indexed queries use their own advertised order;
do not substitute native tree order for Chrome document order. Ancestor/within
queries and collecting all matches are not implied by indexed-query support.

The Playwright adapter currently qualifies ordinary public text inputs and
textareas for fill, and public elements for click. Credential entry uses the
separate Vault operation. Contenteditable editors and special input types may
be unavailable; check the returned code instead of treating them as textareas.
Use a unique ID/test ID for value postconditions where possible: indexed text
reads do not imply indexed value reads are supported by every adapter.

## Durable workflow envelope

The DSL examples above show syntax. On the durable host, give every mutation an
exact typed `effect.businessKey` in a JSON/YAML workflow envelope. Declare any
postcondition adapter in `requires.adapters`; a declared adapter must already
be enrolled. A public value postcondition uses the `web` adapter's `valueEquals`
predicate, with a surface reference, exact origin, selector, attribute and typed
expected value. An expectation never grants authority to read another document.

For an observed element ID, use `strategy: "id"` and `selector` containing that
ID. The predicate has no `id` input. DOM equality provides `observational`
authority; requesting `authoritative` is invalid. With `fixture` bound to the
selected tab in the envelope's `surfaces`, a public fill postcondition is:

```json
{
  "kind": "adapter",
  "adapter": "web",
  "name": "valueEquals",
  "scope": {"surfaceRef": "fixture"},
  "timeoutMs": 3000,
  "freshnessMs": 3000,
  "requiredAuthority": "observational",
  "inputs": {
    "origin": {"kind": "string", "string": "https://example.test"},
    "strategy": {"kind": "string", "string": "id"},
    "selector": {"kind": "string", "string": "message"},
    "attribute": {"kind": "string", "string": "value"},
    "expected": {"kind": "string", "string": "Public test message"}
  }
}
```

Use this object as the step's `postcondition`. Validation rejects an invalid
contract before input; it does not establish the outcome of an older attempt.

DSL timeouts are duration literals such as `timeout:3s`, not strings such as
`timeout:"3s"`. Workflow step deadlines are integer `timeoutMs` values. Validate
syntax and the closed workflow schema before dispatch.

A successful click receipt proves input dispatch. Verify the next page state
or application outcome independently. A dispatched action without a suitable
postcondition may stop as an unresolved durable effect. Do not repeat it merely
because the operation's overall execution status is `failed`.

## Short observation loop

After choosing an item in a menu or popover, observe whether it closed before
filling another control. Some single-selection menus deliberately remain open
and trap focus. A selected label alone does not establish that the composer or
form field can receive input. If the menu remains open, dismiss it through its
observed control and verify dismissal before filling. Do not repeatedly fill a
field to overcome a focus trap.

Keep execution dispatch separate from business verification. An unknown
business outcome does not itself prove uncertain input. Conversely, an empty
field does not prove that a previous attempt was not dispatched. Use the exact
owned attempt's typed result or receipt; preserve unresolved history and never
derive a retry decision by parsing an error message or guessing from page state.

Chrome document actions can run in the background. Do not activate a tab merely
to perform a read or click, or insert activation into a working form workflow
solely to make automation visible. When the user explicitly needs to see the page, use
`mechanize_browser_activate_tab` with its observed opaque handle and approved
origin. This browser-level action remains usable during credential protection;
it does not read page content, release protection, or submit a form. Reuse its
client request ID to inspect an uncertain activation instead of replaying it.

An unknown activation remains unknown in its original run. With the
`visibilityUnknownVersion: 1` worker capability, the broker can independently
qualify a fresh DOM operation by checking the exact retained terminal receipt
and a drained input lane on the original Chrome process. This is a read-only
proof, not a repeated activation. Browser status preserves `unknownCount` and
reports proven cases separately in `visibilityUnknownCount`; a nonzero original
count alone therefore does not establish that all DOM work is blocked.

Let the server perform that qualification for the required fresh DOM operation.
Do not resume the old run, repeat activation, or apply this exception to an
uncertain click, fill, credential operation, or native input. Missing receipts,
including after extension reload, cannot qualify this path. Older workers may
still quarantine the browser. A screenshot showing the tab does not prove the
original dispatch. Preserve history; any independently qualified new executor
starts a different workflow, without resolving the old outcome by assumption.

Before diagnosing a login result, check the exact target tab rather than the
currently selected tab. `mechanize_browser_tab_location_matches` compares an
expected public origin and optional pathname without returning the actual URL,
query, fragment, title, or credentials. For example, a known `/login/error` path
can distinguish an error route from an assumed dashboard. A mismatch is not
proof of login success. The older focused-origin comparison checks only the
selected tab's origin and cannot diagnose a background tab's path.

`privacyReady` is permission to use the qualified redacted DOM, not evidence of
authentication. Verify an application-specific dashboard/history marker before
continuing. If private status becomes unavailable, inspect the original attempt
and supported metadata; do not resubmit credentials or launch a repeated login
loop merely because content access is denied.

Keep the original credential preparation's session, consent grant and purpose
text unchanged for subsequent redacted observations and plans. The current
host verifies the complete consent binding, including purpose; changing only
the descriptive purpose can produce a protected-delivery refusal even when
private status says `privacyReady`. Reuse the original binding rather than
starting another login. Use step names for changing per-action descriptions.

Start with a three-second action deadline and inspect the operation result and
fresh scoped state. Avoid a fixed sleep after every action. If a page is still
loading, observe its declared readiness instead of issuing the same input again.
For an explicit pre-input rejection, correct the reported locator, capability,
or transport issue. For `unknown`, inspect the original receipt and use the
host's recovery/reconciliation tools.

Playwright failure diagnostics may report closed phases, callback/peer-check
counts and elapsed milliseconds. These are performance evidence, not permission
or effect proofs. Do not ask for page values, logs containing credentials, raw
CDP responses, or child-process stderr to diagnose a failure.

For a native screenshot fallback, first confirm the requested app is foreground.
A captured background window can look complete while a different app occludes
the click. Use a fresh one-use frame permit and original integer image pixels;
never infer keyboard authority from a screenshot. If the native click is blocked
by policy or private-entry protection, correct that issue rather than bypass it.

For Chrome's public address bar, prefer an exact native accessibility `fill`
on the observed `Address and search bar` textbox to replace its entire value.
Native `fill` does not imply keyboard focus. Explicitly `focus` the observed
textbox and verify its `focused` attribute before pressing Enter. Activate
Chrome immediately before the key step in the same bounded workflow; an earlier
activation is only momentary evidence and does not authorize later keyboard
input. Verify navigation using the freshly observed exact page title, including
any version suffix on extension setup pages.
`typeWindowText` appends to the current selection and can partially dispatch
before a later focus/window check fails. Never infer an untouched field from
the final error alone. Verify the public address before pressing Enter; do not
use this route for credentials.

Refresh `mechanize_capture_windows` before a native key action. Chrome's address
suggestions may be a separate top owned window with an empty title. The main
window ID can therefore be rejected even when its address bar appears focused.
Use the freshly observed exact window identity; do not relax ownership or
foreground checks. After navigation, switch back to the qualified web adapter.

When the extension is disconnected, native Accessibility can still fill public
Chrome inputs. Scope using the AX-reported window title: it can include the
browser/profile suffix even when physical window inventory reports only the
page title. A matching physical title is not proof of an AX scope match.

Inspect the fresh node's advertised actions before selecting semantic press.
Chrome can expose a button without AXPress. An explicit unsupported-action
rejection before dispatch allows a fresh screenshot click under the existing
frame-click qualification. Verify the page result independently. External
verification does not reconcile an unresolved Mechanize effect; the original
plan should declare an appropriate broker postcondition wherever available.
