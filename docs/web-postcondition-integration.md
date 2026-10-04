# Web postcondition integration

The current source implements DOM observation, exact semantic press/fill,
protected reads, and several assertions for enrolled root-frame channels. This
describes source behavior; it does not establish that an installed production
Chrome runtime is enrolled or qualified. The source host enrolls an independent
protected web outcome adapter when the Chrome control backend is available.
Dispatch receipts remain unknown until the durable executor independently
verifies an explicit postcondition.

## Existing implementation

`backend/chrome/Gateway.Execute` and `ExecuteControl` implement `element.press`
and `element.fill`; they return the renderer's dispatch disposition with
`VerificationState=unknown`. `host/WebControlManager.Execute` explicitly clears
any postcondition/result verification, then retires the exact renderer lease
before returning to durable execution. The durable executor evaluates the
immutable step postcondition afterward. This order is correct: DOM dispatch is
not an independently observed outcome.

Protected `element.read` supports `value`, `text`, and `name`. `expect` supports
`toHaveText`, `toHaveValue`, `toBeVisible`, and `toBeEnabled`, including
negation. Successful reads/assertions set verification to verified, but the
ordinary `Gateway.Execute` result retains its pre-read observation rather than
exposing the actual read request/reply identity and read completion time.

Qualified Go locators are exact cardinality-one `id`, `testId`, `role` with an
optional exact name, and `label`. Frame, window and ancestor scopes are rejected;
only the enrolled root frame is qualified. Although the JavaScript DOM module
has a CSS resolver, the Go route does not qualify arbitrary CSS or JavaScript.
The shared DSL/model accepts `read("checked")` and `toBeChecked`, but Chrome does
not implement them: `Gateway.Execute` now rejects them as unsupported before
observation or transport. Missing expected values for `toHaveText` and
`toHaveValue` are rejected during step validation, with a defensive gateway
guard before transport; no nil dereference or checked-state support is implied.

The existing DOM read policy detects password/secret/token/credit-card/OTP/API-key
fields and `[data-mechanize-secret]` ancestors and returns `[redacted]`. The Go
read path refuses that value. DOM strings are whitespace-normalized and sliced
at 256 UTF-16 units without an explicit truncation marker. A generic equality
adapter must not treat a matching truncated prefix as complete evidence.

`host/native_objective.go` previously registered only `native.valueEquals` in
semantic native mode. Its source registry now adds `web.valueEquals` independently
when Chrome control is configured. A native window title is not
web document qualification or an independent DOM read.

## Exact web identity

`chrome.Identity` contains `profileChannel`, `browserInstance`, `tabId`,
`frameId`, `documentId`, and `documentGeneration`. `chrome.Document` adds origin,
title/truncation and optional tab handle. `Document.QualifiedTabID()` encodes
`profileChannel/browserInstance/tabId`.

Commands additionally bind broker epoch, channel epoch, scope hash, request ID,
deadline, and a mutation attempt/renderer lease when applicable. The broker
checks reply identity and process peer evidence. The root-document selection
route matches the verified namespace and enrolled channel and rejects ambiguous
matches; origin/title selection alone does not pin a subsequent document.

For an effect's postcondition, preserve the actual original admitted document,
not a newly selected page at the same origin or tab. DOM generation can advance
as a fill/click changes that same document. A new document ID, origin, profile,
browser, tab/frame, channel/broker epoch, extension or scope is a different
binding and must be rejected.

## Bounded backend API

New `backend/chrome/read_proof.go` provides:

- `Gateway.PinReadDocument(ctx, principal, surface)` for a standalone read. It
  selects exactly once and verifies a live non-fixture signed root-document
  channel; it must not be called after a mutation to invent a replacement pin.
- `Gateway.PinControlRead(ctx, principal, controlAuthority)` while the original
  admitted mutation authority is still live. It verifies that exact authority
  before creating its read pin.
- Opaque `ReadBinding`, with private channel/broker ownership, exact actor,
  document, transport epochs/scope, extension and signed process-birth fields.
  JSON/public plan input cannot construct it. `Identity()` returns detached
  metadata only, not proof of a read.
- `Gateway.ReadPinned(ctx, principal, binding, selector, attribute, values)`.
  It verifies the original signed channel and document, observes a fresh
  generation inside that exact document, then issues one protected read and
  checks actual reply identity plus channel/document continuity again. It never
  calls document selection, acquires control, dispatches a mutation, or executes
  scripts. It works after mutation-lease retirement because the DOM binding
  survives retirement.

The returned `ReadProof` contains actual read `Reply.RequestID`/`Reply.Identity`,
verified namespace/client/channel/extension/scope metadata, and host read start
and return timestamps. It contains no read value, receipt-derived success or
fabricated transport headers. It retains the actual origin from the trusted
pinned document/inventory, since the current read reply has no separate origin
field. Signed peer/process birth and inventory continuity are rechecked at the
wire gate and after the read.

The API refuses redacted/missing values, unsupported attributes and values at
or above the current 256 UTF-16 truncation boundary. That conservative boundary
avoids claiming complete equality without changing existing protected-read
policy or the DOM protocol. A future raw/long-string read requires explicit
qualified truncation/completeness evidence; this change does not provide it.

## Enrolled objective adapter

New `objective.NewWeb(WebRead)` provides only `web.valueEquals`, with maximum
observational authority. The typed callback receives the exact selector,
attribute and expected `WebIdentity` and returns a value plus `WebEvidence`.
The host callback compares that expected metadata with the opaque original pin,
uses `ReadPinned`, and converts its actual proof. It must never reselect by
origin or substitute a new document.

Closed predicate inputs are profile/browser, origin, numeric tab/root-frame,
document ID/minimum document generation, extension origin, broker/channel
epochs/scope hash, qualified strategy/selector/optional role name, attribute and
expected string. Protected reads remain value/text/name only. The adapter
requires matching actor, exact identity, a nondecreasing fresh generation,
actual request identity and timed evidence, and refuses redacted/truncated
values. Evidence references contain identity/request metadata, not the observed
value. Existing evaluator freshness/authority checks remain mandatory; UI
equality cannot establish business success or prove absence of a prior effect.

## Host/durable handoff source implementation

`host/productionWebControl` now captures the opaque read binding while actual
control admission is active and puts a private closure over it in readiness.
`WebControlManager.Prepare` retains it in the original private intent context.
Confirmed dispatched completion and exact lease retirement admit the later read;
uncertain cleanup, shutdown and replay keep it blocked. The active authority map
can be removed on retirement because the context retains the actual original
read binding. A wire predicate's identity fields constrain that trusted pin,
not replace its provenance.

`host/readWebPredicate` verifies namespace/client, original Endly metadata and
consent binding, configured web-origin ceiling and original expected document/
channel before obtaining exact observe consent and calling `ReadPinned`. It
rejects changed actual proof and protected output. The existing `nativeObjective`
factory now assembles independently available native and web adapters, preserving
native registration without coupling web availability to native semantic mode. No
scheduler or receipt-to-success shortcut is needed: existing Endly/durable
postcondition evaluation already performs the independent read before the
confirmed effect/milestone commit.

For the local fixture, fill a short nonsecret field and verify its protected
`value`; press an exact button and verify a short output element's `text` in the
same document. Avoid navigation, user-activation-only controls, checked-state
assertions and long strings for this bounded proof. Signed peer/profile/executor
qualification, visible enrollment, per-step consent, durable intent/outcome,
actual DOM postconditions and cleanup must all be verified. Neither a native
Chrome title nor a returned DOM dispatch receipt substitutes for those gates.

Previously recorded host source verification passed focused web
control/postcondition/generated-intent tests, the same suite under the race
detector, and host vet. Host tests use real Endly callbacks with inert providers
and prepared data invocation contexts; they prove independent post-retirement
read verification and no replay, not live Chrome qualification. The
unsupported-checked regression cases are source-level gateway tests; neither
they nor the loopback fixture establish installed extension enrollment or a
real Chrome DOM read. Deployment and real browser verification remain separate.
