# Independent source review — 2026-10-11

Model: claude-fable-5-1. High effort; source-only, no tools or private data.
Elapsed: 546 seconds. Findings below are reviewer hypotheses, not accepted defects.

## Initial validation

- Confirmed and unit-tested: engine busy flag was set after an awaited fingerprint, permitting concurrent admission. The lane is now acquired before the await; no live acceptance claim.
- Confirmed and tested: role candidate list omitted several semantic HTML elements; unnecessary accessible-name work applied to direct locators. Discovery is bounded and complete across semantic tags; projection is lazy and errors remain typed.
- Corrected reviewer reasoning: installed dom-accessibility-api has no asserted placeholder fallback. Actual Chrome comparison nevertheless confirmed that Playwright adds one and Mechanize did not. A narrow public text-control fallback now passes the parity fixture, with private-value checks retained.
- Observation patch: visible controls precede structural nodes within the existing output bound. Tests cover a late search control after 130 structural nodes. Existing documents require a fresh load; this is not yet a bank-flow result.
- Rejected as proposed: evicting successful attempt receipts without durable deduplication could replay an old attempt.
- Retirement/recovery recommendations require full authority and receipt analysis before any change.
- Bank acceptance remains incomplete: login and history navigation succeeded; November draft has not been prepared.

## Reviewer output (unverified)

Review complete. Findings are ordered by impact on ordinary authenticated workflows, each marked proven or question, with a minimal fix. I did not edit or execute anything.

## Priority 1: blocks ordinary authenticated workflows

1. **Shadow DOM targets always read as obscured.** `protocolClickPoint` in `extension/chrome/dom.js` uses `doc.elementFromPoint`, which retargets hits inside open shadow roots to the host. For an element inside a shadow root, `hit===el||el.contains(hit)` is false, so every web-component control fails with `targetNotActionable`. Proven. Fix: descend from the hit through `hit.shadowRoot.elementFromPoint(x,y)` until it stops changing, then compare.

2. **Smooth scrolling defeats the settle check.** `protocolClickPoint` calls `scrollIntoView` without `behavior:'instant'`. With CSS `scroll-behavior: smooth` on `html`, which Bootstrap 5 sets by default, the `before` rect is captured pre-scroll and the `after` rect mid-scroll, so off-screen targets always fail "did not settle". Proven. Fix: pass `behavior:'instant'`.

3. **A regex-matched container hides its whole subtree.** `clone` in `extension/chrome/accessibility/provider.mjs` returns early for any `policy.secret` element, and `secret` in `dom.js` matches `login|token|authorization|captcha|security.?code` on `id`, `name`, `title` and `aria-label` of any element. A wrapper like `<div id="loginForm">` or `<nav aria-label="Login menu">` therefore removes all descendants from the projection, so every role and label locator inside reports `projectionUnavailable`, and `taintAncestors` strips names from `form`, `main`, `dialog` and `body`. Proven. Fix: prune the subtree only for `[data-mechanize-secret]` and for form controls; for other regex matches redact the element's own attributes and keep cloning children, since each child is evaluated by `secret` itself. Taint only ancestors whose role allows name from content.

4. **Placeholder-named inputs lose their name.** The `attributes` allowlist in `provider.mjs` omits `placeholder`, `aria-placeholder` and `option[label]`. dom-accessibility-api's input name fallback reads the placeholder attribute, so search boxes and login-adjacent fields that rely on it now resolve with no name. Proven by the allowlist; the library fallback is well established. Fix: add `placeholder` and `label` to `attributes`. The `safe` redactor already covers them.

5. **Projection limits abort every action, with wrong error codes.** `createProjection` throws a bare `Error('projectionLimit')` at depth 65 or 20000 nodes including text nodes. `withProjection` builds the projection for every `resolve`, including `id`, `testId` and `css` locators that never need a name, so large or deep pages lose all DOM actions and the error is not a `MechanizeProtocol` error. The shared `styleReads` budget also trips inside `resolveProjected`'s filter, where the catch rewrites it as `invalidLocator "CSS selector could not be parsed"`. `label` strategy computes names for `*`, and `role` strategy computes names before checking the role, so a few thousand elements exhaust the budget. Proven. Fixes: build the projection lazily only for role, label, snapshot and `read name`; check role and skip the name when no name is requested; convert `projectionLimit` to `coverageIncomplete` and rethrow protocol errors unchanged from the filter catch; in `snapshotProjected` catch per node and emit `name: undefined`.

6. **Role candidate selector is incomplete.** `selectors.role` in `resolveProjected` lists `h1,h2` only, and no `nav`, `main`, `dialog`, `li`, `table`, `option`, `fieldset` or `h3`-`h6`. Locators like `role=heading` for an `h3` return `targetNotFound`. Proven. Fix: query `*` and filter by `role(el)===expected` first, within the existing inspection bound.

7. **Post-handoff re-quarantine is dead code.** `protectedDocument` returns false whenever `privateText` is set, so the `privateText ? unsafePrivateInput : secret` branch never selects `unsafePrivateInput`, and the post-dispatch check in `act` never fires. In single-document SPA logins, an OTP or re-authentication step appearing after handoff keeps the document fully public except for individually matched fields. Proven. Fix: delete the early return and let the ternary run as written, or delete `unsafePrivateInput` and the comment that promises it.

## Priority 2: correctness, recovery and concurrency

8. **Gateway can wedge permanently.** `RetireControl` in `backend/chrome/control.go` sets `controlRetiring=true` and then returns on any failure without clearing it. If the pinned document is gone, because the tab closed, navigated, or the channel connection was severed by `ManualCredentialTransition.Abort`, `controlCheck` with `retirement=true` fails forever on "Pinned document changed" or `c.conn == nil`. Every `AdmitControl` then returns `authorityRetiring` and every `ExecuteControl` returns `staleAuthority`. Proven from the shown code. Question: is there a channel-disconnect hook elsewhere that resets `g.control`? Fix: when the channel is idle, inventory is complete and the pinned document is absent, treat retirement as proven and release; also reset `controlRetiring` on failures that occur before `executor.retire` is written.

9. **Lease identity includes mutable document fields.** `sameControl` compares `a.Document == b.Document` and `controlCheck` requires `d == a.Document` for dispatch. `Document` carries `Title` and `TitleTruncated`. If the broker updates `c.documents` titles from inventory messages, an SPA that changes `document.title` after a click retires the lease and the same actor's re-admission reports `authorityBusy`. Proven-conditional on inventory updates. Fix: compare `Identity` plus `Origin` and fingerprint version, not the whole struct.

10. **Engine busy guard races across an await.** In `browser/playwright/engine.mjs` `execute` checks `this.#busy` and then awaits `fingerprint.mutationV2` before setting `#busy=true`. Two concurrent calls both pass the check and both reach the attempts dedupe with no prior recorded. Proven. Fix: set `#busy=true` and `ownsBusy=true` immediately after the check, before any await.

11. **Attempt map never evicts.** `#attempts` caps at 256 and is never pruned, so after 256 mutations the engine denies all further mutations with `playwrightAttemptCapacity` until restart. Proven. Fix: evict entries whose receipt persisted successfully, oldest first, keeping only uncertain results.

12. **Playwright timeouts are misclassified.** `target.waitFor`, `fill` and `click` timeouts throw Playwright errors without a `playwright*` code, so the result is `playwrightUnavailable` instead of a target or deadline code. Callers cannot distinguish "no such element" from "engine down". Proven. Fix: wrap those calls and rethrow `denied('playwrightTargetDenied')` or a dedicated deadline code.

13. **Admission may return success with an empty authority.** `AdmitControlWithStatus` returns `ControlAdmission{}, err` where `err` is `reply.Error` from `releaseRejectedAcquisition`. If that error is nil, `AdmitControl` returns a zero `ControlAuthority` and nil error. Question, since `releaseRejectedAcquisition` is not shown. Fix: substitute `staleGeneration` when `err == nil` on that path.

14. **Manual exchange swallows unrelated inbound messages.** `acceptManualCredentialLocked` in `backend/chrome/credential_manual.go` consumes every message except `type:"documents"` while `manualPending` is set, for up to ten seconds. Any other event or late RPC reply on the channel is dropped and cleared. Question: which message types can arrive in that window? Fix: consume only `credentialTabAbsentResult` and `credentialManualPrivacyResult` and return false otherwise.

15. **Abort severs the channel before anything was sent.** `BeginManualCredentialPrivacy` calls `t.Abort` when the first `check` fails, for example when the caller's context is already short of the deadline, and `Abort` closes the extension connection. Nothing in flight could be ambiguous at that point. Proven. Fix: record a `sent` flag in `exchange` and close the connection only when set.

16. **Credential bytes linger on one error path.** In `exchange`, the size check `len(raw) > 128*1024` runs before `defer clear(raw)`, so an oversize encoded payload returns with the credential still in the buffer. `encodeManualCredentialSeed` also converts the password to an immutable Go string that cannot be cleared. Proven, low likelihood. Fix: register the clear before the size check and marshal through a `json.Encoder` on the byte slice.

## Priority 3 and residual risks

- **Flattened ids collide.** `provider.mjs` clones shadow-tree elements with their `id` into one document, so a light-DOM `aria-labelledby` or `label[for]` can resolve to a shadow-internal element with the same id. Fix: drop `id` and `for` on clones whose source root is not the document.
- **Text nodes directly under a shadow root do not taint the host** because `taintAncestors(source.parentElement)` receives null. Fix: fall back to `getRootNode().host`.
- **Names over 256 characters** are now unsupported rather than truncated, so long link text resolves with no name.
- **Zero-authority `controlChannel`** in `executeControl` is passed to `broker.call` for element actions without a nil check. Low likelihood race.
- **Lock order.** `Qualify` holds `controlMu` then takes `broker.mu`. No reverse order appears in the shown files, but any unshown broker code taking `controlMu` under `broker.mu` would deadlock. Question.
- **Packaging recovery.** `replace` in `scripts/extension_package.py` refuses to repair a corrupted target because `inventory(target)` must match a known set first, and orphan `.extension-previous-*` and `.extension-stage-*` directories are never cleaned after a crash. Fix: remove owned orphans at start and allow replacement when the target fails inventory but the parent is owned.
- **Universal helper binaries.** `runtimeHelperBrokerPin` in `security/keychain/migration_artifact_contract.go` uses `macho.NewFile`, which rejects fat binaries. If signed helpers are universal, migration pin extraction fails everywhere. Question.
- **Document size cap.** `walk` in `dom.js` stops at 2000 elements and incomplete coverage quarantines the document permanently. Most authenticated dashboards exceed that, so all public DOM actions return `secureDocumentRequired`, and `privateLayoutReady` can never succeed for the manual handoff. I cannot tell from the supplied text whether this bound is new, but it is the single largest workflow blocker if it is.
- **Packaging wiring is unverified.** The manifest content-script list and the bundle that sets `globalThis.MechanizeAccessibility` are not shown, and `version='dom-accessibility-api@0.7.1'` is a hard-coded string that can drift from the installed dependency.
- **Main-world guard.** `targetGuard.publicTarget` runs via `element.evaluate` in the page's world, where page scripts can override DOM prototypes. It only gates non-credential fills and redacted reads, so exposure is limited, but it should not be treated as a privacy control.
