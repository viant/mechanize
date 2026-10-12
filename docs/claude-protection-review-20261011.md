# Claude protection and recovery review — 2026-10-11

Source-only review by Claude Fable 5.1, fast mode disabled. Duration: 532007 ms. No credentials or live browser content supplied. Findings below are reviewer claims, not accepted proof of end-to-end defects.

## Maintainer disposition

- Reject re-dispatch of an intent with a missing receipt, including after extension reload. Missing evidence does not establish that the original action did not happen. Preserve original UNKNOWN and deduplication.
- Reject deleting uncertainty indiscriminately: a receipt proving DOM-lane quiescence does not prove safe native focus or justify replay. Maintain typed per-attempt scope and independently qualified target actions.
- Do not remove epoch/fence binding as an unreviewed shortcut. A read-only recovery query may carry original binding plus current authenticated authority without reusing stale dispatch authority.
- Write-once receipts and authenticated negative-reply preservation have source fixes and focused tests; not yet deployed.
- Validate cross-origin, reopened-login-route, iframe and retention observations against complete call paths before changing protection. The supplied snapshot did not include every protection/redaction gate.
- No elapsed-time assumption proves quiescence. Pending API promises require actual terminal execution evidence and serialized admission.

## Reviewer output (untrusted analysis)

The repository is not present under this working directory, so this review is source-only on the snapshot you supplied.

**Verdict.** The snapshot cannot recover from a single lost activation reply. Three independent locks wedge the channel until Chrome restarts, and the proposed replay path cannot run until all three are fixed. Receipts are not write-once, so the replay itself needs a fence before it is safe. The proposed design is sound after those fixes. Terminal receipt plus an idle lane is sufficient for content-script DOM work and is strictly necessary only for native input. The protection boundary has two real gaps: a live record stops protecting the source tab on the first cross-origin hop, and a retired route is protected in one tab only.

## Proven defects, highest priority first

- **Lost reply wedges the channel until native host restart.** A lost reply adds the attempt to the unknown map in executeBrowserOperation, and nothing in the snapshot removes it. PrepareActivateTab, controlMetadataSnapshot and RetireControl all require that map empty. So the replay that would fetch the receipt is refused as busy, every DOM action is refused as unqualified, and the lease cannot retire.

- **After a native host restart, replay is permanently impossible.** The fingerprint at `extension/chrome/tab-metadata.js:32` includes brokerEpoch, channelEpoch and scopeHash. A host restart changes the broker epoch, so the same attempt replays as attemptConflict and never reaches the stored receipt. Every new attempt then hits the quarantine on line 35 because the old intent has no receipt. Only a Chrome restart clears that state. Epochs belong in the reply fence, not the idempotency key.

- **Intent without receipt can never resolve.** The replay branch on line 34 returns receiptUnavailable when the intent exists and the receipt is missing, and it never dispatches. Service worker death between intent store and receipt store is the realistic cause of a lost reply, so the common case has no resolution path even after the two fixes above.

- **Receipts are not write-once.** Line 54 stores dispatched, then the check runs. If the deadline passed during the storage round trip, the catch on line 56 overwrites it with unknown. Any concurrent replay writer races the same key.

- **The deadline is one instant for three parties.** The Go context, the frame deadline and the decoder's rejection deadline are equal. executeBrowserOperation also spends part of its 3 second budget on admit, two binding readbacks, the commit and a process check before writing the frame, so the extension sees the remainder and polls to within 1 ms of it.

- **Authentic terminal replies are downgraded to unknown.** After a decoded reply, a failed process check or changed epoch calls the unknown closure. This applies to dispatched and to notDispatched replies, both of which were already authenticated by request fences and the pending connection.

- **Protection records are append-only with a hard cap.** Capture throws scopeLimit at `extension/chrome/protection-scopes.js:63` at 256 records, and retire only flips a flag. Records from dead browser instances can never match an identity, yet they count toward the cap and keep boundOrigin true forever. Credential flows stop working permanently after the cap.

- **A live record does not protect its tab across a cross-origin hop.** protects on line 15 requires record origin to equal document origin even when the record is not retired. A login page that redirects the same tab to an OTP or SSO page on another origin leaves that tab unprotected immediately, before any absence proof.

- **A retired route is protected in one tab only.** Retired records require tab equality, so the same login route opened in another tab is unprotected. Browser autofill or a human can place the secret there. The route string is already stored, so this is a policy gap rather than a data gap.

- **Only the outermost frame URL is checked.** target and disjoint evaluate the root frame only, although getAllFrames already returned every frame. A same-origin child frame on the login route inside an unprotected parent passes.

Smaller confirmed items: the `error?.dispatchState` branch on line 35 is dead; match reports no active or focused field; the lease action browser.activate and the native lane action browser.activateTab are different actions and must never share a classification.

Hypotheses that need verification outside the snapshot:

- commitActivationBinding on a replay of the same durable attempt probably rejects a duplicate immutable row before the frame is written. Replay needs readback-equal idempotence inside the Datly component. No migration is needed for that.
- PinReadDocument, captureReadBinding and ReadPinned never call guardCredentialPrivacy. Unless selectDocument or the broker call path applies protection, a read of a retained login document reaches the executor and relies on renderer redaction alone.
- Whether the channel struct and its unknown map survive an extension reconnect. If a new channel is created, the in-memory barrier vanishes while the durable UNKNOWN remains, which is only safe if the durable barrier gates dispatch.
- With a login document in BFCache, getAllFrames likely returns two outermost frames and root throws scopeInventoryUnavailable. That fails closed, which is correct, but it means target and disjoint are unavailable for that tab until eviction.

## Boundaries, quiescence, and the simpler design

**Minimum correct boundary.** Two phases, decided by the record's retired flag.

- Live phase: the whole source tab, any origin, any document, every frame, until the Host explicitly retires. This covers OTP, reauth, cross-origin redirects and in-tab navigation without inferring anything from URLs.
- Retired phase: the exact original documentId in any tab and any lifecycle, plus every known login route in any tab, evaluated against every active frame of the target tab. This covers BFCache restore, autofill on a reopened login page, and route-level reauth.
- Retirement trigger: the Host decides the credential flow ended, then proveSourceAbsent passes twice as today. A navigate that quiesces the renderer lease must not retire the record by itself.
- Fields: document-level protection is the minimum. Field-level redaction in the executor for password, one-time-code and payment autocomplete tokens is defense in depth. Host-side equality redaction of read results against secrets used in the session catches reflection on later pages and needs no extension change.

**Quiescence.** Every receipt written by activate is preceded by settled awaits: tabs.update and windows.update are each awaited before the next statement, and the catch runs only after a settled or rejected await. So an authenticated receipt of any state proves no mutating Chrome call from that attempt is still pending. Only a missing receipt, or a rejected update, leaves real native uncertainty. That is why the missing-receipt case needs idempotent re-dispatch and why the receipt, not elapsed time, is the fence.

An unknown receipt written after the updates settled leaves only OS focus unresolved. That is harmless to content-script DOM work on another document. It is not harmless to anything that depends on which tab or window is in front: the closed pointer adapter, keyboard injection, visible-tab capture, and badge placement. So the precise rule is: the DOM lane may proceed on any authenticated receipt; the native input lane requires dispatched or notDispatched; the dependency barrier keeps the durable UNKNOWN regardless.

Elapsed time has exactly one legitimate use: the Go side must not send a replay before the original deadline plus a grace window, because the original worker may still be writing its receipt. That protects write-once ordering, not quiescence. The race to fence is two activate invocations under one intent writing the same receipt key. Write-once receipts and the existing single openOriginPending per channel close it.

**Simpler viable design.** Keep the global map, type its entries, and let the replay through. The entry carries the server-set action from prepareBrowserOperation. openOriginIdle admits exactly one request: the replay whose attempt equals the single activation entry. On an authenticated terminal reply for an entry, delete the in-memory entry and leave the durable attempt and the stored receipt untouched. The DOM gates then need no change at all, because the map is empty once the receipt exists. The extension re-dispatches only when the stored intent action is browser.activateTab and no receipt exists. Nothing here needs the binding table, and nothing touches the database schema.

## Small implementable changes and tests

Changes, in order:

1. `extension/chrome/tab-metadata.js:32`: drop the three epochs from the fingerprint; keep them in the reply shape.
2. Line 34: when the intent exists, the receipt is missing and the stored action is browser.activateTab, continue to dispatch with the intent flag set and skip the intent store.
3. Lines 54 and 56: write-once. Re-read the receipt key before any store, never overwrite an existing receipt, and return the existing one instead.
4. Line 51: stop polling at deadline minus 150 ms. In open_origin.go, send a frame deadline that is the context deadline minus a grace window, and accept decoded replies until the context deadline.
5. open_origin.go: store the action in the unknown map; add the replay carve-out to openOriginIdle; take the result from the authenticated reply even if the later process check fails; delete the map entry on a terminal reply.
6. `extension/chrome/protection-scopes.js:15`: live records match on tab only; retired records match on documentId in any tab or on route in any tab. Lines 55 and 69: run protects over every active frame of the target tab.
7. Line 63: at the cap, evict retired records whose browserInstance differs from the request identity; throw scopeLimit only if nothing is evictable.
8. Host barrier: classify from the immutable step action, never from the effect class the wrapper assigns.

Negative tests, each asserting the refusal or the preserved state:

- Lost reply, then a different attempt: still refused busy. Same attempt: admitted as replay. Both before any receipt.
- Host restart with new broker epoch: replay returns the stored receipt, never attemptConflict.
- Worker killed after intent store: replay dispatches exactly once and writes one receipt; DOM gate refuses until that receipt lands.
- Deadline passes during the receipt store, with a concurrent replay: stored receipt stays dispatched; replay returns it.
- Focus never true: receipt unknown with crossed set; DOM step on another document allowed; native input refused; second new activation refused.
- Authenticated notDispatched followed by changed process evidence: notDispatched, map unchanged.
- Live record, same tab navigates cross-origin: target returns scopeTargetProtected.
- Live record, OTP route in the same tab: protected. Retired record, same route in another tab: protected. Retired record, other route in the same tab: unprotected.
- Back navigation restores the login document from BFCache: absent and retire return scopeSourcePresent; target on the restored document is protected by documentId.
- Child frame on the login route under an unprotected parent: target protected.
- 256 records with retired prior-instance entries: capture succeeds by eviction. 256 live current-instance entries: scopeLimit.
- Corrupt storage.local: load throws and every scope response fails closed; confirm callers refuse the credential flow rather than proceed unprotected.
- Read of a retained document without a control lease: refused, which checks the read-path hypothesis above.

**Recovery after extension reload.** Session storage is cleared on reload, so intents and receipts for any in-flight attempt are gone while local records survive. The extension can never produce the original receipt. The only resolution is a Host-driven replay of the same durable attempt, which re-dispatches as a fresh intent. That receipt proves the replay, not the original, so the durable record stays UNKNOWN and verification comes only from a fresh metadata read showing the expected tab active. The native host's in-memory map survives only if the native host survived.

**Credential retention.** The extension never stores secret values. Renderer redaction state lives in the document's process for the document's lifetime, and BFCache extends that lifetime, which is why documentId protection in every lifecycle matters. Local records hold cleartext login routes indefinitely; routes are not secrets but they profile the user's institutions, so eviction by browser instance and a per-origin cap are the right retention controls.
