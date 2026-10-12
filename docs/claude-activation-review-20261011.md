# Activation recovery review — 2026-10-11

Claude Fable 5.1, high effort, source-only. Duration310seconds; checked after requested five-minute minimum. Recommendations remain subject to full-source validation.

I'll review the supplied design and snapshot statically, without running or editing anything.

**Verdict.** The fixture failure is a measurement defect, not real uncertainty. The polling fix removes the common case, but three defects in the same path still produce spurious UNKNOWN. The over-quarantine comes from classifying tab activation as an external non-idempotent effect in the host wrapper. The visibility-scoped alternative is sound and materially simpler than the binding-table plus finalizer design, and it is the fastest correct path. The proposed recovery design cannot be built on the supplied surface yet. The fresh-executor route is safe only with exact-birth retirement proof, and it adds nothing the existing per-run gating does not already allow.

## Proven defects in the snapshot

- **Deadline race drops real successes.** The Go timeout, the deadline sent to the extension, and the decoder's reply-rejection deadline are the same instant. The extension polls until one millisecond before it, then writes storage and sends. Any reply in the last round-trip is rejected in acceptOpenOriginLocked or loses the select on the context. Fix: extension stops polling at deadline minus a margin, and the decoder accepts replies until deadline plus a grace window. This is safe because the extension's check function forbids any Chrome API call after the deadline, so a late reply only reports pre-deadline observations.

- **Dispatched receipt is overwritten with unknown.** At `extension/chrome/tab-metadata.js:54` the receipt is stored as dispatched, then the check runs. If the deadline passes during the storage round trip, the catch block at line 56 rewrites the receipt as unknown. A later replay then returns unknown for an activation that verifiably succeeded. Receipts must be write-once. Set a flag after the first successful store and skip the catch-block store when it is set.

- **Focus never true is reported as unknown.** The loop at line 50 requires OS window focus. On macOS, Chrome can accept windows.update while the OS declines app activation, for example during a modal from another app or a locked screen. The readback is then determinate: tab active, window not focused. Line 51 reports it as unknown with activationUnavailable, which is false. The closed reply schema has no field for this. Either bump the metadata version with an observed focus field, or define dispatched as "tab active in the expected window" and treat focus as best-effort. Both require matching the Go struct field order, since the decoder compares canonical bytes.

- **Authentic notDispatched replies are downgraded to unknown.** In executeBrowserOperation, after a decoded reply arrives, a failed process check or changed epoch returns unknown. The reply was already authenticated against the request fences and the pending connection. A notDispatched reply is final and should not enter the unknown map.

- **The extension-side quarantine has no resolution path.** Line 35 blocks every future activate call while any intent has a missing or unknown receipt, regardless of action class. The proposed host-side finalizer never touches session storage, so the channel stays blocked until Chrome restarts. The `error?.dispatchState` branch on that line is dead code, since receipts have no error field.

- **Fingerprint encoders disagree.** activation_binding.go uses json.Marshal with HTML escaping on. data.BrowserActivationFingerprint disables it. The extension uses JSON.stringify, which escapes neither HTML nor U+2028. Any opaque identifier containing `<`, `>`, `&`, or those code points gives three different digests and a hard attemptConflict. Pick one canonical form and test it.

- **Binding row presence does not mean dispatch.** The commit runs before the frame is written. A commit that persists but returns an error yields a notDispatched refusal and an orphan immutable row. Any recovery keyed on row existence would be wrong. Recovery must key on effect state only.

## Design assessment

**The visibility-scoped alternative is sound.** The invariants the global quarantine protects are: no concurrent in-flight mutation on the channel, no hidden late materialization, and no later action relying on an unverified prior state. For activation all three hold without the freeze. The extension's loop ends at the deadline, so after deadline plus grace nothing is in flight. tabs.update and windows.update have no deferred effect beyond OS focus settling, which is harmless. DOM actions requalify origin, handle, and load status at dispatch, so a stale activation cannot corrupt them. What you lose is nothing for form, click, or payment uncertainty, because those keep their own classification. Implementation is small: give each unknown-map entry an action class, let openOriginIdle and the DOM gate ignore visibility-class entries, scope the extension check at line 35 by stored action, and hold the channel busy until deadline plus grace after an unknown. The run-level effect stays UNKNOWN and needs attention, which is truthful.

**The proposed recovery design has three gaps.** The resolver in effect_reconciliation_contract.go rejects any surface that is not native, so an activation step cannot reach a contract. The extension's match function reports origin and path but not active or focused, so there is no read-only visibility proof. RequireBrowserActivationBindingAuthority demands a live committed step intent and a thirty-second-fresh row, so it is unusable after reconnect. ReconcileEffect itself is the right vehicle. It preserves the original DispatchState, sets VerificationState verified, pauses rather than resumes, appends an audit event, and reads back idempotently on a repeated request. Reconciliation by fresh state is only sound because activation is idempotent. For a non-idempotent effect, current state would not prove agent dispatch.

**The binding table is optional for this goal.** Everything the metadata route needs is already in the immutable plan step surface and business key. The table's unique contribution is Chrome PID and start token, which only the retirement route uses and which legacy rows lack anyway. The same evidence could live in the attempt's existing outcome event payload. Keep the table if you want lookup by browser attempt ID, but do not block the fix on it.

**Fresh executor.** Starting a new run after verified exit of the exact recorded PID and start token plus broker restart is safe. The old Chrome process, its tabs, and its session storage are gone, so the uncertainty has no remaining scope. The durable record stays UNKNOWN. This is not a replacement for reconciliation and should not be described as one. For legacy records, there is no birth to verify, so retirement cannot be claimed. Those runs stay UNKNOWN and the new run simply starts under the existing per-run gate. A Chrome-only restart must keep the in-memory unknown until a hello carries verified retirement of the recorded birth. A changed start token in the new hello does not prove the old process died.

**The connection lifecycle module** is transport only and not implicated. Recovery on reconnect needs a metadata read path that works while lifecycleInhibited is set. That code is not in the supplied files.

## Acceptance tests

1. **Fixture replay.** Focus readback false, then true after 50 ms. Expect one tabs.update, one windows.update, reply dispatched with errorCode none, receipt dispatched, empty unknown map.
2. **Late success.** Focus true at deadline minus 5 ms. Expect reply accepted under grace and the stored receipt unchanged.
3. **Receipt write-once.** Deadline passes between the receipt store and the check. Expect the stored receipt still dispatched, and a replay returns dispatched.
4. **Focus never true.** Expect determinate classification per the chosen schema, one update each, and DOM steps on the channel not blocked.
5. **Lost reply.** Drop the result frame. Expect Go unknown, a visibility-class map entry, a DOM step allowed after deadline plus grace, a second activation denied until resolved.
6. **Replay by attempt ID.** Expect the stored receipt shaped with the new request ID, decoder acceptance, and the map entry cleared.
7. **Authentic notDispatched** followed by changed process evidence. Expect notDispatched, not unknown.
8. **Reconcile success.** Fresh read shows active and focused on the expected tab and origin. Expect effect confirmed, evidence DispatchState still unknown, VerificationState verified, run paused, one audit event. The identical request again must not invoke the evaluator. A false read leaves state unchanged.
9. **Legacy record.** Retirement route rejected. Metadata route works from the plan surface alone.
10. **Fresh executor.** Verified exit of the recorded PID and token plus broker restart, then a new run starts. The old run keeps UNKNOWN and needsAttention. A Chrome-only restart leaves the map entry in place.
11. **Orphan row.** Commit persists, write fails. Expect notDispatched and recovery ignoring the row.
12. **Digest parity.** Identical fingerprints across the two Go encoders and the extension for a corpus with HTML characters and non-ASCII identifiers.
13. **Canonical order.** JS reply key order equals the Go struct order with and without controlBadgeWindow.
14. **Epoch wiring.** The pin epoch from PrepareActivateTab equals the committed intent lease epoch. This coupling is assumed in executeActivateTab and not shown in the supplied files.
