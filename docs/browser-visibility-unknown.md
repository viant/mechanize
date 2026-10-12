# Tab visibility uncertainty

`browser.activateTab` changes only an exact tab's active state and its window's focus. Its original UNKNOWN outcome and replay deduplication remain unchanged. It does not prove a historical click, document interaction, or native-input focus authority.

A fresh target-bound DOM operation may proceed only after the broker proves all of the following:

- The original request was the broker's immutable `browser.activateTab` request, with its original exact target, origin, fingerprint and fences.
- The current authenticated native channel belongs to the same original Chrome process birth.
- The extension still retains a matching terminal intent/receipt pair.
- The extension verifies that pair while holding the same serialized lane used by browser activation and renderer input. A pending API promise or busy/private input lane refuses the proof.
- The next operation independently passes normal process, scope, document, consent, lease, private redaction and dispatch checks.

This classification never removes an UNKNOWN, marks a durable effect verified, or permits another tab-visibility operation around it. Other unknown actions—including open-tab, renderer inputs, credentials and untyped receipts—remain blocking. Native input still requires its own fresh focus proof. The browser status retains `unknownCount` and separately counts currently proven `visibilityUnknownCount`.

An elapsed command deadline is not quiescence evidence. Activation sends each update once, polls only metadata under that same deadline, and stores its terminal receipt once. A late authority check or lost storage acknowledgement cannot overwrite a stored successful receipt with UNKNOWN. An authenticated `notDispatched` reply remains negative evidence even if the channel changes after receipt acceptance.

## Restart limits

Classification is invalidated by channel/process/fence replacement. A missing session journal, including after an extension reload, cannot establish the original activation proof. A new broker cannot infer an old request's process birth from a credential record's epochs: a broker channel epoch can survive native-parent replacement. Existing legacy UNKNOWN effects are not retroactively reconciled by this feature.

Retiring an old process and creating a fresh independently qualified executor is a different operation. It must retain the old durable run and pass normal credential/protection retirement and new-session authority checks. Resetting a volatile map is not effect reconciliation.

## Verification

`TestRealChromeVisibilityUnknownAllowsFreshDOM` uses a disposable Chrome profile and the production worker/content/broker paths. It performs a private handoff, drops one activation result, then proves a fresh admitted redacted read and one ordinary DOM click. The original UNKNOWN remains and repeated activation is denied. The native transport and signed-process verifier are fixture adapters; no user browser or database is accessed.

Worker tests cover serialized-lane races, unfinished input, private/lifecycle holds and missing restart journals. Backend tests reject malformed/unrelated replies, mixed or untyped unknowns, and changed process evidence. Durable run isolation is tested independently in `engine/durable/activation_run_isolation_test.go`.

`TestCredentialFreshExecutorRetainsActivationUnknownAndAllowsNewPublicWorkflow` composes the production Host authorization and Datly durable store with a disposable production-worker bridge. It creates a retained activation UNKNOWN, normally closes Chrome, independently verifies the old kernel process birth is absent, and creates a fresh Host/session against the same store. A new credential preparation and public read succeed while the original durable activation outcome and private dispatch history remain unchanged. Resuming/replaying the old run remains refused. Host transport/private-admission methods are fixture adapters; the separate broker/Chrome fixture above exercises the concrete transport and private handoff. This does not prove that a real bank login survives a process restart.
