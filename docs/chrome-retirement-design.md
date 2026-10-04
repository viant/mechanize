# Chrome channel retirement and restart

Status: design requirements, not an implemented or qualified reconnect path.
Source reviewed on 2026-10-03. The production goal includes restart with existing
effects and receipts; a fresh test profile does not establish that capability.

## Current behavior and missing support

`backend/chrome/broker.go` creates new broker/channel epochs on startup. Its
`Close` closes transport connections and the listener without obtaining renderer
quiescence or releasing the extension's persisted fence.

`extension/chrome/worker.js` compares an incoming grant against
`storage.local.lastGrant`. A changed broker epoch, channel epoch or scope hash
fails closed with `storedFenceMismatch`. This protects existing executors and
receipts, but there is no implemented transition that releases the old fence.

`backend/chrome/control.go:RetireControl` retires one exact renderer control
lease. It checks pending and unknown operations and retains their barriers. It
does not retire the channel or release `lastGrant`.

`extension/chrome/content.js` implements `executor.quiesce` as terminal document
shutdown. The executor retains its binding and receipts, and later `bind`
requests reject the quiesced document. Quiescence cannot be treated as permission
to inject a replacement executor or reset that document's history.

Missing pieces include a channel admission gate; an authenticated retirement
protocol; durable transition adoption; complete renderer and receipt accounting;
recording termination/export; and qualified restart or same-document handoff.
None of the existing shutdown methods proves these requirements.

## Typed lifecycle API

A separate explicit lifecycle operation should precede transport shutdown:

```go
type ChannelFence struct {
    BrokerEpoch, ChannelEpoch, ScopeHash string
}

type ChannelRetireRequest struct {
    RequestID, ProfileChannel, BrowserInstance string
    ExpectedFence ChannelFence
}

type ChannelRetireResult struct {
    TransitionID string
    OldFence ChannelFence
    QuiescenceConfirmed, FenceReleaseConfirmed bool
    NeedsAttention bool
    Reason string
}

func (g *Gateway) RetireChannel(
    ctx context.Context, principal auth.Principal, request ChannelRetireRequest,
) (ChannelRetireResult, error)
```

These names are proposed. Request fields identify a transition; they grant no
authority. The host must bind it to the verified owner and client, its configured
extension/channel identity, current trust scope, actual signed native-host and
Chrome process evidence, and an admitted lifecycle context. Preserve the strict
profile proof in profile mode. Desktop mode must retain its honest absence of
profile qualification and the operator's desktop access restrictions.

Endly remains responsible for operation admission and stopping workflows. Hold
its admission inhibition while preparing retirement. Add a broker channel gate
that rejects new commands, renderer lease acquisitions and channel takeovers.
Check that no control lease is held and no pending or unknown attempt remains.
Do not infer an idle workflow from an empty broker pending map.

The operation is distinct from `Close`. A forced socket close cannot report a
successful retirement. Cleanup errors must retain confirmed transition facts
while withholding reconnect readiness.

## Retirement protocol

Use bounded closed native-port message types, with a unique transition ID, exact
old fence, an explicit deadline, and exact document identities. Do not expose
credential material, page values, titles, raw browser exceptions or receipt
contents in public lifecycle diagnostics.

1. Persist the host retirement intent before sending a request. Product database
   operations must use a generated Datly use-case component, scoped by verified
   owner. The current component set does not implement this lifecycle record.
2. Under the admission gate, reverify the actual signed peer and freeze the exact
   old channel. Retain attempts, receipts, unknown effects and recording state.
3. Send `channelRetirePrepare` with the transition and old fence. The worker must
   validate it against its trusted native connection and persisted grant. It
   freezes its command admission and checks mutation activity and unresolved
   worker/browser intents. A different request or fence cannot adopt the work.
4. Establish a complete set of existing bound executors. Reconcile the broker's
   roots, the worker's bindings and current document inventory. Explicitly
   account for child executors, disappeared documents, discarded/prerendered
   pages and navigation races. An unavailable or incomplete inventory does not
   prove quiescence. Do not silently skip an inaccessible executor.
5. Quiesce each exact executor using its old binding, and obtain matching
   acknowledgements. Preserve its receipts and recording history. A renderer
   response must report sufficient bounded state to establish that it has no
   active control/recording work and that receipt retention is accounted for.
   Existing `quiescent: true` alone is not a receipt persistence proof.
6. Persist a worker retirement tombstone containing the old fence, transition,
   exact executor set and completed phase before `channelRetirePrepared`.
   Persist host acknowledgement through Datly after validating identities,
   complete coverage and idle state again.
7. Send `channelRetireCommit` for that exact prepared transition. The worker may
   release only its matching persisted old grant, together with a durable
   released tombstone. Never clear `requests`, `unknownAttempts`, browser intent
   or receipt storage, or content executor receipts as part of fence release.
   Reply `channelRetired` only after the extension storage update succeeds.
8. Confirm the exact released transition through durable readback before
   reporting `FenceReleaseConfirmed`. The next connection must independently
   authenticate its new process/channel, establish its executor challenge and
   obtain a complete qualified inventory. Retirement is not a mutation grant.

Persisted browser storage is the extension's private fence/receipt cache. It is
not a replacement for the host's generated Datly audit and effect ledger.
Document the atomicity and crash behavior of the extension storage update;
writing multiple keys must not be assumed to provide a database transaction.

## Existing receipts and document reuse

Production restart must support nonempty *resolved* history. A gate requiring
zero prior mutations can bound an initial experiment, but cannot satisfy
production retirement or restart.

Before destroying a document, provide a qualified path to retain every relevant
DOM receipt and recording record in the owned durable ledger. Prove complete
coverage, exact attempt identity and disposition. Unknown or missing receipts
remain unresolved; exporting a receipt must not relabel a business effect.
The current content receipt map is in document memory, so reload can destroy
evidence. Current browser API session storage and DOM receipts have different
lifecycles and must both be accounted for.

After the existing terminal `executor.quiesce`, choose one explicitly qualified
route:

- Fresh documents: require new Chrome document IDs and retained old evidence
  before navigation/reload. Old document bindings remain terminal and cannot be
  replaced. Reload is an explicit workflow/setup action; retirement itself must
  not reload or replay anything.
- Same-document handoff: add a distinct guarded protocol that transfers a
  reconciled executor's immutable receipt history and retired lease set while
  permanently rejecting old authority. Do not make ordinary `bind` overwrite an
  old or quiesced binding. This route is currently unsupported.

An old document disappearing is not evidence that its effect was absent. All
late old-fence commands must remain rejected on either route.

## Lost acknowledgements and restart

Each stage must be idempotent for the same transition and exact fence. Retrying
a transition may adopt persisted facts; it must not dispatch a user action or
consume another effect attempt.

- Lost prepare reply: query the exact persisted phase. If all executors are
  confirmed quiescent, adopt it. Partial or unknown coverage stays blocked;
  never assume that a timed-out executor did not act or finish quiescing.
- Lost release reply: the worker's released tombstone permits exact readback.
  Retain the confirmed fence release even when host acknowledgement or cleanup
  fails, but do not claim new-channel readiness from it.
- Worker restart: reconstruct the retirement gate and phase before accepting
  commands. A normal initial handshake must not bypass an unfinished transition.
- Broker restart: use the owned durable transition to reconcile the old fence
  with worker state over a newly authenticated lifecycle-only connection. That
  connection must not authorize input or replace an executor before adoption.
  Ordinary new-epoch `processQualified` is insufficient.
- Crash before durable proof: remain blocked. Recovery needs actual evidence and
  a separately admitted reconciliation procedure, not a blind deletion of
  `lastGrant` or recreation of an old authority.
- Conflicting transition, changed owner/client, scope, extension, process birth
  or signing policy: refuse adoption. Operator enrollment changes require their
  own explicit migration and audit.

Deadline expiry or disconnect must preserve pending/unknown state. The host must
not convert a failed retirement into a successful clean restart simply because
the process subsequently exited.

## Qualification tests

Use injected brokers/workers/renderers and isolated generated Datly fixtures.
Default tests must perform no input on the employee's desktop.

- Exact empty-history retirement, with a single fence release and no dispatch.
- Resolved nonempty DOM/browser receipts survive retirement, export and restart;
  attempts and original outcomes remain unchanged.
- Pending, lost/unknown receipt, live lease, active recording, incomplete
  inventory, inaccessible executor and navigation races block release.
- Wrong owner/client, request, fence, document, process birth or peer code pin
  fails before retirement work or credentials become available.
- Delayed old commands cannot mutate after the gate closes, after quiescence,
  or after a fresh channel is admitted.
- Failures before and after each persisted phase, storage write failures,
  dropped replies and broker/worker restart adopt only exact confirmed facts.
- Old terminal documents cannot rebind; fresh documents do not erase unresolved
  history; any future same-document handoff preserves all receipt barriers.
- Public status reports bounded static stages and counts without page content,
  credentials, titles or raw exception text.

These tests and a disposable real-browser restart gate remain required before
claiming production reconnect qualification.

## Next demonstration setup

For the next build, use a new disposable Chrome profile as isolated test setup.
Keep the existing profile, persisted `lastGrant`, documents and receipts intact.
This does not exercise or qualify the proposed retirement protocol and does not
resolve uncertainty in any existing durable run. Robust production restart
remains an outstanding requirement.

## Implementation status and policy rollover

The internal DOM receipt exporter and typed page collector are prerequisites;
export alone neither releases a fence nor authorizes reconnect. The Datly ledger
schema and generated components retain owned transitions, immutable sanitized
manifests, and audit events. Host/worker lifecycle wiring and crash qualification
remain necessary before exposing retirement through MCP.

The initial ledger adoption contract requires the same enrolled policy and scope
hash. It can cover a new authenticated native-host process under the same policy,
but cannot by itself authorize an ad-hoc build upgrade: this development installer
pins exact broker and native-host code hashes, which change on rebuild. A future
upgrade path must commit the specifically authorized successor policy as immutable
retirement intent, then verify the replacement against it. Do not relax policy
equality or treat the appearance of a newly signed executable as upgrade consent.
A changed Chrome parent process remains a separate recovery case; preserve the old
process evidence even when the bridge process legitimately changes.

## History capacity and repeated cycles

Worker persistence must support another retirement after an adopted transition,
requiring the new old-fence tuple to equal the prior adopted fence and retaining
prior tombstones and receipt manifests. A conflicting active transition or reused
transition ID is not a new cycle. Capacity exhaustion must stop before a write;
it must never trigger deletion of receipt history.

The current store design budgets at most 32 transitions and 8 MiB for its entire
owned value, with lower per-manifest bounds. Chrome documents a default local
storage quota of 10,485,760 bytes, shared by all extension keys; a store budget
therefore does not guarantee a write will fit. All storage failures and readback
failures remain explicit unconfirmed outcomes. See the [Chrome storage API](https://developer.chrome.com/docs/extensions/reference/api/storage#property-local-QUOTA_BYTES).
A future archival protocol must prove durable retention before compacting local
history; silently evicting entries is outside this contract.
