# Enrolled Chrome broker gateway

`NewBroker(ctx, Config)` opens a private Unix socket and loads backend enrollment
credentials using encrypted Scy resources. `Config` declares `SocketPath`,
`FixtureEnrollment`, and nonempty `Grants` of `Enrollment`: trusted authenticated
`Principal`, `ProfileChannel`, `BrowserInstance`, exact `ExtensionOrigin`, exact
`Origins`, and `CredentialResource`. Principal namespace is derived/validated by
the shared auth package; the native-host hello cannot choose a namespace.

Production enrollment requires independent signed process, pinned Chrome launch
profile and server-fenced executor preparation evidence. Fixture configurations
and host hellos must explicitly agree on fixture enrollment. The socket parent must be private; the socket is created mode 0600.
Existing sockets are never removed to seize authority. Scy resource failures block
startup, and plaintext credentials/fallback resources are rejected. The fixture
socket tests inject credential material through a package-private constructor.

`NewGateway(broker, GatewayOptions{Lease: ...})` implements root integration:
`Observe`, `Execute`, `Capabilities`, `LeaseEpoch`, `Close`, plus typed browser/recording methods below. Lease is the host's
desktop-wide held fence callback, not a per-tab workflow scheduler. Nil lease
permits observation only. Mutations additionally require an enrollment principal
with control scope and durable Endly execution RunID/PlanID metadata. Stable attempt
identity is SHA256 of RunID, PlanID, StepID, with NUL separators. Unknown transport
effects block all browser mutations until receipts/business effects reconcile.

The authenticated extension's bounded inventory supplies origin/title and full
browser identity. Exactly one root document must match the requested web surface
for that principal; matching tab IDs across profiles remain ambiguous. Truncated
inventory is rejected, and truncated titles cannot establish exact title scope.
Frame/window/ancestor scope and unsupported selectors fail explicitly. Shared typed
locator/argument values resolve as data; no JavaScript source is created.

An observation returns compact model nodes and DOM coverage limitations. Supported
shared actions are press/fill/read/expect. DOM dispatch returns an unverified effect;
it never establishes a business postcondition. Read/assertion verification means
the particular available DOM attribute was observed. Unavailable/redacted state,
unsupported attributes and incomplete target coverage cannot prove a negative
assertion. Custom editors, file controls and trusted input require other qualified
routes and are not advertised here.

Pending commands correlate full document identity, generation, request and mutation
attempt IDs. Cancellation after send reports unknown and retains late receipts;
identity mismatch reports unknown, never success. Cached attempts cannot redispatch
or change payload. `Broker.QueryReceipt` is a read-only recovery call; authenticated
reconnection reuses the existing broker/channel fences and can query the original
document. Host/worker loss cannot authorize replay. Missing document receipt remains
unknown. A broker restart changes epoch and the extension fails closed until old
executors are explicitly quiesced/reconciled. In-memory receipts do not replace the
root's durable Datly ledger, and known dispatch is still not business verification.

`go test -race ./backend/chrome ./cmd/mechanize-native-host` and the extension's
`npm test` use private socket/jsdom fixtures, with no employee browser controls.
Real MV3/native-host enrollment, permission revocation, renderer suspension,
cross-profile navigation, broker crash reconciliation and signed installation
remain disposable-profile acceptance gates.

## Additional typed methods

- `ListTabs(ctx,p)` returns exact authorized root Documents, completeness and
  inventory time. Each TabHandle is profileChannel/browserInstance/tabID. Supply
  this handle as model.Surface.TabID to disambiguate profiles; a bare numeric ID
  never chooses a first profile. Truncated titles cannot establish exact scope.
- `Navigate(ctx,p,surface,url,attemptID)` and `ActivateTab` return BrowserResult
  embedding StepResult plus Ready/Active/Document. The externally held desktop
  lease is rechecked in the mutation lane. Dispatch/readiness remains unverified
  business state. Shared DSL registry/lowering is owned by the root integration.
- `ObserveSince(ctx,p,surface,observationID)` returns changed semantic nodes/removals
  with current generation and coverage, or a reset snapshot if the bounded
  per-user snapshot cache cannot support a complete delta.
- `StartRecording(ctx,p,surface,id)`, `PauseRecording`, `StopRecording`,
  `RecordingEvents(ctx,p,id,afterSequence,limit)` return RecordBatch. Explicit
  control scope and enrollment are required for start/pause/stop. Polls are
  observational. Root persists events through its Datly recording component and
  deduplicates immutable Lineage. Raw redacted-secret values, forged event identity,
  unknown kinds and injected events are rejected.

Recording is document-scoped and visibly indicated. Root should poll at five-second
intervals while explicitly recording; RecordBatch.LeaseExpiresUnixMS reports the
30-second local recording lease. Expiry locally stops capture and leaves a gap.
Navigation/document loss interrupts this recording with a gap; no new document is
silently recorded. Unreachable stop returns stopUnconfirmed, never false assurance
that an inaccessible renderer stopped. Event Bounds use viewportCSSPixels and are
correlation hints only. Cross-surface CGEvent/DOM deduplication still needs qualified
native/browser window mapping and must preserve ambiguous event associations.

Production profile qualification now crosschecks signed-host launch evidence
against operator-pinned `Enrollment.ProfileDirectory`. The native host extracts
this from Chrome's feature-gated reconnect argv after immediate signed-parent
proof, never extension storage. `ChannelTrust` reports process/profile/executor
layers separately. Production inventory and all calls stay blocked until the
worker acknowledges the broker's connection-specific preparation challenge with
no pending or unknown attempts. Immutable broker/channel/scope fences are the
server-owned executor generation; changed persisted epochs remain blocked.
This implements first-generation binding and same-generation reconnect, not
cross-generation durable recovery or live production qualification. See the
extension README's signed launch enrollment section for installation gates.

Production renderer control uses a separate revocable lease for each admitted
step. `AdmitControl` authenticates the connected signed native-host and immediate
Chrome parent, checks the operator-pinned profile and broker preparation challenge,
requires complete root inventory with no pending/unknown action, observes the exact
root document, and obtains an `executor.acquire` acknowledgement. The lease binds
verified owner/client, profile/browser/document, DOM generation and immutable
broker/channel/scope fences. Host policy and consent remain separate admission
requirements; this transport cannot manufacture either.

`ExecuteControl` uses the pinned document without reselecting or refreshing its
identity. It carries the stable Endly attempt and checks the exact active lease
again at the write boundary. The production worker requires that lease; the content
executor rejects absent, changed, retired or stale-generation authority before
synchronous mutation. Cancelled consent, navigation, disconnection and unresolved
receipts block dispatch. A lost acquire/retire reply retains the barrier.

`RetireControl` first inhibits the exact broker lease, refuses pending/unknown
attempts, obtains the exact endpoint's `executor.retire` acknowledgement, and
rechecks pending/unknown state before releasing that authority. The distinct host
`RetiredAuthorityQuiesced` evidence means no further input under that exact retired
lease; it does not claim that the whole document is permanently shut down.
A fresh lease requires new verified endpoint/policy admission and per-step consent.
Retired lease identities are retained within the bounded document lifetime.
`executor.quiesce` still permanently stops the entire document. The host production
provider currently qualifies only typed exact root `element.press`/`element.fill`;
other mutation methods remain outside that admission route. No live release
qualification is implied by passing the injected peer/DOM test fixtures.
