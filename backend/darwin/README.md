# Native gateway

`NewGateway(c Caller, GatewayOptions{AllowedBundles, Lease,
AllowedValueIdentifiers, AllowedStaticTextBundles})` constructs the shared-model adapter. `Client` implements
Caller; fixture callers can exercise the adapter without touching a desktop.
The root binds Gateway.Execute to Endly's Execute signature and wraps it with
the Datly durable builder. Gateway does not schedule workflows or write data.

Exported methods: Observe(ctx, principal, surface), Execute(ctx, principal, step,
values), Capabilities() []model.Capability, LeaseEpoch(ctx, principal) (int,error),
Close(). Client additionally exposes PID() and WaitStopped(ctx) for supervision.

Nonempty bundle allowlist is required. Every observation/execution checks a
validated principal against the trusted auth context; scopes come from that
context. Observation accepts desktop:observe or desktop:control; mutation
requires desktop:control. The Lease callback must verify and return an externally
held desktop-wide fence. No callback means observe-only and LeaseEpoch fails;
it does not invent a fence or imply cross-process exclusion.

Capabilities reflect the cached helper doctor result (false until doctor is
queried), AX permission, mutation opt-in and configured fence policy. Bundle and
field policy remain additional gates. Exact role/id/name locators require a
complete app-scoped snapshot and exactly one match. App instances are resolved
by exact bundle and must also be unique. Native window scope supports an exact
unique title and optional role (`window` or `AXWindow`), resolving only descendants
of that window. A complete bounded parent graph is required: duplicate references,
orphans, cycles and excessive depth fail. Locator metadata outside the scoped
subtree does not affect its uniqueness proof. Ancestor scope resolves an exact
unique same-surface locator within that window (up to four nested scopes), then
searches only strict descendants using the same validated graph. Conflicting
window boundaries and unavailable required ancestor fields fail closed. Window
documentKey, frame scopes, visibility assertions and checkbox codecs fail before
dispatch.

Helper params (JSON keys are case-sensitive):

- doctor {}, apps.list {}.
- elements.snapshot {pid,bundleID,maxNodes:1000,maxDepth:20}.
- elements.read {elementRef,generation,expectedApp,attributes:["name"]}; permitted
  metadata attributes are role/name/identifier/enabled.
- elements.read for value additionally requires allowValueRead:true and
  expectedIdentifier. Gateway sets these only for configured bundle+AX identifier
  entries. Helper permits bounded string values only on nonsecure text fields.
  Snapshots continue withholding all values. Raw protocol callers are trusted
  broker code; the unsigned helper is not an independent authorization boundary.
- elements.read for staticText additionally requires allowStaticTextRead:true.
  Gateway sets this only for exact configured AllowedStaticTextBundles within
  desktop scope and a fresh, unique AXStaticText target. The helper rechecks the
  role, known nonsecure subrole and nonsettable AXValue; unavailable classification
  denies the read. Text is bounded to 4096 UTF-8 bytes without truncation. This
  policy does not authorize editable field values or add values to snapshots.
- lease.install {id,generation}; the same Lease object is carried at request.lease
  for elements.press/setValue.
- elements.press {elementRef,generation,expectedApp}.
- elements.setValue {elementRef,generation,expectedApp,value}.

`element.read` and supported assertions verify only their explicit read predicate.
A native mutation returns dispatched/unknown evidence with VerificationState
unknown even when AX reports success. The durable builder persists an unresolved
effect and stops; it must reconcile an independent outcome before resuming. No
API return is promoted to business success and no exchange is replayed.

Tests use an injected protocol fixture for strict uniqueness, partial coverage,
unsupported scope, no-mutation defaults, trusted-context scope enforcement,
value policy, external fence and false-success prevention. Native permission-
granted fixture and signed/TCC lifecycle qualification remain pending.

Supervisor integration now uses Options.Fence (*os.File), fixed inherited FD3
artifact, FD4 watchdog and FD5 physical fence. Identity() returns session's public
PID/start/executable/UID identity, and Stop(ctx) supplies Supervisor.AttachHelper's
cleanup callback. Raw helper inputs exist but Gateway's shared DSL still only
supports qualified-contract semantic AX press/fill/read; no low-level input route
is inferred. See session/README.md for lifecycle and uncertainty barriers.
