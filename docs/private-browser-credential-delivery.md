# Private browser credential delivery: current source and remaining integration

Source status, 2026-10-07. The real host now composes native RecordStore selection,
consent, durable preparation/attempt barriers, private fill/submit and same-origin
multi-step continuation. Four canonical MCP routes expose only opaque references
and bounded scalar state. This source work does not change the installed runtime.
Post-login DOM privacy integration and source protocol tests are implemented;
live rollout remains unqualified. No
live bank login or transaction-history operation is asserted by fixture tests.

## Host composition and native approval

`host/credential_service.go` is constructed by `Host.New`. The configured native
RecordStore and shared exposure gate are mandatory; an absent provider fails
closed. The host uses the actual Chrome gateway, Runtime session ownership,
consent broker and generated durable components. Existing permanent grants are
reused. Session grants support the multi-operation flow. A trusted restrictive
preflight rejects a single-use grant before consuming it; it is not permission
for an entire fill/submit sequence.

`mechanize_credential_prepare` accepts session/purpose/grant and an exact HTTPS web
surface. Apply, submit and status accept only session and a random preparation ID.
Errors are static; no record IDs, keys, revisions, field names, values, DOM content
or provider errors are returned. Canonical controller routes preserve the owned
runtime session and never create native administration authority.

The signed native localRPC methods `credential.pending`, `credential.bind` and
`credential.cancel` are metadata-only. Bind supplies the native-selected opaque
record ID and exact ciphertext revision. Native selection validates encrypted
standard `username`/`password` fields locally and wipes decrypted buffers. It
retains a sealed `RecordDelivery` capability bound to the original automation
actor/session/grant/purpose/origin and a maximum five-minute expiry. Delivery
uses `NewRecordDeliveryManager` and the exact selected RecordStore revision;
there is no legacy Store fallback, mutable lookup or plaintext getter in delivery.

After native binding the opaque state is `awaitingPreflight`. Explicit status
commits and reads back held protection, pins the private version-2 inspector, and
returns `ready` with its closed stage. It does not construct a value consumer,
resolve a Vault key or reserve an input attempt. Repeated ready-status verifies
the same pinned binding. Apply cannot skip preflight; it reuses that exact lease
and fresh-checks the version-2 inspector before encoding values. Before every
fill or exact-form submit, the host commits and reads back a
separate UNKNOWN attempt. A lost commit/reply is never retried. A successful
submit may independently qualify a new same-origin document for the next private
username/password stage; it does not establish login success. Every historical
unknown disqualifies a later DOM privacy permit. Protection remains held across
navigation, cancellation and restart.

Source tests exercise real Host.New composition, native-only selection, the real
encrypted RecordStore/Manager, generated consent and durable components, committed
UNKNOWN readback before each synthetic transport dispatch, distinct fill/submit
attempts, username-to-password continuation, revision substitution, cancellation
of exposure capabilities, and no replay. Browser transport fixtures contain only
synthetic values; they do not qualify a deployed Chrome or bank website.

## Implemented private browser boundary

`backend/chrome/credential_admission.go:AdmitCredentialControl` performs the closed
metadata-only `credentialInspect` exchange instead of public `Observe`. It checks
the existing signed channel and root document, adopts only its freshly returned
generation, and acquires the normal retained renderer lease with `executor.acquire`.
A mandatory trusted host callback must validate actual consent and held exposure
protection before every probe/acquire. Missing producer, changed identity, old
incompatible authority and unresolved effects fail closed. It does not invent
consent, select a new document or clear an old lease.

`backend/chrome/credential_fresh.go:FreshCredentialBinding` is the real
`Manager.Hooks.Fresh` adapter for an already-held secure renderer lease. It performs
another private metadata-only inspector exchange and requires exact original
identity/generation. It never calls Observe, re-admits, adopts a new generation or
clears quarantine. `CredentialNavigationID` derives the binding from recipient,
actor, channel fences and renderer lease. Both Fresh and delivery require this
exact derived navigation ID; a caller-chosen navigation string is insufficient.

`backend/chrome/credential_delivery.go:DeliverVaultCredential` requires the selected
ciphertext revision and uses `Manager.ConsumeRevision` / `Credentials.WithBytes`.
Only its explicit private encoder receives username/password. The deadline is at
most 10 seconds. The closed scalar reply reports dispatch knowledge, not successful
login. Raw private frames cannot enter generic commands, fingerprints, receipts,
public observations or error output. A confirmed fill retains the quarantined native connection for exact private
submit/continuation; uncertain outcomes retain protection and never replay.
The actual Fresh call occurs before acquiring the transport lane, avoiding recursive
lane acquisition when the real Manager hook is used.

`extension/chrome/worker.js`, `content.js` and `secure-input.js` implement the
matching private inspector/delivery receiver. It requires the existing production
content binding; no reinjection/rebinding resets quarantine. Inspection examines form metadata locally; its closed response returns no
field values, field names or selectors. Delivery fills a uniquely qualified same-origin username, password or paired
form stage and excludes OTP/payment/captcha ambiguity. The metadata-only inspector
and fill receiver both require the same supported submission contract before
writing: a same-origin form with one native submit button, or one native action
button when no submit button exists. Initially disabled buttons may qualify before
fill, but must be enabled at dispatch. Submit uses the retained exact button's
native click method so JavaScript click handlers run, and rechecks form, button
identity and endpoint overrides without reading input values. A persistent submit
listener blocks default GET, foreign-action and foreign-window submissions, including
delayed native submissions. The click acknowledgement does not establish login
success. Ambiguous controls remain unsupported; refusal does not authorize a generic
unprotected click fallback.
Separate private submit
uses the retained exact form once, without receiving selectors or value bytes. Ordinary output is suppressed
through private inspection, lease acquisition and delivery. Protected origins
persist in local/session storage and continue to block ordinary reads after SPA
navigation or document replacement. A connection acknowledgement is not evidence
that the bank accepted credentials.

## Private tab retirement (source, not yet host-connected)

The worker and Chrome gateway implement an internal `credentialRetire` exchange
for a known credential fill with no submitted login. It closes only the retained
tab after rechecking its exact root document, origin, channel fence and renderer
lease. A confirmed refused submit is allowed; a successful or uncertain submit
is refused. The worker uses browser tab removal and an independent complete tab
query to confirm absence, without renderer calls or DOM/value reads. Origin
quarantine and attempt identities remain retained. The request is consumed once;
lost removal/readback replies remain unknown and never retry.

The gateway issues a nonconstructible volatile proof only for the closed scalar
acknowledgement under unchanged signed process/channel and original consent.
This is not a cleanup API or a durable release: host composition, a separately
reserved cleanup attempt, audited protection closure, and startup recovery are
still required. No MCP route invokes this operation yet. Do not clear a live
preparation or its attempt history based on this source implementation alone.

## Implemented Vault primitives

`vault/delivery_gate.go` adds a separate exclusive delivery lease. It is distinct
from the signed console's native **administration** entry lease and uses the
original authenticated automation principal. `ExposureGate` excludes ordinary
readers, capture, input, recording, other deliveries and native entry while the
lease is held. Admission checks exact consent/session/client/document/Target and
requires actual trusted authorization and cleanup callbacks. Action admission is
one-shot: success, error or panic cannot make the lease reusable. Cancellation,
revocation and uncertain cleanup retain protection rather than release it.

`Store.ConsumeRevision` and `Manager.ConsumeRevision` verify the selected revision
against the same opened authenticated ciphertext bytes consumed under the custody
lock. They do not adopt a newer credential or use a legacy/latest fallback. They
need the original verified principal, not fabricated NativeHuman authority.

`vault/delivery_selection.go` implements an opaque in-process selection object.
`NewDeliverySelection` requires the actual native-human/admin selector, an original
verified automation context with control scope and exact consent binding, equal
namespaces, a pinned browser binding, native EntryMetadata, a bounded expiry
(maximum five minutes), and a mandatory host authorization callback. Current
metadata is verified locally. `Store.Metadata` internally decrypts/authenticates
and wipes; the selection object never receives or returns username/password bytes.

`DeliverySelection.UseBinding` checks the original client/session/grant/purpose,
exact recipient, expiry/revocation and live host guard, then synchronously supplies
binding/reference/revision only to trusted host code. Public recipient metadata
contains no Account alias. Object JSON and formatting withhold all private routing.
Same-session selected-secret reuse is allowed; each delivery attempt and exposure
lease remains independently one-shot. Revision drift is refused, including at the
final ConsumeRevision boundary. Selection revocation changes no credentials or
unknown-effect records. `DeliverySelection.Verify` is the pure metadata guard for
each private probe/write: it rechecks owner, exact consent/recipient, revocation
and expiry without invoking authorization or Store.Metadata, so it is safe inside
ConsumeRevision's custody lock. The host combines it with actual consent and
`DeliveryLease.Verify`; selection proof alone does not authorize delivery. The host production route uses the separate sealed RecordDelivery capability for native-managed records; the legacy Store selection remains separate.

## Implemented generated durability and startup barrier

Schema `011.sql` adds `credential_delivery_preparations` so the original nonce
protection is committed and read back **before Pin or any private browser probe**.
A preparation has original namespace/client/session/grant, task-purpose hash, exact
HTTPS origin, selected ciphertext revision, random 64-hex PreparationID, held
protection, revision and timestamp. It has no document/renderer lease placeholders,
Account alias, Vault reference or value data. A failed unpinned probe leaves this
record held and visible to the startup barrier after restart.

`CredentialPreparationReserve` POST and `CredentialPreparationGet` GET are generated
from `data/source/credentialpreparation*`. Their sealed in-process authority requires
actual original actor/consent plus a mandatory real host guard. Builder methods
`ReserveCredentialPreparation` / `ReadCredentialPreparation` operate under the
existing private per-user lock; Reserve requires confirmed commit and exact
readback before the host may Pin. Duplicate held namespace preparations fail.

Schema011 enforces correlation atomically in SQLite insert triggers. A child010
attempt is accepted only when SelectionID equals the held PreparationID and
namespace, client, session, grant, purpose hash, origin and selected ciphertext
revision all match. A correlated preparation plus child is expected; unrelated
preparations or attempts are refused. Preparing while a held/unknown child exists
is also refused. Nullable purpose_hash on old010 rows records unavailable legacy
metadata; migration invents no purpose and clears no barrier. New writes require
an actual matching purpose hash. No release component exists; preparations stay
held until a future qualified cleanup protocol and schema transition are supplied.

`data/schema/010.sql` adds
`credential_delivery_attempts` and append-only audit. Stored fields are bounded
operation metadata: owner/client/session, random attempt/selection IDs, selected
**ciphertext** revision, consent grant, origin/document/channel/lease/process birth
identities, scalar dispatch/protection state, CAS revision and timestamps. There
are no credentials, plaintext-derived hashes, Account aliases, Vault references,
raw frames, DOM values or arbitrary error payloads.

Four additional private components are generated from `data/source/credentialdelivery*`:

- `CredentialDeliveryReserve` POST atomically reserves `unknown` / `held` and audit.
  The unique active-owner index prevents another unresolved/protected delivery in
  the same namespace. Reused attempts and mismatched sealed metadata are refused.
- `CredentialDeliveryGet` GET reads exact owner/attempt metadata and its audit.
- `CredentialDeliveryFinish` PATCH performs a guarded CAS and appends audit. It
  records scalar dispatch knowledge while keeping protection held. It cannot
  fabricate cleanup or clear an unknown record through ordinary retry.
- `CredentialDeliveryBlocked` GET returns only a namespace-local 0/1 unresolved
  protection count. It unions namespaces across held preparations and unresolved
  attempts, so a correlated pair returns one. It reveals no reference, account or
  other-client metadata.

`data/credential_delivery_scope.go` supplies revocable in-process authority bound
to the original actor/session/grant and a required live host guard. The factory is
not a transport endpoint and does not itself prove the production grant/protection.
`engine/durable/credential_delivery_component.go` holds the actual per-user lock;
`credential_delivery_reservation.go` requires confirmed generated commit **and**
exact readback before the host may write private credential bytes. The dedicated
component allowlist grants no generic DAO or browser execution capability.

`engine/durable/credential_delivery_barrier.go` reuses an existing held user lock
or acquires it normally. Startup checks do not require an already-held delivery
lease. Errors block exposure; a false result alone is not browser cleanup proof.
`host/consent_policy.go:AuthorizeOperation` now calls this barrier before ordinary
exposure permits. Unavailable readback returns Vault unavailable; a held barrier
returns delivery protected. This source hook covers shared authorization for
native/Chrome observation, capture, input, recording and retained hybrid permits.
**The source hook is wired; the installed live host remains unchanged.**

Generation used the published `go.mod` pin
`github.com/viant/datly v1.1.1-0.20261004024140-a3837f55687f`, against a throwaway
schema-only SQLite database. Regeneration reproduced 76 generated Go/SQL artifacts across six components.
The component inventory is registered in `data/host/host.go` and
`data/scripts/regenerate.sh`; generated orchestration is not hand-edited. No
installed database was opened or migrated.

## DOM privacy transition and rollout gates

`host/credential_privacy.go` is the sole production constructor of a DOM privacy
capability. The private Advance inspector must first return the exact authenticated
privacy-candidate sentinel. The host then calls Chrome's independent
`QualifyCredentialPrivacy`; only its opaque proof and authority accessor can bind
the new exact same-origin document. Every credential attempt must have confirmed
dispatch metadata; any historical unknown permanently prevents this transition.
The authenticated typed document-change sentinel remains distinguishable on
subsequent verification of the same source lineage. It may trigger explicit
requalification, never input replay.
Malformed replies and changed/disconnected channels remain blocked.

A separately authenticated native-challenge sentinel preserves only the known
submit/redactor lineage and quarantine. It grants no document/input authority;
no OTP field/value is read or returned. Apply/submit cannot operate on the
challenge. The human completes it locally, and explicit status may independently
inspect the later exact document. Runtime session closure cancels these retained
capabilities immediately, including active private transport, without clearing an
unknown outcome or its durable barrier.

The five-minute record selection expiry still forbids further credential bytes or
private submits. After a durably confirmed submit, the original unrevoked binding
may support metadata-only challenge/privacy qualification under fresh live consent
without renewing secret use or rereading the Vault. No unknown attempt qualifies.

`vault/delivery_dom.go` keeps the exclusive desktop exposure gate held while
minting a separate exact-document DOM capability. It cannot fill credentials or
resubmit a private form. `host/credential_dom.go` admits ordinary observation and
control only for the original actor/session/grant/purpose and exact qualified tab
and origin, with a fresh backend redaction verifier on every admission. Native
reads, screenshots, recording, other tabs and other origins remain unavailable.
The proof's `Authority()` is a retired routing/provenance snapshot, not a reusable
input lease. Qualification acquires and exactly retires a probe lease; the normal
web-control provider later owns its independently acquired ordinary lease.
Native cancellation cancels retained DOM leases. The persistent backend callback
reads an atomic current exposure binding and verifies actual consent; it never
captures a completed MCP request's context or expired durable-lock marker.

This is a privacy transition, not login success, full-desktop cleanup, or unknown
business-effect reconciliation. All durable preparation/attempt protection stays
held, so restart or reconnection cannot recreate the volatile DOM permit from
caller JSON. No unqualified whole-desktop release or credential retry exists.

The matching signed broker/nativehost and updated extension worker/content/private
renderer must be deployed together before private login. An intermediate
`preserve-extension-v1` infrastructure repair deliberately retains old extension
bytes and is not proof of private-protocol compatibility. Actual deployed channel,
loaded extension, native approval, form stage and redaction behavior still require
qualification. Initial and fresh private inspectors require running protocol
version 2; a stale worker/content script is refused before value encoding. Source
fixtures contain no real Vault values or bank data.

During quarantine, the controller bridge admits only strictly decoded, owned
`mechanize_credential_apply`, `mechanize_credential_submit`,
`mechanize_credential_status` and `mechanize_session_close` continuation requests.
Value-bearing, malformed, cross-session and generic controller frames stay blocked.
After proof qualification, ordinary DOM routing remains subject to intrinsic fresh
privacy guards as well as host consent, including paths that qualify a normal
renderer lease before host authorization. Controller availability is not native
administration authority.

## Source validation

Disposable race tests cover private admission and retained leases; exact real
Manager Fresh-to-ConsumeRevision-to-delivery composition without deadlock;
credential/document/navigation drift; secret echo and panic sanitization;
selection namespace/client/consent/expiry/revocation/concurrency; one-shot delivery
protection and cleanup retention; generated commit/readback, append-only audit,
stale CAS and replay rejection; failed-unpinned-preparation and new-Builder restart barriers, exact cross-table
correlation rejection and cross-client
namespace inhibition; and Host startup-barrier refusal before exposure modes.
These tests establish source behavior only. They do not qualify paid actions,
bank data, an installed console/Chrome channel, browser cleanup or a live rollout.

## Explicit native legacy credential import

The native Vault legacy row offers **Import for private sign-in**. The user selects
one exact legacy target and ciphertext revision, opens the independently protected
native window, and explicitly chooses Import selected. This requires the reviewed
RecordStore root enrollment and the same enrolled cipher/key and exposure gate.
There is no startup migration, scan, fallback or MCP/reverse-controller import
route. The legacy encrypted entry is retained.

The signed localRPC methods `vault.record.importCredential` and
`vault.record.inspectImport` accept only entry/session IDs, legacy target/reference
and ciphertext revision. The broker consumes that exact revision in protected
memory, copies username/password into the generic encrypted record, and wipes
owned plaintext buffers. Swift and RPC receive only an opaque destination ID and
ciphertext revision; neither receives credential values. Selecting that new record
for a browser preparation remains a separate local approval.

A domain-separated authenticated `.import-<source-revision-digest>` receipt reserves
a random destination before any copy and is synchronized to disk. Its digest is
over opaque source metadata, never credential plaintext. Completed receipts bind
the destination ciphertext revision. Existing reservations never copy again:
**Inspect prior import** checks the exact original revision and authenticates the
reserved destination inside the protected broker. A prepared receipt with a valid
copy can reconcile a lost acknowledgement without writes. Missing, changed or
unauthenticated destinations remain unresolved; neither restart nor retry creates
a second copy. Import receipts also prevent empty-store key replacement.
