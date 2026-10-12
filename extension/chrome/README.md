# Mechanize Chrome transport

Packaged dependency-free JavaScript MV3 backend, with optional origin permissions
and an isolated-world semantic DOM executor. No all-URLs default permission,
externally-connectable pages, page-message bridge, arbitrary scripts, debugger,
downloads or workflow scheduler. `jsdom` is a development-only fixture dependency.

## Supported fixture capabilities

`observe`, `resolve`, `read`, `element.press`, `element.fill`, `element.select`,
`element.check`, `element.uncheck`, `receipt.query`, `executor.quiesce`,
`browser.navigate`, `browser.activate`, `record.start/pause/stop/events`.
Selectors: strict unique ID, test ID, role/name, label and CSS within one bound
document, including open shadow roots. Snapshot: at most 200 semantic nodes,
2000 visited elements, truncated values/names; password and sensitive-name fields
are redacted. Names/roles are an approximate packaged DOM implementation, not the
browser accessibility tree. Custom editors, file uploads/user activation, closed
shadow roots/canvas, trusted input, screenshots, network observations,
tab open/close and browser restoration are unsupported. Dispatch is not business
verification; the broker/Datly effect ledger and qualified outcome adapter own it.

## Explicit fixture installation

1. Build `go build -o /absolute/path/to/mechanize-native-host ./cmd/mechanize-native-host`
   from the module. Load this extension directory unpacked in a **disposable,
   explicitly authorized Chrome test profile**, then read its extension ID.
2. Replace both placeholders in `native-host-manifest.example.json`. Register that
   manifest in the test profile's approved Chrome native-host installation location.
   Do not use wildcards in `allowed_origins`.
3. Create a private mode-0600 host configuration at
   `~/Library/Application Support/Mechanize/native-host.json`, or set
   `MECHANIZE_NATIVE_HOST_CONFIG` to a private configuration path inherited by Chrome:

   ```json
   {
     "socketPath": "/absolute/private/path/broker.sock",
     "extensionOrigin": "chrome-extension://EXACT_EXTENSION_ID/",
     "profileChannel": "fixture-profile-1",
     "browserInstance": "fixture-browser-1",
     "credentialResource": {"URL": "registered-scy-encrypted-resource", "Key": "registered-scy-kms-key"},
     "fixtureEnrollment": true
   }
   ```

   Resource/key strings are deployment-specific registered Scy providers, not
   invented provider schemes. Credentials are loaded through Scy; no plaintext
   credential fallback, argv credential, or extension credential storage exists.
   The Unix broker socket must have mode 0600. The broker must independently verify
   the credential, principal, fixture enrollment and profile grant. Production
   native-host startup **fails closed** without its signed immediate-parent, reverse
   broker and canonical Chrome launch-profile proofs; origin argv alone is only
   an allowlist routing signal.
4. Open extension options, enter the fixed profile/browser IDs and exact allowed
   HTTPS origins (or HTTP loopback origins), then grant access and connect. The
   broker must separately enroll these exact origins; extension UI alone does not
   grant broker authority. Do not use an employee browser for fixture controls.

## Broker protocol v1

Both Chrome stdio and Unix socket use a 4-byte **native-endian** unsigned length,
UTF-8 JSON, maximum 256 KiB/frame. No chunks are supported; large artifacts require
broker artifact handles. Sequential frame I/O supplies backpressure; host quotas
limit each direction to 65536 frames and 64 MiB total per connection, worker limits requests to
4096/channel, content cache retains 512 mutation receipts without eviction.

Extension sends `hello` with `protocolVersion:1`, `extensionVersion`, fixed
`profileChannel`, `browserInstance`, previous `lastGrant`, and known `documents`.
Host overrides/injects `credential`, `extensionOrigin`, `fixtureEnrollment` and
forwards it once. Broker authenticates before replying:

```json
{"type":"enrolled","brokerEpoch":"b1","channelEpoch":"c1","scopeHash":"authorized-scope-hash"}
```

Extension emits bounded `documents` inventory with capability/unsupported lists.
One document request example:

```json
{
  "requestId":"unique-request-1",
  "action":"observe",
  "identity":{"profileChannel":"fixture-profile-1","browserInstance":"fixture-browser-1","tabId":7,"frameId":0,"documentId":"browser-supplied-document-id","documentGeneration":1},
  "brokerEpoch":"b1","channelEpoch":"c1","scopeHash":"authorized-scope-hash",
  "deadlineUnixMs":1790880000000,
  "args":{"limit":100}
}
```

The example deadline must be replaced with a real deadline no more than 30 seconds
ahead. Results contain the fresh identity; `observe` can refresh a stale generation.
Mutation adds `attemptId` and a closed `locator` (for example
`{"strategy":"role","value":"button","name":"Save","exact":true}`), with
`args.value` for fill/select. Browser APIs revalidate top-level and frame origins,
frame/document identity; the content executor validates all fences and the deadline
immediately before synchronous dispatch. Arbitrary `code`/scripts are rejected.

`receipt.query` carries original `attemptId` and document identity, using a new
request ID/deadline. A retained receipt is returned; a missing receipt is `unknown`,
never proof of non-dispatch. Same-attempt identical content returns cached receipt,
changed content is `attemptConflict`. Lost receipts inhibit further mutation in the
worker; the durable broker ledger must maintain this barrier across worker/host
restart. It must never replay unacknowledged work. `executor.quiesce` stops a bound
document permanently and acknowledges it; new-epoch takeover remains blocked until
explicit broker reconciliation/replacement. A changed persisted grant fails closed.
BFCache restore quiesces its executor. Closing a user's tab to regain authority is
never automatic. No claim of durable exactly-once dispatch is made.

## Verification and open gates

`npm ci --ignore-scripts && npm test` runs jsdom fixtures. From module root,
`go test -race ./cmd/mechanize-native-host` tests framing and thin bridge authentication.
No live browser/employee desktop controls run as part of these commands.

Real Chrome native-messaging installation, MV3 restart, renderer suspension,
two-profile/tab reuse, cross-origin iframe denial, permissions revocation,
native file-dialog correlation, signed packaging/update and durable broker/Datly
reconciliation still require disposable-profile acceptance evidence. Unit fixtures
and build success do not qualify a production release.

## Recording and browser lifecycle

Recording requires explicit authenticated start bound to one document and a visible
REC badge. Packaged isolated code captures trusted click/input/change events only;
it excludes injected DOM events, records no key presses, and removes secret values
(including descendants of `data-mechanize-secret`) before buffering/transport.
A 128-event ring, at most 64 events per poll, returns exact overflow gap ranges.
Event lineage binds recording/document/sequence; exact event-object duplicates are
removed, while similar actions remain distinct. CSS viewport bounds are hints for
cross-surface correlation, not native coordinates or proof of duplicate actions.

`record.events` polls with recordingId/afterSequence/limit. Root must persist batches
through Datly and deduplicate immutable lineage there; no product database is used
in the extension/bridge. Polls renew a 30-second consent lease. On expiry capture
stops locally and an explicit recordingLeaseExpired gap is retained. Root should
poll every five seconds while the authorized recording is active. Pause/stop halt
capture; a stopped document recording cannot silently restart. Document/host loss
returns gaps, and an unreachable stop remains stopUnconfirmed until qualified.
Recording is never silently attached to a replacement document.

Navigation uses one Chrome tabs API dispatch, subscribes to completion/error before
that dispatch, checks destination and redirect origins, and waits observationally
for bounded readiness. Readiness is not business success. Tab activation does not
claim physical window focus. Browser intent markers and receipts survive worker
restart in chrome.storage.session; markers retain no URL/value/credential. Missing
receipts and unknown redirects inhibit new mutation. Same-attempt content changes
are rejected. Browser API receipts retain the original document identity and return
the new document separately. SPA history/fragments, completion, tab status/title/
activation/removal refresh inventory; BFCache/popstate/hashchange invalidate
executor generations and recording gap evidence remains explicit.

## Signed Chrome profile launch enrollment (implementation; live gate open)

The production host now requires `profileDirectory` in its private operator config,
and the identical canonical absolute path in the broker grant. This is separate
from `profileChannel`/`browserInstance`, which remain routing identifiers.
The registered native-host manifest must set
`"supports_native_initiated_connections": true`. The disposable browser must be
launched with `--enable-features=OnConnectNative`, an explicit private
`--user-data-dir`, and `--profile-directory`. Enablement is needed because Chrome
parses this manifest field behind that feature. Do not execute the reconnect value.

Chrome supplies a base64 JSON reconnect argument containing its internal profile
path. After the existing native image, immediate signed Chrome parent and reverse
broker proof, the host parses this argument strictly as bounded data, validates its
Chrome executable/host/extension/features and canonical owned profile directory,
and compares it with operator enrollment. Missing, ambiguous, duplicate, unexpected
or aliased values fail closed. An intermediary ancestor cannot qualify launch argv.
The signed host overwrites profile launch evidence in the broker hello; extension
storage is never profile proof. Scy resources still provide all credentials.

The broker's `processQualified` reply reports independent profile proof and carries
a random server-owned connection preparation challenge. The worker freezes its
old grant, refuses a changed persisted fence or unresolved/busy mutations, and
binds every eligible root document from a complete inventory to the immutable
server broker/channel/scope fence. Existing conflicting, quiesced or inaccessible
executors block preparation. Only a matching `executorPrepared` response with no
pending or unknown broker attempt opens document/action dispatch. A reconnect in
the same broker generation may retain matching bindings; a broker restart changes
its fence and requires a future durable reconciliation procedure. This code never
resets persisted fences or claims that unknown old executors were quiesced.

Local inspection on 2026-10-02 found Google Chrome 154.0.8037.97 and signing team
EQHXZ8M8AV. Live native-messaging argv support on that installed version remains an
acceptance gate. Current Chromium source documents the launch argument and feature
condition:
[launch_context.cc](https://chromium.googlesource.com/chromium/src/+/HEAD/chrome/browser/extensions/api/messaging/launch_context.cc),
[native_messaging_host_manifest.cc](https://chromium.googlesource.com/chromium/src/+/HEAD/chrome/browser/extensions/api/messaging/native_messaging_host_manifest.cc).
A passing fixture test does not qualify the installed browser.

Load unpacked from a fixed canonical installation directory, then enroll its exact
Chrome-reported extension ID in both host and broker manifests. Moving an unpacked
extension without a manifest key can change its ID; a release needs its publisher
key and signed package/update policy. No arbitrary development key is a release
identity. The source directory is directly loadable; `node_modules` and fixture
tests are not runtime dependencies. Install and live disposable-page proof must
use the authorized Mechanize surface and consent scope.

## Web controller reverse RPC

Trusted controller origins are managed in Mechanize's native browser panel.
The suggested initial origins are `http://localhost:3000` and
`https://steward.agently.viantinc.com`; the list is configurable.
`localhost:*` permits HTTP and HTTPS on any valid port of the exact `localhost`
hostname. `http://localhost:*` and `https://localhost:*` restrict the scheme.
These patterns do not include `127.0.0.1`, subdomains, or other hosts; add those
as separate exact origins when needed. Enabling and saving an origin authorizes its document-bound
connections automatically. The native panel can disable access, replace the list,
or revoke a connection. Only its authenticated native-human control plane can
change this saved trust. Chrome Options and target website permissions grant no
controller authority.

For an enrolled local signed installation, the fixed console command
`Mechanize.app/Contents/MacOS/MechanizeConsent --trust-localhost-controllers`
adds `localhost:*`, preserves other entries, and verifies saved policy readback.
It uses the existing native enrollment and refuses ambiguous browser channels.

The manifest permits external connection attempts for HTTPS and loopback HTTP.
The worker requires the actual Chrome sender origin, including port, to match
the current broker policy. Only top-level documents are supported. The broker
checks the enrolled channel and native fences, mints a distinct controller client
identity, and sends the existing `controllerApproval` reply. Older clients may
briefly receive `approvalRequired` first; trusted origins need no page approval.
The worker verifies the live Chrome frame/document before accepting that reply
and before every request.

Sessions last at most five minutes from port creation. Navigation, tab closure,
transport disconnection, worker restart, changed/disabled policy, or explicit
revocation ends them. Identical policy synchronization does not extend expiry.
Saved origin trust survives broker restarts; live sessions do not. Each reconnect
must establish a fresh exact document session under that saved policy.

Saved controller trust authorizes ordinary automation within the current allowed
applications and websites without another Mechanize approval. The host creates
bounded session authorization through the existing audited consent components;
it revalidates saved policy, signed connection, owned session and target ceilings
for each admission. Client tool policies, macOS permissions, credential protections
and replay guards still apply. No caller can supply a human-authority assertion.

The reverse lane advertises the MCP `2025-11-25` complete-result boundary and
carries `initialize`, `tools/list` and `tools/call`
through the same canonical Mechanize MCP server used by local clients. The
host's actual negotiated protocol version is returned. The catalog contains
canonical schemas for sessions, capability discovery, observation, script/step
execution, operation status/cancel/outputs, permission request/status, and
origin-scoped tab inventory. Tool calls reuse host policy, Endly runtime,
principal/session ownership and the existing scoped consent service. The controller
cannot approve its own consent or edit native settings.

Each approved port is one locally generated conversation identity. The broker
derives a distinct client identity from that conversation, document, origin and
channel epochs. Caller-supplied client IDs, namespaces or authority are never
accepted. Automation sessions must have been opened by that exact controller;
even older sessions without a client ID cannot be adopted. Revocation or
connection loss cancels in-flight calls and closes that controller's runtime
sessions without replaying uncertain effects. Cleanup failure inhibits further
MCP controller calls and is exposed in native controller state as
`cleanupPending`.

The host dispatches reverse calls asynchronously so a tool can use Chrome and
receive its executor response over the same native channel without deadlock.
Calls are bounded to ten seconds, 48 KiB of arguments, one active canonical call
per conversation, eight automation sessions per conversation, and the
connection/session quotas above. Small results use one frame; negotiated image
results preserve canonical MCP text/image order, MIME types, annotations and
structured business metadata. Host and content-block `_meta` are withheld.
Results are capped at 12 MiB of serialized JSON and 8 MiB of decoded image bytes
in aggregate. Larger results use at most 128 chunks, each carrying at most
96 KiB of result bytes (about 129 KiB after base64 and framing), without changing
the ordinary 256 KiB native frame limit. Original request/session/fences, deadline,
sequence, total size and SHA-256 are verified before one result is published.
Incomplete, corrupt or expired transfers produce a closed terminal unknown
outcome; no tool is retried. At most 24 MiB of result assembly is reserved at
once. The native forwarder retains per-frame validation instead of disconnecting
a healthy connection after a cumulative byte or frame count. Long automation runs
are started asynchronously and inspected with canonical operation status tools.
Unknown or rejected tool errors use a closed public vocabulary. Script
validation withholds the compiled plan; operation errors and raw business keys
are not echoed. Ordinary observations retain existing host/renderer redaction
and private-document barriers. Credential documents and credential values remain
on the separate private local Vault delivery route; no credential methods or
native-human authority are exported to the web controller.

### Local connection diagnostics

The options page can also **Open a website** when the connected browser has no
ordinary web tab yet. This requires a trusted click in the extension's own
options document, an already enrolled origin, and existing Chrome host access.
Only HTTP(S) origins are accepted; paths, queries, fragments and embedded login
details are refused. The new tab opens in the background so the local status can
be verified, then MCP can discover it through its origin and opaque tab handle.
This UI action adds no broker authority and does not read or store credentials.

The extension options page provides **Read connection diagnostics**. It reports
the reconnect phase and whether credential protection, lifecycle retirement, or
an unfinished reconnect journal is present. This is a read-only request from
the extension's own top-level options page. It does not inspect website tabs,
request permissions, change enrollment, or clear recovery records.

The diagnostic response contains only fixed enums and booleans. Origins,
credential values, document identities, receipts, and raw errors are excluded.
An unavailable diagnostic clears the previous displayed result. `pending`
means a reconnect transaction was interrupted; it is not evidence that website
access was denied, and deleting extension storage is not a recovery procedure.

An interrupted reconnect retains the original pending journal, receipt identities,
and archived history. With `reconnectBindingsVersion: 1`, the authenticated Host
holds admission through local journal commit and the exact existing
`executorPrepared` acknowledgement while a Datly-owned serializable snapshot enumerates every client
and epoch in the exact enrolled channel and scope. Keyset pagination proves
exhaustion; capacity or cancellation returns no partial proof. Bounded native
frames carry only original source identity, fence, attempt digest and dispatch
state. Business outcomes remain unchanged, including unverified and UNKNOWN.

The worker independently checks a stable Chrome tab/frame census. Active opaque
or non-HTTP child frames, including failed child navigations, retain their Chrome
document ID and validated parent chain as non-executable metadata; they receive
no injection or input authority. A failed child with missing document identity
remains an explicit unknown entry: any original-source absence proof that could
depend on it is refused. Root navigation errors remain a separate refusal.
An original source document found anywhere in the census, including another tab
or an opaque child, is never counted absent. Root URL, root/tab origin mismatch,
child URL and built-in New Tab refusals have separate finite diagnostics without
exporting URLs or page content. A live source
needs an exact known receipt and a responsive idle executor; a missing source
needs independent document absence. A still-live executor frozen by older code
cannot answer its receipt query and stays inhibited. Unknown/inaccessible frames,
private live sources, malformed history, changing fences or receipt snapshots also
deny recovery. A structurally valid reserved intent with no outcome remains
UNKNOWN; a live source blocks, and only independent original-document absence
can permit a new executor without modifying or replaying that intent. No tab is closed or reloaded by recovery. Protected bank documents
and native capture retain their separate exposure gates.

Future pending journals record the selected eligible source inventory before
prepare (not a claim of complete private-document inspection). Unrelated DOM
mutations may advance generation during quiesced adoption; document identity,
fences and receipt revision must stay fixed and the old lease remains retired.
The committed journal records the final generation. Older brokers retain the
setup-only recovery path. No recovery path replays a website action.

Tests combine real disposable Chrome/content/worker census and adoption with
synthetic native replies, and separate real Unix broker, Host and generated Datly
snapshot tests. These do not prove that an arbitrary legacy live document can be
recovered, and never inspect a user's Chrome profile.

### Browser-side MCP transport SDK

`controller-transport.js` implements the MCP JavaScript SDK transport interface.
It is a **separate source module to bundle into the web shell**, not an extension
runtime file or web-accessible resource. Configure the consuming application to
select this transport in the browser and supply the installed extension ID:

```javascript
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { MechanizeExtensionTransport } from "./controller-transport.js";

const transport = new MechanizeExtensionTransport({ extensionId });
transport.onapprovalrequired = () => showNativeApprovalInstructions();
const mechanize = new Client({ name: "my-web-agent", version: "1" });
await mechanize.connect(transport);
const catalog = await mechanize.listTools();
const session = await mechanize.callTool({
  name: "mechanize_session_open", arguments: { name: "Current conversation" }
});
```

One transport instance/port belongs to one conversation. Requests are serialized
through a bounded FIFO queue. An SDK cancellation closes the conversation and
cancels its owned sessions; use `mechanize_operation_cancel` for a specific
automation without closing the connection. A framework can select
it with a browser-execution setting and extension transport configuration;
registering that adapter in agently/agently-core/forge remains a consuming-shell
integration step. This repository does not claim those products already
understand an invented configuration field. There is no bearer token, local
HTTP port, public fallback, automatic controller-conversation reconnection or action replay. The extension’s separate native metadata connection does retry automatically as described below.

The SDK contract test runs with the official MCP JavaScript SDK when
`MECHANIZE_MCP_SDK_PATH` points to its installed package directory. The ordinary
JS suite also tests negotiation, closed results and disconnect behavior without
requiring that optional dependency.

Remaining scope: persistent native controller preferences, configurable
native-owned approval duration, embedded-frame support, AG-UI event adaptation,
and integration of this generic transport with each consuming framework. The
current five-minute approval is intentionally still document-scoped; it is not
persistent “trust until revoked.” Large captures and unrelated state/recovery
administration tools are outside this bounded controller catalog.

## Browser protocol pointer input

Version 0.1.6 adds Chrome's required `debugger` permission. Chrome does not allow
this permission to be optional. Reloading/upgrading the extension may require
Chrome's permission approval before the extension can run.

The adapter accepts only fixed mouse move/down/up and named key down/up
commands. It exposes no arbitrary CDP API, evaluation, cookies, network data,
page reads, screenshots or text input. The currently wired public route is a
v2 `element.press` on an eligible top-level document. DOM observation locates
and scrolls the target, checks stable geometry and the hit target, then the
worker admits exactly one browser-protocol click under the original command,
renderer lease and document identity. Legacy fixtures retain DOM delivery.

An uncertain protocol result blocks subsequent input. Cleanup sends only the
matching release event, using its own bounded deadline. Session metadata keeps
uncertain attempts across worker restart; input is never transparently replayed.
Cursor presentation remains independent of action completion.

Vault delivery remains a separate private local protocol. The public pointer
adapter refuses credential-protected documents, and no credential value enters
its messages, results or logs. Browser-protocol credential delivery and the
public named-key route still require integration and live qualification.

### Repeat private login admission

Retained origin quarantine continues to exclude a website from ordinary tab
inventory and observation. A separate `credentialCandidates` inventory carries
only an exact root document identity and HTTPS origin to the signed local broker;
it contains no title, path, DOM, labels or values and is not exposed through MCP
browser tab listing. Unknown fields and foreign scope are rejected.

A current reusable control grant and native exposure protection remain required
before private inspection or delivery. The broker selects exactly one candidate,
seals private reply demultiplexing before retaining its lease, and the worker
checks the current root document before and after binding. Existing private or
unknown attempts cannot be replaced. A protected executor containing previously
written input cannot be rebound through this path. Quarantine is retained.

Missing candidate metadata leaves preflight pending without creating a durable
credential protection barrier; opening an eligible document permits the same
preparation to continue. No fill or submit is retried automatically.

### Same-document post-submit status

A dispatched private submit does not prove login success. The private receiver
can classify the same bound document as pending, rejected, challenge or a privacy
candidate without reading input values or returning page text. Status reads do
not submit again or acquire replacement input authority. A same-document reply
can never admit the next credential fill.

A privacy candidate still requires independent qualification and an explicit
commit: credential/challenge controls must be absent, the original private input
lease must be retired, and the original secret variants must be installed in the
isolated-world redactor. Only then may DOM-only observation be admitted. Native
observation, screenshots, recording and other documents remain protected. The
original dispatch and preparation audits remain unchanged.

Explicit navigation from a qualified public source may target a quarantined
HTTPS origin's root URL. Quarantine is retained: the destination remains absent
from ordinary inventory and cannot be observed or controlled publicly. The
navigation receipt contains only routing identity, with a blank title; the
worker never reads the protected title. Paths, queries and fragments are refused
for this route. Private credential admission is a separate subsequent operation.

### Private recipient pins

Worker build 22 supports private credential inspector protocol 3. The broker
supplies a fresh opaque recipient nonce during the initial metadata-only probe.
The isolated content executor retains the actual form, credential fields and
submit control in a private closure. Fresh probes and delivery must carry that
same nonce under the original document, channel, consent and renderer lease.
The pin rejects replaced controls, altered form/submit targets, field metadata
changes, ambiguity and authentication challenges. It reads no credential values.

An unrelated DOM update may advance the page generation without changing the
pinned recipient. Only the negotiated private path accepts that advance;
ordinary automation and legacy credential delivery retain their exact generation
checks. The nonce never appears in MCP credential results, and a matching pin is
not login or business-success evidence. Interrupted or unknown delivery remains
protected and cannot be replayed. Legacy navigation binding hashes are preserved.

## Automatic native connection

Website permission and native connection are independent. **Save website access**
requests missing website permission only from a trusted Options gesture. **Connect
/ Retry** uses saved enrollment without changing it or requesting permission.
Automatic connection is enabled by default and can be disabled in Options.
Options does not need to remain open. Existing unpacked installations need a one-time extension reload to load version 0.1.39; later backend outages use this automatic lifecycle.

| State | Automatic transport behavior | Executor authority |
| --- | --- | --- |
| No valid saved enrollment / disabled | Stop retries; wait for explicit settings change | None |
| Saved enrollment, native host offline | Retry after 1, 2, 4 seconds, then 1, 2, 4, 8, 15 minutes; cap at 15 minutes | None |
| Native port open, handshake pending | Bounded 15-second handshake; close/retry if unanswered | None |
| Authenticated metadata, qualification refused | Keep metadata available with closed attention reason | None |
| Qualified current scope and reconciled executor | Keep current port; no periodic reconnection | Existing normal lease admission remains required |
| Private work, unknown receipt, retained lifecycle or invalid journal | Metadata connection is permitted; original recovery gates remain | No document publication or input qualification |
| Website permission revoked / enrollment changed | Invalidate old port and grants; retry metadata for current settings | Requalification requires current Chrome permission and all original proofs |

A named `mechanize-native-reconnect` Chrome alarm backs short in-memory timers so
MV3 suspension cannot lose the retry. The `alarms` permission schedules wake-ups;
it grants no website access. Chrome 106-compatible alarms are at least one minute
away. Each worker startup checks the alarm; browser startup and explicit Retry
can wake the connection immediately. Scheduler storage contains only a version,
attempt counter, next retry timestamp and closed phase. It contains no commands,
URLs, document IDs, credential values or receipts.

Transient host/socket failures retry automatically. Missing enrollment, disabled
connection, missing website permission, trust/configuration errors and retained
recovery barriers remain visible as distinct attention states; another transport
attempt does not repair or bypass them. The scheduler retries only `hello` and
normal qualification, never an application command. It never deletes receipt,
private-attempt or reconnect history. Disconnect clears ephemeral private
material, while durable origin quarantine and unresolved receipts continue to
block ordinary document access until separately reconciled.

The isolated Chrome lifecycle test uses actual service-worker restarts, storage,
permissions and alarms with a synthetic native-port adapter. It covers an offline
backend longer than one second, reconnect, changed backend epoch, worker restart,
disable/re-enable, no Options page, no permission requests, one active port and no
input replay. Native host process authentication remains covered by the separate
broker/native-host tests; this fixture does not install a native messaging host.

## Focused loaded-tab comparison

Version 0.1.37 introduced `focusedLocationVersion:1`. The public
`mechanize_browser_location_matches` tool accepts an owned session and one
expected origin under existing Observe consent. It returns only availability,
a Boolean match, a closed reason, and explicit extension-window evidence when available: `extensionFocusedTab`
when that window is focused, otherwise `extensionLastActiveTab`. The Boolean
`windowFocused` makes the distinction explicit. A matched authorized origin may include its opaque profile/browser/tab
handle. A mismatch does not reveal the other origin or its tab identity.

The extension prefers its unique focused normal window, otherwise its last active
normal window, and samples that window’s active fully loaded tab twice within a 1.5-second request budget. Pending navigation,
missing URL permission, private/incognito or discarded tabs, userinfo, unsupported
schemes, focus/tab/origin drift and ambiguous metadata refuse. URL parsing and
comparison stay in the worker: addresses, paths, queries, fragments, titles and
page contents never enter the reply. It does not read the physical omnibox,
verify OS foreground, inspect a page, clear credential protection or grant input.
Authenticated metadata remains usable with zero public documents or retained
private/unknown/lifecycle barriers. Older workers return `unsupportedWorker`
without waiting for the request deadline.


## Scoped credential protection (0.1.39)

`protectionScopeVersion:1` binds a new private preparation to its exact enrolled
profile/browser/tab/root document and a SHA-256 commitment to the login route
(origin plus pathname). The extension captures it under the existing private
renderer lease before any fill. Query strings and fragments are excluded; raw
routes stay in extension-local protection storage and are never tool results.
The Host stores an immutable source association in the additive preparation-scope
table; original preparation, intent, receipt and UNKNOWN histories remain intact.

Ordinary work on a proven disjoint tab uses normal consent, document binding,
sensitive-field filtering and its own execution lease. It neither borrows the
credential lease nor requests fresh Vault entry. Known credential variants remain
in the local output redactor across source promotion and disjoint operations.
The former credential document still requires the existing explicit private-to-DOM
redactor proof. A returning login form or challenge revokes that document’s public
permit before an ordinary read/input; unrelated password fields retain normal
field filtering. Native capture/access remains subject to its independent exposure
guard.

Legacy origin-only entries stay restricted to their affected origin. They are not
silently rewritten by a new capture. An explicit new-login request may retire
exposure protection only after independently proving every owned original source
tab/document absent (or its original process birth absent), with current reusable
consent. This updates protection state only; outcomes, unknown effects and replay
barriers are retained. Missing or ambiguous proof keeps protection in place.

Cleanup pins the exact authenticated process/channel for its held context: full
signed verification brackets the cleanup, each exchange rechecks kernel identity,
and every absence guard still queries Chrome. There is no TTL, global process
cache or cached document-absence claim. The isolated real-Chrome regression proves
source capture, both credential canaries redacted in a separate same-origin tab,
source absence, and admission of a new login with one new fill and no old submit
replay. Its native process verification is a test adapter; the performance test
adds 90 ms per full signed-verifier call while retaining actual Chrome IPC.

## Private inspection diagnostics (0.1.40)

The negotiated `privateInspectionDiagnosticVersion:1` adds only a finite cause to
a failed private preflight. The inspector's v2/v3 renderer envelope remains
unchanged, including when an older executor is already injected. After a valid
negative reply, a fixed extension-owned ISOLATED helper can classify metadata-only
predicates such as missing form, ambiguous credential fields/submitter, unsafe
form/submitter, and hidden versus visible challenge controls. It returns no field
labels, counts, values, addresses, page text or thrown errors. If those predicates
pass but the old executor refuses, the result identifies its binding/protection
boundary. A known challenge stage remains visible. These causes never grant
input permission or relax a form predicate.

A failed preparation with no captured source is recoverable only after an owned,
complete zero-child durable snapshot proves that no private attempt was reserved,
and the broker independently proves no pending private admission/input, unknown
attempt or retained control. The typed cleanup retires preparation protection only.
Any child attempt or retained authority excludes this path and requires the
existing exact-source recovery proof.
