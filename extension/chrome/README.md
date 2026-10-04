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
