# Chrome CDP integration

Mechanize's Go Chrome backend sends typed browser actions over its enrolled
native-messaging channel. The extension resolves the target and uses
`MechanizeCDP` for Chrome debugger attachment and command delivery. Mouse and
key input use this shared transport through `MechanizeBrowserInput`.

The transport follows the per-tab session approach reviewed in Playwriter:

- Reuse an attached debugger session across actions.
- Invalidate session handles and outstanding calls when Chrome detaches.
- Treat Chrome's user-cancelled debugger session as stopped across all tabs.
- Bound calls by the action deadline without replaying timed-out commands.
- Track attached child sessions before allowing child-session routing.
- Retire late attachment results rather than resurrecting expired sessions.

Consumers supply method policy. The current input consumer allows only mouse
and key event commands. CDP responses and events remain internal; they are not
returned as unrestricted MCP output. Vault delivery and redaction keep their
existing separate local path.

## Playwright integration in progress

The intended browser execution path is:

```text
MCP typed action → broker admission and intent → local Playwright engine
                → private CDP relay → enrolled Chrome extension → owned tab
```

Playwright runs locally in Node, outside the extension. The extension transports
CDP to the selected tab. The broker remains responsible for user/session binding,
Vault quarantine, durable action identity and receipts. Accessibility and RobotGo
remain separate native adapters selected through the same MCP interface.

The implementation under `browser/playwright` is being developed. Installing
`playwright-core`, connecting an isolated fixture, and wiring the production MCP
path are distinct milestones. Production support must remain unavailable until
the real host and extension relay are wired and verified; callbacks supplied only
by tests do not establish production integration.

The relay is private and scoped to one admitted tab/document. It must not expose
an arbitrary JavaScript or CDP tool to an MCP caller. Vault values travel only in
the separate local credential channel. Public observations and engine results
must pass the existing privacy boundary before reaching any model.

For development packaging, `scripts/build-development.py --playwright-node
/absolute/path/to/reviewed/node` adds the self-contained Playwright JavaScript
runtime to the app resources. It downloads nothing. The selected local Node
executable and the entire runtime tree are hash-pinned; Node remains an explicit
local dependency in this development configuration. The unified manifest carries
the reviewed `chrome.playwright` configuration for installation. Ordinary builds
without this option retain the existing executor and do not advertise Playwright.

### Required verification before live website use

Use a disposable local fixture and the production MCP action path to verify:

1. Protected login, document or SPA transition, and independently proved public
   readiness, with credential canaries absent from all model-facing outputs.
2. Filter, expand a row, repeat a previous record, edit fields and reach a review
   screen using Playwright locators rather than manually traversed snapshots.
3. Short action deadlines with measured admission, execution, verification and
   end-to-end times. Human approval waits have their own visible bounded state.
4. A lost reply before input reports no dispatch; a lost reply after actual input
   remains uncertain and is inspected without replay. Pointer movement and
   actionability checks alone must not create an uncertain application mutation.
5. Navigation, detach, restart and revoked authority invalidate stale handles.
   Saved trusted controller origins survive restart and authorize fresh bounded
   document connections; live sessions are not restored. Tool consent remains separate.
6. Agently discovers tools through its browser proxy, invokes them under the
   original call/session IDs and receives verified results. A catalog failure is
   shown in the conversation before a model request is sent.

RobotGo remains the native window/desktop fallback. A CDP input receipt proves
dispatch, not the application's business outcome; callers must verify the new
page state before continuing or retrying an uncertain action.

Reference: Playwriter commit `525732a474a14224d46469c2b85737dbcdc23e07`;
see `third_party/NOTICE.md` for attribution.

### Local Node runtime enrollment (Go source)

`chrome.playwright` is optional and disabled when absent. Enrollment supplies
`nodePath`, its exact `nodeSHA256`, `runtimeRoot`, and `runtimeSHA256`. The runtime
hash is `playwrightipc.RuntimeDigest`: sorted relative file names plus each
SHA256, including the pinned dependency tree. Paths are canonical; symlinks,
nonregular files, wrong owners and group/world writable files are refused.
Qualification is rechecked before each local child starts. The environment is
restricted, stdout is bounded private JSON IPC, and stderr is discarded.

The broker uses this child only for typed exact `element.press`, `element.fill`
and text reads after its existing admission and mutation binding commit/readback.
It requires an authenticated extension advertising `playwrightRelayVersion: 1`;
configuration alone does not establish this capability. There is no raw CDP or
JavaScript MCP tool and no alternate reservation of the original attempt.

Each private relay is bound to the original command, port, document, lease,
fingerprint and epochs. Movement/actionability checks do not mark input. Actual
input writes may create uncertainty; an exact extension no-dispatch rejection
can establish absence for that request. A successful mutation receipt requires
extension journal acknowledgment before entering canonical broker history.
Lost input replies retain the original unknown attempt and cannot be replayed.

An independently qualified post-login `redacted-dom` privacy permit remains
eligible for ordinary DOM operations. The broker revalidates its exact document
and private guard; the extension sanitizes returned text using its own secret
redactions before any string reaches a model. Private input remains separate.

`playwrightLocatorVersion: 1` additionally qualifies explicit `nth` with bounded
index 0–999 and `order: "document"`. This advertises `web:indexedQuery`, not
arbitrary ancestor scopes or all-result ordering. Original fingerprint bytes are
unchanged when these optional fields are absent. The locator is resolved afresh
and its exact handle is guarded; unrelated monotonic same-document DOM changes
inside that privately admitted semantic execution do not grant a new lease or
permit reuse of an opaque snapshot reference. Subsequent operations retire the
original lease and freshly admit the observed document generation.

The opt-in `TestIntegratedPlaywrightGoWorkerAndActualCDP` fixture connects the
production Go gateway, committed original attempt, hashed Node runtime, actual
Playwright, canonical worker and actual content observer to isolated HTTPS
headless Chrome. It verifies duplicate-row controls, independent row reads,
eight confirmed inputs and retirement between generations, continuous decorative
DOM changes with concurrent normal inventory publication during an admitted
semantic operation, the canonical pinned-target input boundary, reflected private
text refusal, and a ninth lost input acknowledgment that remains unknown without
replay. Enrollment/process evidence and the Go privacy-publication authority are
test adapters. This does not qualify installed native enrollment, real Vault
login, external MCP transport, or a particular real website; those need live
verification before claiming the complete workflow is ready.

### Scoped process verification for one local execution

Full signature/resource qualification runs before the private Playwright child
is admitted and again immediately before each actual input boundary. During that
one active operation, callbacks recheck the Unix socket's actual kernel PID,
process birth, UID, executable path and exact ancestry graph twice. The private
proof also requires the same connection, enrolled evidence, actor, consent,
original pending request, lease and broker/channel/scope fences. It is discarded
on completion, revocation or reconnect; no session-wide cache, TTL or caller
claim can reuse it. Legacy paths continue to require full verification. Declared
action deadlines, target guards, protected output and unknown-effect barriers
remain unchanged. Static failure diagnostics distinguish full peer checks from
fresh identity checks without returning parameters or process/provider output.

### Ordinary lease admission when the DOM generation changes

The renderer checks `executor.acquire`'s document generation before installing
its lease. A decorative DOM update can therefore reject acquisition without any
application input or renderer lease installation. This differs from a lost
acquisition acknowledgment, which cannot establish whether a lease exists.

The broker recognizes a no-install rejection only from the authenticated pending
acquire request's exact closed reply: correlated request ID, the same six-field
document identity with a newer generation, and `staleGeneration`,
`notDispatched`, `none` error states. Extra fields, duplicate keys, a substituted
document, missing proof, or an ambiguous reply cannot authorize cleanup. Only a
newly created, unchanged broker reservation with no pending/unknown actions or
attempt bound to that lease can be removed. All receipts, private redaction,
other leases and lifecycle barriers remain intact.

At most three metadata admissions share the original caller deadline and pinned
document/channel/process scope. A known rejection at the retry limit reports no
retained acquisition, so the Host does not report it as uncertain dispatch before
there is an active consent dispatch binding. Lost acquisition replies still
retain their exact authority. Business input is never retried by this path.

`TestRealChromeOrdinaryLeaseAdmissionGenerationRetry` forces two actual content
observer generation changes after private login and before ordinary acquisition.
The third admission succeeds, redacted reads remain available, and the original
fill/submit counts stay unchanged. Closed-reply, retry-limit, lost-reply and
concurrent-authority tests cover the broker boundary; provider tests verify that
known rejection does not invoke dispatch cleanup. This prevention does not clear
an already inhibited session or reconstitute a private proof lost on disconnect.
