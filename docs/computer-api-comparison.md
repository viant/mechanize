# Computer API comparison

Local source inspection on 2026-10-10 examined the installed OpenAI Chrome
plugin's `scripts/browser-client.mjs` and `scripts/browser-service.mjs` under
`~/.codex/plugins/cache/openai-bundled/browser/26.1002.51308`. These are bundled
client/service implementations, not a complete extension source checkout.
No implementation was copied into Mechanize.

## Verified recovery and workflow comparison, 2026-10-10

The installed service bundle provides concrete implementation evidence:

| Source location in `browser-service.mjs` | Observed behavior | Mechanize consequence |
| --- | --- | --- |
| `resolvePlaywrightSelectorNode`, around line 1266 | Resolves the current target under one deadline; bounded retry can be disabled. | Do not preserve an obsolete node or reject an entire session because an unrelated DOM node changed. |
| Frame/context event handlers, around line 1266 | Invalidates the affected frame's cached execution/helper state on navigation or detachment. | Keep browser/tab ownership separate from renderer-generation readiness. |
| `performPointerAction`, around line 1321 | Checks visibility, enabled state, stable geometry, scrolling and hit target before dispatch; dispatch is outside the locator retry loop. | Retry only demonstrably pre-input work. Unknown input still needs reconciliation. |
| Injected-helper recovery, around line 1473 | Drops stale context/helper state and reinjects after classified context loss. | Repair the affected execution context, not the complete browser connection. |
| `n0`/`uM`, around line 1662 | Polls within the original deadline, using at most approximately 100 ms waits. | Do not restart the timeout at each layer or use long unconditional sleeps. |
| Accessible-name utilities in the bundled Playwright helper | Uses the accessible-name algorithm shared with semantic selectors. | Observation names must round-trip through the action locator; raw `textContent` is insufficient. |

These are observations from the installed client/service bundle, not claims
about every backend, extension release or failure mode. Reuse the public
Playwright primitives and the architectural patterns; do not vendor the bundled
proprietary service implementation.

A live user-authorized workflow on an already authenticated application then
completed through OpenAI Chrome. It inspected scheduled items, searched history,
expanded a matching row, opened the repeat form, changed two public fields, and
reached review. Application-specific identifiers and financial records stay out
of this repository.

| Operation | Measured API elapsed |
| --- | ---: |
| Open scheduled items | 3428 ms |
| Back navigation | 10172 ms |
| Open history | 656 ms |
| Search fill and Escape | 363 ms |
| Expand exact matched row | 626 ms |
| Open repeat form | 555 ms |
| Fill two public fields | 410 ms |
| Advance to review | 508 ms |

Dashboard-to-review wall time was 181389 ms; dashboard-to-confirmed-result wall
time was 280447 ms, including model orchestration and user authorization. This
single run is not a general latency benchmark. Advancing the particular form
also requested external authorization; the application-specific workflow must
classify that control accordingly rather than assume every "Next" is harmless.

Observed Mechanize defects prevented the equivalent workflow:

1. Observation text concatenated adjacent content without the accessible-name
   separator, so an exact role/name action could fail for a visible element.
2. A correlated `executor.acquire` stale-generation rejection occurred before
   installing a renderer lease. The host retained its provisional reservation
   and reported dispatch-cleanup uncertainty before any durable input attempt
   existed, inhibiting later control.
3. The Playwright adapter rejected a zero-match target immediately, before
   Playwright could wait for delayed rendering. It now waits only before input,
   within the original deadline; ambiguous matches still fail.

The acceptance test for remediation is a dynamic, synthetic page with split
accessible labels, delayed rendering and changing unrelated content. It must
complete the same semantic workflow, retain one deadline, preserve private
redaction, and never replay input after a lost acknowledgment. Passing isolated
parser or mock tests is not sufficient to claim live equivalence. The combined
actual-Chrome fixture now passes with split labels, a 250 ms target delay,
20 ms unrelated DOM updates, and a lost input acknowledgment that remains
unknown without replay. The serial Playwright suite passes 23/23; two parallel
fixture runs exceeded their existing short startup deadlines under contention.
No production timeouts were increased.

Accessible names now use pinned MIT `dom-accessibility-api` 0.7.1 through an
inert sanitized projection. Private or editable-value-dependent names are
omitted rather than guessed. Generic business identifier fields remain public;
password, OTP and local sign-in context still activate credential protection.
The standard package inventory also now includes the five previously omitted
worker imports and the generated provider, with exact legacy upgrade sets.

## Credential lifecycle follow-up

Further inspection of the same installed browser-service bundle found a
credential-protection object tracked by tab ID. Its disposal removes its own
interceptors/listeners and deletes the active entry only if that entry still
refers to the same object. A rejection-cleanup path navigates the exact affected
frame to a blank document and verifies a navigation event, frame identity and
changed loader identity before disposing protection. This is evidence about
that path, not proof that all OpenAI recovery paths behave identically.

Mechanize's retained credential proof can refer to an original login document
after navigation has replaced it. Requiring the entire tab or browser process
to disappear disrupts an otherwise usable session. A replacement document must
not inherit the old lease.

The source now negotiates `manualPrivacyDocumentVersion: 1`. The existing
private recovery lane can prove the original document absent using bounded,
complete tab/frame metadata, then bind and commit fresh redaction to one exact
successor on the approved origin. It checks that successor through all phases.
Older peers still require whole-tab absence. A same-document SPA route change
does not qualify; active leases, unknown effects and changing successors remain
refusals. This recovery performs no input and does not prove authentication.

Actual Chrome fixture tests passed for both whole-tab absence and same-tab
document replacement, including a worker restart and fresh broker/session.
They also checked repeated redactor commits, unchanged input counts and
login/challenge refusals. Native transport trust in that fixture uses test
adapters. The signed runtime update was installed with extension source version
0.1.44. The user's Chrome worker still needs to load that version; live-session
recovery and equivalent workflow latency remain unverified.

## Observed patterns

- A locator operation serializes one typed command with browser/tab identity,
  selector and deadline. Successful input invalidates cached collection reads.
- Tab attachment promises are shared; detach events invalidate tab/session state.
- Attachment attempts enable CDP focus emulation for the selected tab.
- Browser clicks use CDP move/down/up with a bounded deadline, release cleanup
  after a dispatched down, and navigation event tracking.
- Visible pointer updates are distinct from protocol input dispatch.
- The inspected click deadline helper defaults to 3000 ms. This is not evidence
  that every browser command or complete user task has that duration.

## Live baseline

One warm run on a disposable localhost form through OpenAI Chrome measured:
fill 26 ms, click 266 ms, outcome snapshot 9 ms. The result was visibly
`Applied: Public comparison`. The 301 ms sum excludes setup, model scheduling,
and cold-start costs; it is not a statistically representative benchmark.

Mechanize did not dispatch the paired action because reconnect qualification
reported `storedFenceMismatch` after a signed broker update and Chrome relaunch.
This is a reconnect failure, not a measured input-latency result. The comparison
must be rerun on the same tab/profile after qualification succeeds.

## Mechanize changes and remaining verification

The initial `sdk/computer` adapter provides target-oriented state and actions,
invalidates numeric indices after input, polls one original operation, and
reports content-free timings. It preserves broker consent and Vault boundaries.
Unknown actions are not replayed.

A tested worker reconnect fix allows an explicit metadata connection retry while
dormant origin quarantine remains held. Active private work, unresolved receipts
and lifecycle barriers still deny retries. Live qualification remains to verify.

Background focus emulation is under investigation. A source match alone does
not prove that it explains Mechanize's earlier inactive-tab actionability timeout.

## Native Computer Use source and comparison

The installed `@oai/cua` package also includes JavaScript modules under
`dist/project/cua/sky_js/src/targets/mac/`: `client.js`, `native-pipe.js`,
`get_app_state.js`, `click.js`, and related action wrappers. They send typed
app-scoped requests through a reused, serialized native IPC transport with
request IDs and deadlines. State requests support diffs and return a combined
text/screenshot result. The actual macOS executor is compiled; its full source
was not found. These wrappers do not establish its internal AX/input algorithm.

The native Applications→Browsers tab transition in Mechanize was verified with
both providers on three runs:

| Provider | Run 1 | Run 2 | Run 3 | Scope |
| --- | ---: | ---: | ---: | --- |
| OpenAI native | 603 ms | 816 ms | 828 ms | click + state API calls |
| Mechanize | 1664 ms | 1789 ms | 1738 ms | broker preparation + input + checked-state postcondition |

Mechanize's complete polling API loop on runs 2–3 was 2199/2123 ms; those values
include IPC/polling beyond broker stage timing. Model scheduling is excluded
from both measurements. Mechanize execution alone was 1235/1350/1313 ms.

Source investigation found three target RPCs (enumerate, snapshot, press),
multiple doctor calls, and repeated identical foreground AX readiness checks
within each doctor reply. Consolidating those identical checks within a reply
is a bounded optimization; exact contribution still needs measured validation.

After installing per-doctor-reply readiness deduplication, three verified native
runs measured 1234/1148/1168 ms in the broker and 1608/1493/1540 ms in the full
MCP polling loop. Median broker time improved from 1738 to 1168 ms (~33%).
Execution alone measured 907/810/773 ms. Each run independently verified that
the Browsers radio/tab was selected. These samples establish a local improvement,
not general performance across applications.

## Native Chrome fallback while the extension is disconnected

The same disposable public form was loaded in Chrome's native window. Physical
window inventory reported `Mechanize comparison`, while AX reported `Mechanize
comparison - Google Chrome - Adrian`; exact AX scoping required the latter.
Native AX fill succeeded with verified replacement in 624 ms (broker timing).
The button's semantic press was rejected before dispatch because Chrome did not
advertise the exact AX action. A fresh one-use screenshot click then dispatched
in 510 ms (58 ms preparation, 451 ms execution). OpenAI's independent DOM snapshot
confirmed `Applied: Public comparison` afterward.

That external observation proves the fixture changed, but the Mechanize click
run remains durably unresolved because its plan did not declare a postcondition.
Do not replay it or present it as a broker-verified business outcome. Capture,
model interpretation, and tool round-trip time are excluded from the 510 ms.
