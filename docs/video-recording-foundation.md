# Native video and business-flow draft foundation

This implementation is opt-in source infrastructure. It is not registered in
`main.swift`, host configuration, MCP tools or the installed release. No employee
recording, OS permission request, screenshot, external upload or live replay was
performed to develop or test it.

## Implemented boundaries

- `ScreenVideoCapture` uses macOS 14 ScreenCaptureKit `SCStream`, not macOS 15
  `SCRecordingOutput`. It can capture all inventoried permitted displays, the
  exact application's filtered displays, or one exact bundle/window. It checks
  Screen Recording permission and uses explicit visible permission-request API.
  Audio is disabled, cursor capture is disabled, frames are limited to 2 per
  second, maximum 1920 pixels per dimension and queue depth 3. Completed screen
  frames pass through a mandatory trusted local redactor before a synchronous
  sink. Missing redaction pauses and tears down capture. There is no plaintext
  movie file or temporary-file ownership problem: pixels remain in bounded
  memory and only immutable encrypted artifacts leave the sink.
- `VideoRecordingBudget` binds namespace/client/session/grant and exact `record`
  mode plus desktop/app/window scope. Monotonic duration, byte and frame limits
  apply across all displays. Pause and revoke are terminal; stop uncertainty is
  explicit. Frames carry sequence, wall timestamp, monotonic offset and display.
- `VideoFrameIngestor` integrates with existing `ArtifactService.publishBound`:
  encrypted artifact bytes and existing generated Datly publication own all
  durable writes. A trusted callback must verify the pixel-record grant before
  start and every frame. The same owner/client/session and retained record lease
  bind ingestion. Redaction is mandatory and decoded JPEG dimensions/size are
  bounded. Invalid lineage, cancellation, exhaustion and publication uncertainty
  pause ingestion; immutable references survive unknown metadata publication.
- `VideoTimeline` validates bounded silent frame metadata and correlates frames
  with existing AX/browser event timestamps. Correlation is explicitly temporal
  context, not actor/action attestation. Pure draft helpers validate structure;
  authenticated artifact reads/verification remain the host's authority.
- `DraftBusinessFlow` invokes the existing shared DSL compiler. It produces a
  user-declared goal, observed/unattested steps, evidence links, proposed actions,
  proposed checkpoints, gaps and editable DSL. Decisions and business outcome
  require independent review rather than guesses from pixels. No automatic
  qualification, business success or full-system rollback is claimed.

## Remaining integration gates

1. Explicit video opt-in schemas/enrollment and host/MCP capability wiring must
   include purpose, bounded capture scope, owner/client/session, pixel-record
   consent and retention intent. Current AX event-record approval must not
   silently broaden to pixel recording. Bind `VerifyRecord` to that authority.
2. A reviewed local pixel redactor/classifier must positively establish safe
   frames, including secure-input and non-AX secrets. Current callback is a
   required trust boundary, not a shipped privacy implementation. Missing safe
   redaction keeps capture unavailable.
3. Wire passive-helper RPC and lifecycle to the existing native recording
   manager, retain the shared lease until BOTH streams and event tap are stopped
   and helper reaping is confirmed, and connect host ingestor pause/failure to
   native teardown. Renew bounded authority or stop on revocation/expiry.
4. Capture must detect display inventory changes, application relaunch/PID
   changes, disappearing windows and unsupported frame status as explicit gaps.
   Filters currently bind the initial inventory; they do not track new displays
   or reincarnated processes. Never silently broaden a filtered scope.
5. Stream framed JPEG bytes through a bounded authenticated local channel;
   persist the timeline and business-flow document as encrypted artifacts through
   the existing Datly publication graph. No new SQL or handwritten DAO exists.
   Authenticate every referenced artifact before external export or scenario
   publication. Existing scenario draft restrictions on live handles still apply.
6. Assemble a local review/playback UI from timestamped JPEG artifacts (or add a
   reviewed in-memory encoded movie pipeline), visible recording indication and
   pause/stop affordances. This foundation is a video frame stream, not a complete
   downloadable MP4 recorder or UI.
7. Qualify actual recording in an explicit disposable desktop across displays,
   apps/window changes, consent revocation, permission loss and secure fields;
   qualify DSL replay with independent business-keyed outcome verification.

## Focused validation

`go test ./record ./host -run 'TestVideo|TestBusinessDraft' -count=1` passed.
`swift test --package-path native/macos --filter RecordingJournalTests` compiled
new capture source and passed six existing journal tests. New focused native
budget tests passed: `--filter VideoRecordingTests` (three tests). Tests use synthetic
pixels/metadata and encrypted temporary artifact roots; no OS capture is started.
