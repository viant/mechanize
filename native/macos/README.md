# macOS feasibility helper

Development slice, macOS 14+, public AppKit/ApplicationServices/ScreenCaptureKit APIs.
Build/test with `swift test --package-path native/macos`; executable is
`native/macos/.build/debug/mechanize-native`. No RobotGo/private WindowServer APIs.

Transport: uint32 big-endian length then JSON; v1, 2 MiB maximum frames. Each
request needs requestId, method, deadlineRemainingMs (1...30000), params, and
helperEpoch except doctor/apps.list. `doctor` returns the new UUID epoch without
prompting for permissions. Go's `backend/darwin` supervises a single subprocess,
serializes requests, terminates it on deadline/cancellation, and never replays.
Any failed exchange after possible write yields **unknown**, including reads;
callers decide which effects require reconciliation. No in-memory state survives
restart. The caller must enroll/authorize the broker and own the desktop lease;
this unsigned stdio development helper is not a production security boundary.

Methods and parameters:

- doctor {}, apps.list {}: permission/capability diagnostics and app identities.
- windows.list {pid,bundleID,maxNodes?}: exact live process scope, AX windows.
- elements.snapshot {pid,bundleID,windowIndex?,maxNodes?,maxDepth?}: bounded tree.
- elements.read {elementRef,generation,expectedApp,attributes}: role/name/identifier/enabled.
  Value additionally requires allowValueRead and expectedIdentifier, and a nonsecure
  text field; broker must enforce the explicit bundle/identifier read allowlist.
  StaticText uses the separate staticText attribute and allowStaticTextRead opt-in.
  Broker must enforce an exact app read policy and resolve a unique fresh target;
  helper requires AXStaticText, positively known nonsecure subrole and confirmed
  nonsettable AXValue. Static text is bounded to 4096 UTF-8 bytes; unavailable,
  oversized or NUL-containing values fail without truncation.
- elements.press {elementRef,generation,expectedApp} and elements.setValue with
  additional string value: require --allow-mutations, exact helper epoch, installed
  lease {id,generation}, enabled nonsecure element, current generation, live app
  launch identity and ref age under 5 seconds. Every result is dispatch evidence,
  never an outcome assertion. AX failure after the native call is unknown.
- lease.install {id,generation}: trusted broker only, increasing generation.
- lease.revoke {}: remove control authority. Cancellation during blocked calls
  instead terminates the helper through Go's supervisor.
- capture.image {artifactFD:3,displayID} or {artifactFD:3,windowID,pid}: explicit
  ScreenCaptureKit source, PNG to broker-allocated inherited descriptor3. No path
  input and no silent full-display fallback. Max 32M pixels/32MiB encoded. Broker
  must publish/hash/scope that artifact; helper does not publish a checkpoint.

Snapshots withhold values by policy; unsupported attributes are marked unavailable.
Refs are helper-local UUIDs and expire on every new snapshot or mutation; snapshot
completion is bounded coverage, not atomic state. AX window ↔ Quartz capture ID
correlation is not implemented; choose an explicit public SCK window ID.
Mutations have a bounded 4096-ID reply ledger; saturation blocks further dispatch
until restart/reconciliation, so eviction cannot silently replay a prior effect.
The serialized helper cannot interrupt a blocking AX/SCK call; host termination
is the hard deadline. Queries set AX messaging timeouts, but these alone are not
universal cancellation.

Evidence: Swift core tests cover framing, truncation/oversize, budgets and bounded
mutation dedupe. Go subprocess fixture tests cover framed identity and unknown
dispatch on cancellation. Tests do not synthesize live input or capture the user's
screen. Permission-granted AX/SCK actions, independent fixture outcomes, signed
bundle/TCC upgrade behavior and locked/disconnected desktop detection remain
unqualified. No release reliability measurement is claimed. Advanced input,
clipboard, app launch, window updates, AX subscriptions, OCR, recording and
business-effect reconciliation are explicitly outside this slice.

## Fenced input and watchdog slice

Additional public Quartz methods: input.key (virtual key code), input.text
(1...1024 UTF16 units), input.pointer (scoped left click), input.releaseAll. These
are raw helper contracts; new DSL input commands have not been qualified or
advertised. Every input requires an exact fresh elementRef/generation/expectedApp,
foreground app and launch identity, AX trust, Event Posting permission, explicit
mutation opt-in, enrolled inherited physical fence FD5 and live watchdog FD4.
Keyboard additionally requires positively focused AX target; secure targets are
rejected. input.key accepts keyCode 0...127 and modifiers command/shift/option/control;
input.text accepts text. input.pointer requires x/y global logical points,
displayID and button:"left", within current AX element and active display bounds.
Keyboard events use public postToPid. Mouse click uses HID event posting. Events
carry an injected-source marker. Drag, scroll, IME/layout qualification, secure
input and background typing remain unsupported.

A held-input tracker retains releases before posting down. Independent watchdog
EOF/two-second heartbeat silence inhibits further downs, dispatches cleanup and
exits; protocol EOF also releases inputs. Native posting has no delivery/business
oracle, so its receipt says dispatched or unknown and businessSuccess:false.
Validation failures before posting say notDispatched. Host shutdown first asks
input.releaseAll under a short deadline, then closes watchdog and proves helper
termination. Forced stop may leave cleanup unknown; session persists that barrier.
Default NewClient requires a supervisor Fence when AllowMutations is true. The
helper's raw --allow-mutations alone no longer enables mutations.

Additional evidence: six Swift core tests include injectable down/up/inhibition
and unknown release cases. Go session tests prove process/fence lifecycle without
posting events. A built native helper's watchdog EOF and heartbeat-silence tests
call doctor only; no live input or screenshot is used for those proofs.

Exact application instance targeting accepts a native Surface's paired `processId`
and `processStartToken`. `capture.windows` returns `pid` and
`processStartToken` in each window row, from current-login-user public libproc
identity. Use that fresh fingerprint for `elements.snapshot` and native script
`app(bundle, processId: ..., processStartToken: ...)`; stale or reused identities
fail before dispatch. The helper retains and revalidates process start tokens in
its generation-scoped references before reads and input. Unqualified bundles
continue to require one application instance. `app.open` cannot take an existing
process target. Capture transports may carry the same optional start token;
physical capture validates it again before returning bytes.

Application lifecycle `launchTime` is an opaque canonical kernel birth identifier
(`kernel:<startToken>`), not a Cocoa timestamp. Directly launched applications may
have no `NSRunningApplication.launchDate`; inventory, activation, launch receipts,
AX references, and capture identity rely on the exact same-user libproc birth
fingerprint. Optional Cocoa date metadata cannot invalidate an unchanged process.
