# Capture-bound Word focus qualification

Observed October 5, 2026 through Mechanize MCP, Endly and the signed macOS helper.
One fresh exact-window frame click focused the owned Word sales report's text
area. A separate fresh AX observation showed AXTextArea with focused=true;
the original DOCX hash remained unchanged. The run's input effect is verified
with no unresolved effects. Business status remains unverified because no
authoritative business outcome adapter is enrolled.

The initial blocker was a full-screen Dock window whose upper region is
transparent. Window alpha and bounding boxes cannot prove mouse routing.
The helper now uses AppKit's public mouse-down recipient query, with the primary
display coordinate transform verified, bounded main-thread access and repeated
qualification immediately before posting. Apple documents the query as using
mouse-down hit-testing rules, excluding transparent points and windows that
ignore mouse events. No application or window whitelist is used.

The exact target window must still have one valid CG inventory row matching
PID, kernel birth, bundle, geometry and opacity; current foreground/session,
secure-input, held fence and one-use capture checks remain. Missing/zero/different
recipient, uncertain screen mapping, timeout or changed recipient reject input.
The target image pixel must be opaque and its fresh patch must match the capture.

`examples/endly/microsoft-office/plan-word-frame-focus.py` emits one typed click
from fresh `processId`, `processStartToken`, `windowId`, `captureRef`, original
`widthPixels`/`heightPixels`, integer `x`/`y` and a stable `caseId`. Inspect the
original image and choose a document-body point first. Image metadata supplied
to the emitter is not authority: the helper independently checks its retained
permit and pixels. The emitter is parser-validated; its generated workflow has
not separately been live-executed. It neither captures nor grants permissions.

Use the same owned session, approved grant and exact purpose for capture and
run; changing the grant can invalidate the permit even when both grants permit
control. Activate the exact document before capture. The permit is single-use,
expires after thirty seconds, and other native mutation invalidates it. Never
reuse a preview's pixel coordinates or a stale permit. Inspect terminal status
and original effect state before an alternate route or replay.

This proves one body-focus case, not generic Office pointer coverage, selection,
dragging, clicks on noneditable canvases, or complete unattended tasks. Larger
automation-cursor visualization remains separate work.

## Parameterized outcome scope update

The source emitter now requires the fresh exact captured windowTitle and checks
the AXTextArea focused flag inside that window. It no longer declares a separate
focusedElement root after a frame-scoped action, because that transition cannot
be reconciled by the enrolled native contract. The updated emitter is parser
validated only, not live-executed. The earlier live click and its original
predicate/evidence remain historical and unchanged.
