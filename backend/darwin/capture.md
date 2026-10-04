# Native capture transport

`CaptureWindow(ctx, WindowCaptureOptions)` is a low-level read-only transport,
not an authorization grant. The host/MCP route is wired: host authorization
checks the authenticated principal, enrolled native bundle, observe grant and
exact PID/window; helper validation rechecks physical window ownership.
`mechanize_capture_windows` provides bounded fresh physical window discovery.
Discovery results do not authorize capture. Its call consumes a once grant, so
discovery followed by capture requires a session grant. A capture grant remains
held through helper teardown, encrypted byte storage, and durable metadata
publication. Configured transport flags do not attest to human consent or
macOS TCC approval.

Each call creates a disposable helper and inherited descriptor-3 pipe. No
plaintext image file is staged. After doctor epoch discovery, the request uses
an unpredictable 16-byte nonce as its request ID. The helper requires an exact
bundle/PID/window, checks the live application before and after capture, and
captures only the specified desktop-independent window. Whole-display capture
is excluded from this API and now rejected by this helper method.

The pipe frame is `MCAP` (4 bytes), nonce (16 bytes), PNG length (4 bytes, unsigned
big endian), then the PNG. The JSON reply independently binds the same nonce,
app, PID, window, byte count, dimensions, logical bounds, scale, timestamp and
non-atomic AX status. PNG headers must match the receipt dimensions. All sizes
are bounded: at most 32 MiB encoded bytes and 32 million pixels, with a tighter
caller byte limit and at most 30 seconds. Coordinate metadata rejects nonfinite,
inconsistent or unsupported mappings.

Malformed, foreign, partial, oversized, stale or cancelled results never publish
bytes. Teardown closes the private pipe and stops that helper before returning;
`CaptureError.CleanupConfirmed` records actual process teardown, independently
of uncertain capture acknowledgement. A failed capture's bytes cannot spill into
another request because it has no shared stream. No automatic retry occurs.
If cleanup is uncertain, the host retains the consent lease for reconciliation;
it releases only after confirmed teardown. Successful capture confirms helper
teardown before publication, but metadata publication may still fail or have an
unknown acknowledgement. In that case the encrypted bytes/reference are kept
and metadata/checkpoint reachability must be reconciled; there is no rollback.
These cases, production TCC attribution for this short-lived helper topology,
permission revocation, offscreen/multidisplay geometry and deployed host grant
cleanup still require installed fixture acceptance. No Chrome or whole-display
capture is provided by this route.

The per-window filter and point-to-pixel mapping follow Apple's
[SCContentFilter contract](https://developer.apple.com/documentation/screencapturekit/sccontentfilter).
The reported bounds use that filter's content rectangle, which also determines
the requested pixel dimensions. This is separate from AX observation, not an
atomic semantic/screenshot snapshot.

`capture_test.go` uses a Go subprocess producing an in-memory fixture PNG, and
`capture_targets_test.go` uses a disposable discovery fixture. Host and MCP
capture tests cover consent binding, exact window scope, publication, the 2 MiB
inline response limit, cleanup uncertainty, and unknown publication.
MCP may encode a labelled PNG/JPEG display preview for large source images,
under separate decoder/raster/deadline/iteration limits. Full original bytes
and their immutable artifact identity are preserved. Preview pixels use the
returned logical scale mapping; they are not original pixel evidence.
The synthetic preview fixtures exercise high-entropy images and malformed inputs.
These fixtures do not query desktop APIs or capture any employee window. They do not
qualify signed installation, live TCC behavior, or production reliability.
