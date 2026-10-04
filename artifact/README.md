# Encrypted evidence publication

`artifact.Store` owns bounded immutable binary I/O; Datly generated components own product metadata and checkpoint reachability. `host.ArtifactService` joins these contracts. Its trusted host configuration supplies the store, verified enrollment authorization, exact-surface consent authorization and `durable.Builder.PublishArtifact` callback. Bind `ArtifactService.VerifyArtifact` into `durable.Options.VerifyArtifact` before constructing the builder. Close the service/store after durable operations stop.

Host publication authenticates the context principal, derives the user's `data.Scope` (rejecting any conflicting existing scope), obtains an exact-surface consent lease, persists authenticated encrypted bytes and metadata, then invokes the durable publication graph. The supplied principal cannot elevate context scopes. Byte limits, namespace quotas, private directories/files, immutable publication, hash/type/key-version verification and Scy key resolution remain in the store. Key resources and storage roots are operator configuration; no request selects a resource URL or plaintext fallback. Key unavailability blocks writes and reads.

`ArtifactPublicationError` returns the immutable reference when the metadata publication failed or its commit acknowledgement is unknown. It does not delete bytes or claim rollback: metadata may have committed. Reconciliation and garbage collection must consult generated metadata/checkpoint reachability before removing potential orphans. For the integrated native capture route, the host retains the dispatch lease through helper cleanup and storage/publication; other evidence ingestion callers must manage their own authorization lifetime.

`Read` authenticates the enrolled owner and every reference field before returning decrypted existing evidence. It does not capture a surface or confer desktop authority. This API does not implement a public listing/export endpoint, redacted-export policy or bearer capability. Those routes need their own product authorization and generated metadata resolution.

## Native capture integration and qualification

The host/MCP route now connects bounded native window discovery and exact-window
capture to encrypted storage and Datly metadata publication. The tools accept an
enrolled native application plus exact PID and physical window ID; they do not
capture Chrome or an entire display. `mechanize_capture_windows` consumes its
own observe grant, so discovery followed by capture needs a session grant. A
capture lease is retained through helper cleanup, byte storage, and metadata
publication. MCP includes original PNG image content up to 2 MiB; larger images
remain saved in full and may return an explicitly labelled bounded PNG/JPEG
preview. Preview metadata maps its pixels into the original logical bounds;
the immutable artifact hash/size still identify the full original PNG. Sources
that exceed safe preview limits return `imageReturned: false` with a reason.

Configured capture transport and publication do not prove human approval or
Screen Recording TCC readiness. Helper cleanup uncertainty and unknown metadata
publication acknowledgement remain reconciliation cases. Publication errors
keep encrypted bytes and a reference because metadata may already have
committed; garbage collection must consult metadata/checkpoint reachability.
Installed signed-helper/TCC acceptance, permission revocation, orphan handling,
and production reliability remain unqualified. There is no whole-screen
fallback, helper-selected filesystem path, or synthetic screenshot.

Fixture coverage exists in `mcp/capture_test.go`, `host/capture_test.go`,
`backend/darwin/capture_test.go`, and `backend/darwin/capture_targets_test.go`.
These fixtures do not capture or input on a live desktop and are not release
qualification. Generated Datly publication/checkpoint integration is exercised
separately in `engine/durable`.
