# Conditional discovery with Endly

Use Endly when the user requests orchestration or a measured batch can remove
repeated agent decisions. Preserve the selected executor and its permissions.
Do not add app launch or activation merely because a window is not observed.

When advertised, `mechanize_application_presence` accepts an owned `sessionId`,
`purpose`, exact native `bundleId` and optional existing `grantId`. It returns
`state`, and for `running`, a fresh `processId` and `processStartToken`. It reads
no window titles or document content and performs no input. `running` establishes
process presence only. `ambiguous`, `notObserved` and tool errors do not establish
process exit or authorize a launch. Use the returned PID/birth pair for subsequent
scoped window discovery; verify the intended document separately.

Endly's `mcp/runner:call` exposes `StructuredContent`. A workflow can retain the
presence result with `post: {currentPresence: $StructuredContent}` and condition
window discovery on `when: $currentPresence.state:running`. Use the actual tool's
response shape, not an illustrative `apps[0]` structure from another service.
The runner can also evaluate indexed output paths when the service returns arrays.

Initialize invocation-local completion markers in an unconditional first step.
Set the relevant marker only in the current action's `post`, and assert that
marker with the intended result at the end. A skipped action can leave a previous
result in shared state; old success is not current-run completion. Run with
`FailOnAssertion: true`. If the workflow references root-level parameters, set
`PublishParameters: true` explicitly on its run request.

Use Scy credential references, never token values in workflow arguments or logs.
Close owned sessions after the bounded work. If an action fails before the close
step, reconcile and close its original session separately; do not rerun the whole
workflow solely to clean up. Poll an unfinished operation by its original ID.

Live qualification must cover the actual dependent operation. Successful presence
and window discovery do not qualify mailbox reads, document authoring, or exports.
Measure the complete Endly batch separately from individual MCP calls and retain
failed attempts; do not attribute agent-token savings from elapsed time alone.
