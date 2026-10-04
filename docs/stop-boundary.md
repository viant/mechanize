# Recording a stopped execution boundary

`mechanize_state_stop_boundary` records an already-quiescent native run as
`paused`. This is a recovery operation, not a cancellation command or a success
claim. This document describes the source contract; it does not establish that a
particular installed server exposes the tool.

New host admissions persist the initial Endly operation correlation before
releasing the first step. Legacy runs created without that correlation cannot
use this tool until a separately verified correlation/recovery path exists;
caller-supplied operation IDs cannot fill that gap.

First cancel any live operation through Endly and wait for its terminal state.
Then obtain the owned run's current state and immutable plan reference. The host
must also acquire its native executor fence; a terminal Endly status alone does
not establish that an old input helper has stopped.

Example tool arguments (replace the illustrative references with actual values):

```json
{
  "sessionId": "owned-session",
  "purpose": "Record that the interrupted report workflow has stopped",
  "runId": "owned-run",
  "planId": "original-plan",
  "requestId": "stop-request-unique-to-this-boundary",
  "expectedRunRevision": 2
}
```

The request accepts no caller-supplied quiescence proof, replacement outcome,
predicate, or workflow. Version one accepts native-only plans. Active operations,
an unavailable executor fence, foreign references, stale revisions, and terminal
durable runs reject without establishing a new boundary.

The Datly transaction increments the run revision, sets its status to `paused`,
and appends one `stopped_boundary` audit event. Original outcomes, unknown effects,
milestones, the plan, and Endly operation correlation remain unchanged.
`resumeAdmitted` is always false. A paused run with unknown effects still cannot
resume automatically.

## Response loss and errors

Retain all request arguments before calling. If the response is lost, repeat the
same request, including its original expected revision and request ID. The server
can adopt its exact committed audit without another write. This adoption still
requires the quiescence guard and original Endly correlation. A new request ID
with an old revision cannot adopt the earlier boundary.

Inspect `commitConfirmed` even when the MCP result has `isError: true`. A write
can commit before state readback or guard cleanup fails. Do not infer rollback,
retry with a new request ID, or dispatch more input on that basis. A missing `run`
projection means readback is unavailable, not that the unresolved-effect list is
empty. Check state and resolve cleanup before proceeding.

## Continue toward the business objective

Use fresh observations and an enrolled reconciliation contract to determine the
original action's outcome. The stop boundary itself cannot resolve uncertainty
or authorize replay. If the original action remains unknown, keep that history
and require a separately qualified recovery path. Current-state intervention and
automatic recovery handoff remain separate implementation work.
