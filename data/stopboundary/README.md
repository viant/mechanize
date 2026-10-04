# StopBoundary

Private generated Datly v1 PATCH use case: CAS an owned nonterminal run to
`paused` and append a `stopped_boundary` event while the host holds Endly
admission and the physical input fence. This transaction records stopped
execution, not effect absence, step success, or business success.

Input is one sparse run (`namespace`, `id`, prior `revision`, `status=paused`,
`updatedAt`) and one new event matching `data.StopBoundaryAuthority` exactly.
The authority is in-process context metadata, never tool input. It binds the
prior plan/revision, immutable persisted Endly correlation, request ID, opaque
host quiescence proof and next audit cursor. Missing authority, foreign scope,
stale CAS/correlation, forged ingress and terminal runs fail closed.

Only runs/events appear in the writable graph. Effects, attempts, milestones,
plan history and original outcomes remain untouched. Stable request IDs produce
canonical audit IDs. Reply-loss adoption must use an owned generated readback
and exact `data.MatchStopBoundaryAudit` correlation; repeating the writer cannot
append or rewrite the event.

Authoritative sources: `data/source/stopboundary/StopBoundary.dql` and adjacent
SQL. Generate with local Datly CLI `transcribe patch -dir <mechanize-root>
-schema -connector user -driver sqlite3 -dsn <isolated-schema-fixture>
github.com/viant/mechanize/data/source/stopboundary`. Authored policy is in
`authorization.go` and `lifecycle.go`; generated files are not hand-edited.
