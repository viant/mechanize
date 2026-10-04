# App skill evidence template

Keep durable procedures separate from ephemeral execution references.

| Field | Record |
|---|---|
| Identity | App name, bundle ID, tested version/build, relevant OS version |
| Scope | Document/window kind and feature tested; installed copies if ambiguous |
| Task | User outcome, preconditions, output location/format |
| Discovery | Smallest useful observation scope, stable selectors, qualified shortcuts, and any currently advertised capture-bound pointer route |
| Procedure | Steps that actually worked; parameters rather than captured PID/ref IDs. If pointer input was used, bind it to the fresh exact-window capture that established the target |
| Verification | Readback, saved artifact inspection, reopen result, formula/export checks |
| Recovery | Recognized failure, evidence required, qualified alternative, stop condition |
| Evidence | Run/artifact references, test date, exact tested cases |
| Status | Observed only, verified, failed, stale, or unqualified |
| Reliability | Successful/attempted applicable cases and environment; no invented score |

Useful task cohorts:

- **Document work:** find by name/location, disambiguate duplicates, open existing,
  read a section, edit a copy, Save As, reopen, search inside, export PDF.
- **Spreadsheets:** identify sheet/range, read values/formulas, enter a table,
  calculate totals, format numbers, save/reopen, verify exported workbook.
- **Administrative apps:** find a record, inspect details, stage a permitted edit,
  verify persistence. Sending or publishing needs the user's actual authorization.

A single successful run qualifies that case, not every app version or all tasks.
Prefer the current scoped AX/semantic route; consider only an observed and
qualified app shortcut next. When those routes are unavailable or unreliable,
use a fresh exact-window capture, then a capture-bound pointer route only if the
current catalog advertises it. Do not infer coordinates or reuse stale capture
targets. A screenshot can verify visible layout but does not establish hidden
rows, formulas, full document text, or persistence. A file's existence does not
establish correct content. Keep evidence proportional to the requested result.

When generating an app-specific skill, keep its entrypoint short and put distinct
Writer/Calc/export-style procedures into references. Preserve useful negative
findings, such as “advertises writable AXValue but setter is ineffective,” with
version and evidence. Do not turn untested platform assumptions into instructions.
