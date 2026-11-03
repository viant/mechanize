# Time, tokens and quality

Compare Computer Use, individual Mechanize MCP actions, and bounded Mechanize/Endly
batches on identical synthetic Office tasks. Endly is an executor used by Mechanize,
not evidence that a script's intended outcome occurred. Keep offline file-library
authoring as a separately labeled reference, not a native UI result.

Freeze inputs, app versions, requested formulas/objects, output formats and quality
checks. Report cold setup separately from warm repeats. Include all preparation,
tool execution, completion polling, save/reopen, verification and recovery in total
elapsed time. Record failed attempts and human interventions, not only successes.

Record provider/session-reported input, output and cached tokens when available.
Retain the source and measurement boundary. If only a goal/thread total is exposed,
label it as that accounting metric, not billable provider usage. Do not estimate
tokens from character counts or infer dollar cost without verified model pricing.
Leave unavailable breakdowns explicitly unavailable. Concurrent unrelated work must
not contaminate run deltas.

When a local Codex session log is available, its `token_count` events may expose
`total_token_usage` and `last_token_usage`. Read only those accounting fields;
do not copy conversation or credential-bearing tool payloads into benchmark
reports. Record the event timestamp and session source at both boundaries. Reject
deltas across a counter reset or different session. Cached input is a subset of
input, and reasoning output is a subset of output: do not add either twice.
Label these as session-reported counters and preserve unavailable fields as such.

Use at least three comparable successful runs per route before describing repeat
performance. Report sample size, median and range, plus failures. A small cell or
slide benchmark cannot establish full-workbook/deck behavior. Expand to the user's
actual task only after basic routes pass.

Measure speed consistency separately from average speed: retain each attempt's
elapsed time and report the spread, including recovery overhead. Three successful
runs are an initial comparison, not proof of a reliable tail-latency estimate.
Do not report meaningful percentile or reliability claims from tiny samples.
Report first-attempt successes / all attempts, eventual successes / all attempts,
retries, unresolved outcomes and human interventions. Never discard failures from
the denominator or replace them with successful reruns.

Tune each route competently before freezing its measured procedure. Give Computer
Use the same prepared inputs and opportunity to batch supported deterministic
actions. Record the Mechanize revision, runtime configuration and Endly plan used
for each attempt. Separate exploratory tuning time from repeat execution, retain
both, and start a new comparison cohort after a material implementation change.

Quality gates: correct typed values and formulas; observed input sensitivity;
save/reopen persistence; complete requested sheets/slides; preserved editable
charts and embedded data; no clipping or missing content; valid matching exports.
Lower token use or elapsed time is not a win if a gate fails.

Batch only proven actions against current scopes. Stop at new windows/dialogs,
ambiguous selections, uncertain effects and required review boundaries. Measure the
batch's completed result, not its submission latency. Do not reduce verification
or replay uncertain saves, exports or sends to improve benchmark numbers.
