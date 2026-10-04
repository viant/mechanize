---
name: mechanize-scenario
description: Select a reusable Mechanize scenario only when a discovered, qualified catalogue has a verified match for the requested business objective, inputs, surface, and permissions. Use when choosing an existing plan; recording or authoring a new plan and one-step actions use other workflows.
---

# Mechanize scenario selection

Distinguish the request before acting:

- **Existing scenario:** inspect and select a stored, qualified plan when the
  user asks to reuse a workflow.
- **Interactive one-step mode:** use `mechanize_step_run` for one authorized
  action, not as an implicit replacement for a missing full scenario.
- **Recording:** use the separate recording workflow only when the user
  explicitly asks to capture a demonstration for reuse.

Use `mechanize_scenario_list`, `mechanize_scenario_publish` and
`mechanize_scenario_select` when advertised. Publish stores an immutable
parameterized draft; it never executes or qualifies it. Caller-supplied review
or gap claims are untrusted. Drafts cannot persist captured action values,
input defaults or live run/artifact/element handles. Keep any normalized fields
reported by publication; never silently change the requested objective.

The selector requires trusted fresh host environment, reverified provenance
and exact cohort qualification. The current packaged host has no enrolled
environment/qualification providers, so selection returns `needsAttention`.
Catalogue membership is not qualification. If no catalogue/tool is advertised,
say selection is unavailable here. You may compare plans the user supplies,
but must not invent catalogue entries or silently choose a nearest match.

## Discover and filter candidates

When the connected server advertises an authorized plan catalogue,
inspect its schema and qualification evidence before selecting. First require
all of these hard matches:

1. The plan's declared business objective and success predicate match the
   requested outcome; required business keys and typed inputs are available.
2. Its surface, app, version, browser profile/origin, and relevant session
   assumptions match the currently authorized environment.
3. The needed locators/actions are advertised and qualified for that exact
   cohort, and the user's current policy authorizes them. Capability does not
   equal permission.
4. It has an independent verification route for the requested outcome and no
   unhandled side effects, unsupported steps, or unresolved effects.

Rank only candidates that pass every hard match: prefer the most specific
qualified app/profile/version match, then current qualification and measured
cohort evidence. Equally ranked candidates return `needsAttention`; request an
explicit revision rather than treating database order as a winner. Never relax an objective,
permission, verification, or effect requirement to manufacture a winner.

Use bounded list pages and their `next` cursor, with objective or exact
ID/revision filters. Select takes the requested objective hash, exact entity,
typed input schema/values and surface; the client cannot supply authoritative
environment or qualification. A `proposalOnly` response is never an execution.
Return the selected plan ID and revision, match evidence, required inputs,
verification method, qualification scope/freshness, and any constraints before
starting it. Obtain any missing business key or user choice rather than
guessing. Do not expose secrets in selection summaries; pass credentials only
through approved secret references.

## Before starting or resuming

Inspect current surface state and recheck plan revision, app/profile/version,
capabilities, and authorization. For a prior run, inspect durable state and
checkpoint compatibility. Reconcile each in-flight or unknown effect using
fresh evidence keyed to the relevant business entity before resuming. A
checkpoint does not undo an external effect. If state, permission, or effect
outcome remains uncertain, stop and ask for attention; do not replay a
consequential action.

Use the advertised session/run/status/cancel tools only. Execution completion
is not business completion: report success only when the declared independent
outcome predicate is satisfied. If no matching plan exists, offer to help
author one from user-provided requirements, or use one-step mode if that meets
the request and is authorized. Do not launch a consequential fallback workflow
without authorization.
