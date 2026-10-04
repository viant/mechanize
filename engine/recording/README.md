# Scoped Chrome recording composition

`New` receives the server-owned lifetime context, Chrome capture backend, and
private generated Datly component invocations. `ComponentFuncs` makes the root
integration explicit. `AppendEvents` must return only after confirmed durable
commit; `ReadEvents` returns authorized writer-compatible entities in ascending
journal sequence without silently truncating. The journal contains an immutable
capture intent, bounded redacted backend batches, and failure markers. Journal
sequence is independent of source capture sequence. No product SQL lives here.

Call `Close` before cancelling the server lifetime and closing Datly hosts.
Capture polls every five seconds with a four-second deadline to renew the
extension's bounded lease; cancellation stops renewal. Duration is at most
15 minutes, source events at most 4096, live sessions at most 16, journal rows
at most 1024. Pause does not resume implicitly. Recording IDs cannot be reused.

All captured values are discarded before persistence as an additional privacy
boundary. Export uses typed input references and never captured field defaults.
The caller provides the objective, input declarations and parameter mappings.
The compiler preserves gaps, unresolved targets/inputs and effect-review issues,
and produces an unqualified report even when operator review is acknowledged.
Review, syntax validity and successful input replay do not establish business
success or qualification. Independent fixture replay and outcome verification
remain separate requirements. Restarted live state is always interrupted unless
persisted stop evidence exists. Failed stop is never reported as confirmed.

Fixture tests use disposable injected backends and seeded values; no live desktop
or employee input is used. Production Datly acceptance additionally requires the
root's generated recording reader/writer roundtrip integration gate.
