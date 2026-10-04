# Recovery after an uncertain native input shutdown

Status: historical raw-input recovery is not qualified. Do not clear a retained
physical-input fence to make a demo run.

A missing `input.releaseAll` acknowledgement leaves physical cleanup uncertain.
A successfully stopped helper proves that process cannot send more input; it does
not prove all earlier key/button-down events received matching releases. Business
postconditions and physical cleanup are separate facts. Neither can substitute
for the other.

The current supervisor supports narrowly proven recovery for a historical
semantic/launch-only helper, a generation with no committed intent, or one whose
original committed outcomes all prove no dispatch. These do not apply to raw
input with a verified dispatched action and a missing cleanup reply. Preserve
its generation, helper identity, lease, and unknown business effects.

## Evidence required for a production recovery route

- Bind recovery to the exact stopped helper identity and retained generation,
  under the existing exclusive fence. Recheck process death before release.
- Establish how all potentially held input was neutralized. A new helper with an
  empty in-memory held-input map is not evidence about the old helper.
- Keep uncertain business effects unresolved, and never replay their input as
  part of cleanup.
- Retain an auditable cleanup result and reason. Only release the physical fence
  after the complete recovery evidence is verified.
- Test helper failure between down/up, missing acknowledgements, process PID
  reuse, cancellation, and a concurrent contender. Test actual native delivery
  in an explicitly disposable session before qualifying the recovery route.

## Platform evidence and limits

Apple documents `CGEventSource.keyState` as a current key-state query, and the
combined-session source as the state table for event sources in the current
login session:

- [Key state](https://developer.apple.com/documentation/coregraphics/cgeventsource/keystate(_:key:))
- [Event-source states](https://developer.apple.com/documentation/coregraphics/cgeventsourcestateid)

Those APIs may help diagnose held input. The documentation does not establish
that a sampled session table proves delivery of a matching release to every
application that previously received process-targeted input. Mechanize uses both
process-targeted and session posting. Treat a sample with no keys held as
incomplete recovery evidence until that delivery gap is experimentally and
contractually resolved. This is an implementation assessment, not an Apple
claim that recovery is impossible.

The immediate shutdown repair separates doctor and release budgets, validates
all acknowledgement fields, and preserves static failure phases. It improves
future shutdowns; it cannot retroactively certify an earlier missing reply.
