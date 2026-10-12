# Consent and executor recovery

Saved permission and a live executor have separate lifetimes. Recovery reuses
existing human authority only after proving that its previous executor can no
longer dispatch input. It does not erase receipts, replay an uncertain action,
or turn an UNKNOWN business outcome into success.

## Native operations

Native synchronous steps authorize and complete cleanup before capturing the
helper generation for durable intent. The prepared authority belongs to one
client, consent binding, immutable step, execution identity and generation.
Dispatch consumes that authority once, retaining the committed intent's context
and the original lease's cancellation signal.

Cancellation before dispatch retires the exact prepared generation. Unproven
physical cleanup retains the cleanup barrier. Human revocation, a different
client, stale step or held input cannot dispatch.

An application-scoped native operation may use independently proven native
cleanup while a broader browser cleanup barrier remains. This exception excludes
Chrome, does not clear the broader grant's durable cleanup state, and requires a
fresh proof for every operation.

## Browser operations

Chrome need not be closed when an authenticated reconnect proves retirement of
the previous executor. The proof requires a changed lease-required broker or
channel fence, the current qualified process and challenge, completed prepare /
adopt reconciliation, and complete document inventory on that connection.

Admission and channel write locks retain the proof through the consent recovery
compare-and-swap. New work, changed inventory, disconnect, private operations or
pending / unknown commands invalidate it. A READY status or empty in-memory
registry alone is insufficient. When this proof is unavailable, recovery retains
the existing independently verified process-death fallback.

## Controller compatibility

The broker derives the receiver's tool capacity from the authenticated native
hello, never from page-provided metadata. Extension versions before 0.1.63 receive
the 30-tool baseline; version 0.1.63 and later receive the 34-tool catalog.
Invocation enforces the same exposure policy as discovery.

## Regression coverage

Synthetic regressions cover actual durable native dispatch after recovery,
generation equality at intent, cancellation and denial paths, browser proof
invalidation, consent recovery under a held proof, and the broker-to-extension
catalog roundtrip. Durable and Endly suites cover continuation, detached and fork
lifetimes. These tests do not substitute for verification of an application's
business outcome after a live action.
