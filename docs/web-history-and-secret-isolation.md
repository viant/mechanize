# Web history checks and credential isolation

## Read-only history qualification

The generic `history.Reconcile` evaluator consumes explicitly attributed records,
not credentials, account numbers, or guessed tax periods. It uses integer minor
currency units. Each invocation must use one currency; adapters must reject mixed
currencies first. It does not calculate tax, attest source completeness, initiate
transfers, or expose a payment command.

An app/site adapter must independently establish:

- exact enrolled HTTPS origin, profile, frame, document and current navigation;
- requested calendar date bounds rather than a rolling year preset;
- all pages/export rows, settled history and pending/scheduled queues;
- unique operation ID, status, amount/currency, transaction date, and tax period
  from details; descriptions alone cannot establish a property or period;
- explicit subject mapping, with uncertain rows left unattributed;
- reconciliation against independently supplied liabilities and reversals.

Repeated identical operation IDs count once. Contradictory copies are excluded
and listed for review. Multiple completed operations for one subject/period are
review flags, not proof of an erroneous duplicate. Future-dated scheduled orders
remain visible. Failed/reversed operations do not count as completed payments.
A positive expected-minus-observed difference is an observed shortfall with
unverified coverage, not authorization to pay. Future completed operations are
excluded. Scheduled dates describe execution dates of already observed orders.

A local acceptance case can reconcile rental-income tax history for multiple
configured subjects, January 1 through the current date. App/site skills describe
navigation and evidence extraction; personal records and workflows stay local
and ignored. No screenshot-derived login identifier, taxpayer ID or account
number belongs in source fixtures. Rolling twelve-month screenshot totals cannot
be presented as calendar-year totals. Live extraction must establish completeness before asserting year-to-date totals.

## Credential boundary

Both username and password are secrets. They must never enter model-visible tool
arguments, outputs, logs, traces, errors, recordings, screenshots, AX snapshots or
exports. Collection, clipboard import, CRUD and application must be native/local
operations carrying opaque references on the agent-facing channel. Ordinary
`element.fill` must not serve as a credential submission route.

The Chrome DOM executor now quarantines a document when bounded traversal finds
credential indicators (including username/login labels and autocomplete), secret
subtrees or incomplete coverage. It refuses ordinary observe, resolve, read and
mutation. Quarantine is sticky even after fields are removed. Recording stops and
clears its buffer on detection. Credentials appearing during a mutation suppress
the response and leave an unknown effect requiring reconciliation without replay.
Errors contain static messages, no selector, field metadata or secret values.

These guards are defense in depth, not a guarantee based on pattern matching:
closed shadow roots, unrelated reflected secrets, custom login controls, browser
metadata, titles, other frames and native pixels still require a trusted
broker-owned secure-session barrier and egress enforcement. Pages must never be
able to clear that barrier. This change does not enable the disabled vault UI,
provision a master key, qualify capture suppression, wire a signed submission
channel, or apply real credentials. Fixtures used no real credentials.

Secure activation remains gated on the vault README requirements. Clipboard and
CRUD backend tests do not prove the whole provider boundary is secure. The
installed Chrome channel is unconfigured; these changes have not been installed
or live-qualified against a production website by these fixtures.
