# Mechanize DSL v1 frontend

This closed frontend parses source before any execution. Newlines or semicolons
separate instructions; `//` comments are accepted outside double-quoted JSON
strings. Integers are signed int64; durations are positive integer `ms`, `s` or
`m` literals with a maximum of 60 minutes. Source is limited to 1 MiB and nested
expressions to 64 levels. Strings accept JSON escapes only. Arrays and objects
are typed values, object keys are JSON strings, duplicate keys and trailing
commas are rejected. Unknown methods/options and trailing source are errors.

```ebnf
program = { instruction, separator } ;
instruction = [ "let", identifier, "=" ], expression ;
expression = value | root, { ".", call } ;
root = identifier | call ;
call = identifier, "(", [ arguments ], ")" ;
arguments = argument, { ",", argument } ;
argument = [ identifier, ":" ], expression ;
value = string | integer | boolean | duration | reference | array | object ;
reference = "$", ("input" | "artifact" | "run"), ".", identifier,
            { ".", identifier } ;
array = "[", [ expression, { ",", expression } ], "]" ;
object = "{", [ string, ":", expression,
             { ",", string, ":", expression } ], "}" ;
```

Bindings are immutable and referenced by bare identifiers. Namespaces and
boolean keywords are reserved. Named options cannot precede positional values.
`app(bundleId)` and `web.tab(origin: ..., title: ..., id: ...)` construct lazy
scopes; `window` and `frame` narrow the appropriate surface. Locator strategies
are role, name, id, testId, label and text. Test IDs and label relationships
require explicit backend capability support. `getById` and `getByTestId` match the
entire identifier by default (`exact: true`). An explicitly supplied `exact:
false` stays false; it may be rejected by a backend that requires exact IDs.
Other locator strategies retain their existing defaults. These defaults apply
when compiling new DSL source, including commands in workflow envelopes; stored
normalized plans retain their original selector flags.
 `click`, `fill`, `check`, `uncheck`, `select`, `pressKey`, `read` and
`expect(...)[.not].toBeVisible/toBeEnabled/toHaveText/toHaveValue/toBeChecked` compile to the
shared typed plan. `click` is `element.press` internally. Mutations and reads
terminate chains and cannot be nested inside another argument. Mutations cannot
bind values. Every target has strict cardinality `one`.

Scope identities are literal strings. Locator/value references remain typed
until execution and are never expanded into source. Read results become typed
`binding.<name>` runtime references; that namespace is not accepted after `$` in
source. Mutation effects default conservatively to `externalNonIdempotent`.

The strict JSON plan decoder is another frontend for this IR. `Schema()` describes
its closed records and discriminated Value/Surface unions. `Validate` performs
semantic checks beyond JSON Schema; `CheckPolicy` checks allowed surfaces,
mutation authorization and explicit backend capabilities.

The shared selector model supports explicit `within(parentLocator)` ancestry,
`.all(limit: N, order: "document"|"tree")` for bounded plural reads, and
`.nth(index, order: ...)` for explicit ordered selection. Query completeness and
ordering must be qualified by the backend; the compiler never repairs ambiguity
by selecting an arbitrary element. Plural reads require `orderedQuery`; ancestry
requires `ancestorScope`. Additional actions require `ensureChecked`,
`selectOption`, or `targetedKeyboard`; checked assertions require
`checkedObservation`. These declarations do not qualify existing gateways.

`DecodeJSON` and `DecodeYAML` decode one strict workflow envelope and normalize
source command steps to the same flat Plan.Steps. Surface aliases become typed
scope bindings. Read bindings retain stable workflow step IDs. YAML anchors,
aliases, custom tags, non-string keys and multiple documents are rejected; both
formats reject duplicate keys, unknown fields, nesting over 64 and payloads over
1 MiB. Typed values use the same tagged JSON shape in both formats. User content,
including literal `$`, `${...}`, quotes and newlines, remains data.

Optional metadata covers inputs/defaults/sensitivity, named surfaces, artifacts,
required profiles/adapters, an objective, scoped adapter/element predicates,
effect business keys/reconciliation, file/surface constraints, checkpoint
policies, and recovery bounded to at most 10 repairs and one hour. The only
unknown-effect policy is `needsAttention`. Metadata is validated and serialized;
this frontend does not execute adapters, compute artifact hashes, create
checkpoints or schedule repairs. `Schema()` describes normalized IR;
`EnvelopeSchema()` adds source command alternatives derived from the same schema.

References include expected runtime types; `ResolveValue`, `Selector.Resolve`
and `Step.ResolveArguments` reject mismatches without source interpolation.
Recursive resolution detects scalar/composite cycles and limits expanded output
to 100000 nodes. Scalar values, bound values, and read-result types remain typed.

Pending v1 requirements: Endly lowering for bounded conditions/forEach/repeat and
named subflows; YAML authoring shortcuts from the aspirational plan example;
qualified app semantics profiles that can safely lower effect classes;
executable adapter predicates, artifact materialization, checkpoint/recovery
policies; physical pointer/keyboard gestures and watch/network events; and
native/Chrome backend qualification for each newly declared capability. This
package implements no workflow scheduler or arbitrary host evaluation.

Native instance narrowing accepts `app("com.google.Chrome", processId: 4464, processStartToken: "1790000000:123")`. Both literal fields are required together and must come from a fresh `mechanize_capture_windows` row (`pid` and `processStartToken`). A reused or exited process returns `staleReference`; an unqualified bundle still requires exactly one app. Existing-process narrowing is unavailable for `app.open`.

`locator.pressSessionKey("Cmd+Shift+G")` is an explicit native login-session
keyboard action with its own `sessionKeyboard` capability. It requires native
PID/birth narrowing and the same closed named-key syntax as `pressKey`.
`pressKey` remains process-targeted; neither action falls back to the other.
Session delivery is not atomically addressed to a PID or window. The helper
must qualify current foreground and focused-container ancestry immediately
before posting, preserve key-up cleanup, and leave outcome verification to the
independent postcondition. Source integration is under qualification; this
entry does not claim installed or production availability.
