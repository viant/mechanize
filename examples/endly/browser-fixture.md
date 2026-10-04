# Browser fixture through the generic DSL

`browser-fixture.yaml` reads/asserts the expected initial counter, increments exactly once with a protected `web.valueEquals` postcondition, fills the nonsecret literal `Endly browser fixture` with an echo postcondition, then reads/asserts counter, title, and echo. Defaults are counter `0` → `1`; explicit `1` → `2` inputs preserve an already-used fixture document and its receipt history.

Open exactly one enrolled root tab for the disposable `examples/browser/fixture` page at `http://127.0.0.1:18771`. Check current browser scope, executor, and inventory readiness using `mechanize_browser_status`. The workflow neither reloads nor resets the page.

| Parameter | Requirement |
| --- | --- |
| `endpoint` | Authenticated Mechanize MCP endpoint. Required. |
| `credentialResource` | Existing Scy `URL` or `URL\|Key` secret reference, never a literal bearer token. Required. |
| `grantId` | Existing applicable consent covering observe/control for this client, session, origin and purpose. No approval is requested or created here. Required. |
| `requestId` | Fresh unique ID, preferably `[A-Za-z0-9._-]{1,96}`; each stage adds a distinct suffix. Required. |
| `sessionId` | Optional existing owned session compatible with the grant. Otherwise a fresh session is opened, requiring an applicable persistent/trusted-client grant. |
| `purpose` | Optional exact approved purpose for session-bound consent; default `Run the disposable browser fixture`. |
| `expectedInitialCounter` | Optional **string**, default `'0'`. Must equal the counter before mutation. |
| `expectedIncrementedCounter` | Optional **string**, default `'1'`. Supply the intended result of one increment; no arithmetic UDF or reset is performed. |

Run the whole workflow from this directory; do not select a mutation task directly:

```sh
endly-mcp-runner -r=browser-fixture \
  endpoint=http://127.0.0.1:4987/mcp \
  credentialResource='/absolute/path/credential.sec|blowfish://file/absolute/path/key' \
  grantId=EXISTING_APPLICABLE_GRANT \
  requestId=FRESH_UNIQUE_REQUEST_ID \
  sessionId=EXISTING_OWNED_SESSION \
  purpose='EXACT_APPROVED_PURPOSE' \
  expectedInitialCounter=1 expectedIncrementedCounter=2
```

Expected counters enter Mechanize as typed string inputs and references. They never interpolate executable DSL source. Initial/final DSL assertions use declared value bindings; the mutation postcondition uses an input reference.

Only read-only status polling repeats: at most 120 polls, 250 ms sleeps, and a 30-second timeout per MCP call. Mutation requests have no repeats/retries. Dependent stages require the preceding `executionStatus` to be `succeeded`; increment additionally requires the actual initial typed read to equal the supplied initial value, and fill requires the actual incremented read to equal the supplied result. DSL assertions/protected step postconditions fail the operation on failed or unknown verification. Timeout, failed/cancelled execution, or missing/withheld read values prevent later mutations even if an Endly validator assertion does not abort the pipeline.

Descriptive goals are not authoritative business-success contracts. Assess executed assertions, actual operation statuses and final typed values, rather than overall `businessStatus`, a zero exit code, or skipped stages. On uncertainty, retain operation/run IDs and inspect/reconcile; never blindly rerun with a new request ID. The owned session remains open for inspection.

Validation (2026-10-03): all four inner plans passed the installed Mechanize compiler. Local Endly tests covered empty/provided sessions and 13 status/value cases, including failed, unknown, cancelled, running, wrong-value and wrong-type inputs. Session branching uses `$Len` on an initialized string; Endly's `:/` operator is substring matching, not regular-expression matching.

The complete bundled workflow passed live through Mechanize and Endly with explicit counter `2` → `3`, including both protected mutation postconditions, all final assertions, and diagnostic reporting. Final typed values were counter `3`, title `Endly browser fixture`, and matching echo. The same document and receipt history were retained. A separate default-input run failed with `assertionFailed` and left increment/fill/final `notStarted`.

Live evidence: session `e866f6ab-ce1f-4edc-a21c-ce5754eac538`, final run `4f6a7407b0dcfca9c53c19b59339631605b1026041aea1d497669b593047a725`; [successful run log](/private/tmp/mechanize-browser-example-complete.log) and [assertion-refusal log](/private/tmp/mechanize-browser-example-negative-final.log). These qualify this fixture's UI behavior, not authoritative business outcomes or production-wide reliability. Use the actual current counter for a new intentional run; do not discard receipt history to restore defaults.
