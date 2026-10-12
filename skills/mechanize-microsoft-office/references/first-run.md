# First launch and recovery

## Mechanize readiness after an update

Before observing Office, verify the running installation rather than a shell-launched
helper. This host's launchd deployment attributes Accessibility checks to the
`mechanize` broker. An enabled entry for an older ad-hoc build does not authorize a
replacement binary, even when its filename and installation path are unchanged.

On October 5, the signed native console's read-only Vault diagnostic confirmed
authentication, key readiness and inventory readability, while native MCP observation
was rejected. macOS TCC logs identified an Accessibility signing-requirement mismatch
for the exact installed broker. This was a permission failure, not an empty Vault
or a reason to create a replacement encryption key.

After the user refreshed that grant and the same broker binary was gracefully
restarted, native MCP observation succeeded. One MCP/Endly action selected Vault;
fresh observation confirmed Create credential enabled. This confirms recovery of
observation and the control's readiness, not protected credential entry or CRUD.

Use the current console's Permissions tab to reveal the verified `mechanize` file.
Remove its stale Accessibility entry, add that exact file and enable it. After a
failed secure-entry attempt, close secure entry windows and choose **Recover
protection**. Then check native MCP observation again. An enabled switch, a readable
Vault, or a successful MCP capabilities call alone does not prove desktop readiness.

Until independent native window verification succeeds, do not capture, type, click,
replay Office actions, replace the Vault key, or use another desktop controller to
bypass the refusal. Preserve existing workflow runs, result predicates and unknown
effects. After permission recovery, rediscover process/birth and window identity;
do not reuse observations from before the restart.

## Identify readiness

Resolve Word as `com.microsoft.Word` and Excel as `com.microsoft.Excel`; verify
installed version and inspect live capabilities. Open an app through a typed
`app.open` step with a business key, then observe its actual process. Do not
import old PID/birth pairs or assume a default workbook name is unused.

Classify the observed screen before choosing a document action:

- **Optional sign-in:** on the tested Excel version, the uniquely observed
  `Skip sign in` button reached the local template screen. The successful step
  verified that the `Create` button was enabled. This does not activate a licence.
- **Account or licence activation required:** report the exact need and hand
  credentials, account selection, purchases and protected prompts to the user.
  Resume from fresh observation afterward.
- **Template screen:** observed native window name was `Open new and recent
  files`, identifier `DocStage`, with `Blank Workbook` or `Blank Document` and
  a `Create` button. Confirm the intended blank template and absence of the
  expected new window in a complete observation before the one creation action.
- **Recovery dialog:** preserve documents and uncertainty. Re-observe recovered
  windows and independently verify files before resuming writes.

## Window-changing actions

Word and Excel `Create` each returned AX error -25204 even though the requested
new document appeared. Do not interpret that code as proof of no dispatch or
repeat creation. Inspect the exact original run and fresh app state.

The Excel fixture used a unique app-scoped Create locator within an exact
PID/birth pair, with an immutable `native.valueEquals` result predicate selecting
the expected new window by exact role/name in that same process. After terminal
Endly status, `mechanize_state_stop_boundary` committed a pause and
`mechanize_effect_reconcile` confirmed the original effect using that predicate.
Creation was not replayed. This proves observed window state, not file persistence
or business completion.

The earlier Word fixture scoped Create to the start window but expected a new
window outside that scope. Current reconciliation rejects that window-boundary
change. Its original effect remains unknown. Do not widen its stored predicate,
change the business key or create another document to make that run pass.

For future transitions, validate that the original action scope and declared
result-check scope are compatible before dispatch. Exact process ownership and
unique target resolution still apply when the result is another window.

A later semantic Insert-tab click on the disposable Word table-qualification copy
also returned AX error -25204. A complete window observation and enabled control
did not establish that the action would complete. The terminal operation was
paused through `mechanize_state_stop_boundary`; reconciliation using the original
checked-state predicate did not establish success. That effect remains unknown
and was not replayed. No table-insertion action was attempted. Do not record this
as table support or use another business key to repeat the same uncertain click.

Source investigation identified a timeout-ordering defect: scoped ancestry validation
could overwrite the semantic action's intended 200 ms timeout with its 100 ms read
timeout. A helper-only update now restores and checks the existing action timeout
after final scope validation, bounded by the remaining request deadline. It covers
press, menu disclosure and submit, with no retry or alternative input. Native tests
cover ordering, expired budgets, configuration failure and unchanged uncertain AX
results. The signed helper was installed while preserving broker/console binaries,
Vault readiness and all unresolved runs. This fixes the identified code defect;
the earlier Word action remains unknown and live table insertion is unqualified.

## Excel editing boundary

In a fresh disposable Book1, a scoped `Control+U` key changed the independently
read status text from `Ready` to `Edit`. The formula editor identifies itself as
`XLFormulaEditor`, role `AXTextArea`; it did not advertise writable AXValue or
selected text. Do not assume a reported text role supports `.fill()`.

An empty-value check returned unknown, stopping before text input. The native
helper's explicit-ID read path initially rejected an absent optional AXSubrole;
a tested compatibility change now distinguishes explicit absence from unknown
or secure metadata. Live formula read then returned `attributeUnavailable`.
A subsequent bounded text-range reader qualified exact reads when AXValue is
absent: it reads the complete AXStringForRange using a bounded character count,
checks UTF-16 length and unchanged count, and revalidates ownership. A separate
workbook then received `test` with prefix readback after each key. See
[the Excel text/save case](excel-text-save.md).

A later one-key test lacked a fresh immediate visual precondition. Capture
showed unexpected mixed text rather than its expected result. The run was stopped
and its uncertainty preserved. Establish uninterrupted input ownership and a
fresh content baseline before another typing qualification; do not erase or
reinterpret the existing text.

## Pointer boundary

Exact-window screenshots worked. Frame-click capture rejected foreground or
occlusion qualification, including a Dock-owned full-display window reported by
CoreGraphics. No click permit or pointer dispatch was qualified. Do not ignore
that window, substitute desktop coordinates, or switch to another input library
to bypass the guard. Recheck after the interfering UI is gone.

## Bounded child traversal observation check

On October 5, the helper-only traversal update returned complete MCP snapshots
for the owned Word table-qualification copy (100 nodes) and Excel sales-analysis
workbook (129 nodes). The broker identity remained unchanged and no document input
was sent. Array reads are capped before traversal; failed/changed/short reads
produce incomplete coverage. Do not interpret this as all-Office AX coverage.
