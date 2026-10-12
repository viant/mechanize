# Microsoft Office qualification

Status: qualification is in progress. Excel text/formula/save/PDF cases and a
sales workbook with a persisted chart have evidence. A Word report has verified
text, Heading 1 formatting, DOCX save, local PDF export and verified close/reopen. Two authorized Outlook email
cases reached Sent, including a request received by email with a workbook
attachment and a reply after independent read-only analysis. Broad unattended
Office reliability, PowerPoint/OneNote workflows and pointer clicks remain open.
See [evidence.json](evidence.json)
and the [Office guide](../../../skills/mechanize-microsoft-office/SKILL.md).

The destination is macOS 27.0 (26A428), arm64, with Microsoft Word and Excel
16.113.3 (`com.microsoft.Word`, `com.microsoft.Excel`). PowerPoint 16.113.3 is
also installed. The user subsequently expanded the target to the whole Office
suite; see [suite-qualification.md](suite-qualification.md) for the acceptance
matrix, including Outlook and OneNote.

## Initial preparation evidence — October 4, 2026

- `go test ./...` passed after correcting the consent concurrency fixture's
  missing initial durable operation correlation. The fixture now also proves
  its warm-up reached the executor, rather than accepting any failed operation.
- `go vet ./...` passed after replacing mutex-copying Chrome test fixtures.
- `go test -race ./backend/chrome` and the targeted consent concurrency race
  test passed.
- Chrome `npm test`: 90 passed after `npm ci --ignore-scripts`.
- Native Swift tests: 60 passed. Consent-console Swift tests: 56 passed.
- Python packaging tests: 25 passed with `PYTHONPATH=scripts python3 -m unittest
  discover -s scripts -p 'test_*.py'`.
- Development package built and installed with verified ad-hoc signatures and
  fresh per-host Scy resources. No original-host credentials or process IDs
  were imported. Per-build console enrollment succeeded; its report did not
  claim independent ACL audit verification.
- A client using the pinned Endly `mcp/runner` service successfully listed 36
  live Mechanize tools, read capabilities, opened an owned session and submitted
  an observe/control permission request. These operations performed no Office
  document input.
- The installed helper's nonprompting doctor reported Accessibility, event
  posting, Screen Recording and Input Monitoring unavailable. macOS permissions
  and a human consent decision are required before live qualification.

The private installation is under the current user's
`Library/Application Support/Mechanize/development/20261004T134519Z-baacd1d5`.
Its `setup-report.json` identifies the installed artifacts. Configuration and
credential files remain private; never copy their contents into examples or
reports. Transient sessions, requests, PID/birth pairs and capture permits must
be discovered again when reconnecting.

## Reusable discovery workflow

[`discover.yaml`](discover.yaml) ran successfully against the installed broker
through the pinned Endly workflow and `mcp/runner` services. It reads capabilities
and the shared DSL contract, then asserts schema version 1 and DSL/JSON/YAML
support. This is API preparation evidence, not live Office qualification.

With an Endly CLI that includes the pinned MCP runner, run:

```sh
endly -r=discover endpoint=http://127.0.0.1:4987/mcp \
  bearerTokenSecret=/absolute/private/path/to/stdio.jwt
```

The standard `/usr/local/bin/endly` on this destination is an older build; it
was not used for this check. The preparation run used a local client compiled
against Mechanize's pinned Endly dependency, without changing the system CLI.

## Qualification sequence

Runtime recovery follow-up (October 5): Vault authentication, key readiness and inventory
checks pass. After the user refreshed Accessibility for the current `mechanize`
broker and it was gracefully restarted without changing its binary, native MCP
observation succeeded. An MCP/Endly action selected Vault and fresh observation
confirmed Create credential enabled. The console provides the exact verified file
and Accessibility/Finder actions for future recovery. See the
[first-run recovery guide](../../../skills/mechanize-microsoft-office/references/first-run.md).
These checks do not qualify protected credential entry or CRUD. A native secure
entry window blocks all observation and desktop input until cleanup is confirmed.
Obtain fresh observations before continuing the sequence below.

1. Run the nonprompting permission check under the intended service launcher.
   For this launchd deployment, grant the signed `mechanize` broker Accessibility,
   Screen Recording and Input Monitoring as required; helper-only grants were
   insufficient. Approve the requesting client in Mechanize Permissions. Reuse
   matching permanent trust rather than requesting permission for each action.
2. Rediscover live capabilities and exact process/window identity. Qualify a
   single capture-bound click using a fresh original image and independently
   observed result. Preserve any unknown effect before trying another route.
3. Word: create/open a disposable DOCX, edit one paragraph while preserving
   neighbors, apply styles, insert a table, set layout, save/export PDF and
   reopen; independently inspect DOCX content/styles and rendered PDF layout.
4. Excel: create/open a disposable XLSX, navigate sheets/ranges, enter values
   and formulas, check results, format, add/rename sheets, sort/filter, chart,
   configure print scaling, save/export PDF and reopen; independently inspect
   workbook records and rendered output.
5. Exercise modal dialogs, changed layout, stale references, save/overwrite,
   cancellation and restart. Preserve originals, checkpoints and uncertain
   effects. Record attempted and verified cases, timing, screenshot volume and
   fallback frequency without extrapolating reliability from individual trials.

Save only observed, verified procedures as reusable workflows and app skills.
All live proof must use Mechanize MCP and Endly; document generation or another
GUI controller does not qualify the Mechanize automation path. Read-only file
inspection is independent verification, not a substitute for GUI execution.

## Permission attribution follow-up — October 4, 2026

macOS permission records confirm Accessibility, Screen Recording and Input
Monitoring were granted to the exact installed `mechanize-native` path. Live
helper preflight checks nevertheless returned false. TCC attribution logs
identified the responsible launcher as the Codex host for shell-launched checks,
and the signed `mechanize` broker for a launchd-launched check. Helper-only
permission guidance was insufficient for this deployment.

The owned broker was stopped gracefully without clearing state or fences and
restarted as a per-user launchd job `com.viant.mechanize.office-development`.
Its plist is in the private installation's `runtime/broker.plist`, with
`KeepAlive` disabled and no login persistence registration. The restarted MCP
endpoint is responsive and a new owned session was opened. The broker executable
`mechanize` also needs the human's privacy approval under this launch context;
recheck live capabilities afterward. A doctor launched from the Codex shell
continues to test that shell's attribution and is not sufficient evidence of the
standalone service's permissions. No TCC database was modified.

## Latest live results

The output pair is under `~/Documents/Mechanize Qualification/`:
`Mechanize Excel Qualification.xlsx` and `Mechanize Excel Qualification.pdf`.
The workbook was entered, saved, closed and reopened through Mechanize MCP and
Endly. Both live editor readback and independent OOXML inspection confirmed
Sheet1!A1 = `test`. Excel exported one Letter-size PDF page, visually inspected
without clipping, and the XLSX hash stayed unchanged. These are small cases;
full Word editing, formulas, charts, layout and reliability remain open.

`verify-artifacts.py` performs read-only OOXML and optional PDF inspection. It
accepts a JSON sheet/cell/expected-text mapping, optional original workbook hash,
and optional expected PDF text/page count. PDF inspection requires `pypdf`;
workbook inspection uses only the Python standard library. It never generates
or edits Office documents. `evidence.json` records the current case results,
artifact hashes and retained uncertain effects.

The helper now handles explicitly absent optional text subroles and bounded
AXStringForRange reads for an enrolled field when AXValue is absent. Live Excel
readback exercised that path. The pointer diagnostic is read-only: macOS's
system-wide hit test identifies Excel at the tested point, but does not expose
an exact window through AXWindow or the bounded same-owner parent walk. Frame
capture still rejects `windowClickOccluded`; no pointer input was qualified.
Matching an app PID alone must not be treated as proof of the permitted window,
and no Dock-name/PID exception has been added to the occlusion guard.

## Staged text/formatting candidate — October 4, 2026

The isolated candidate `office-text-state-20261004T181852Z` adds opt-in
`typeWindowText` and exact checkbox/radio observations. It is built and signed,
and its console credential is enrolled. The active service has not switched to
it. A launchd preflight reports Accessibility, Screen Recording, event posting
and Input Monitoring unavailable for the new ad-hoc signing identity. Human
macOS approval is pending; an earlier build's permission grant is not evidence
that this candidate can control Office. No TCC records were changed.

Source digest: `4f920e1f0824b700462b58fa2762d9a275fe92b48286e705b330cfe1020048fe`.
The source snapshot preserves exact candidate code separately from subsequent
qualification-document updates. `go test -p 2 ./...`, `go vet ./...`, and the
149 native Swift tests passed. Two overlapping Go runs shared a log accidentally;
the final successful process exit is recorded separately from that mixed log.
Focused checkbox tests additionally cover null/mixed states, unsupported roles,
missing helper advertisement, negation and capability refresh. These are code
validation results, not live Office text or formatting qualification.

The candidate reuses existing credential references, consent identity and
durable storage, preserving unknown-effect records. The existing installation
remains available. Before service activation, repeat the candidate permission
check; after activation, open a fresh MCP session and verify advertised
capabilities before sending input. See [native-window-text.md](../../../docs/native-window-text.md)
for the action's bounds and verification requirements.

### Activation follow-up

The candidate is now running, its console connection is authenticated, and all
four macOS permission checks pass. A live Excel window capture succeeded. Fifteen
older Launch Services registrations were removed, leaving the current panel
registered; recovery files remain intact.

The new frame-click attempt still fails exact window ownership before dispatch.
Excel's menu tree currently includes a node with no role, so strict menu role
lookups reject the incomplete evidence. One Cmd+N action created Book3 while its
original check expected Book2; that unknown record is preserved without replay.
The plan declared a blank Book3 editor precondition, but source review found
that preconditions were not evaluated; that baseline is unverified. Literal
formula entry failed
`windowTextUnqualified` before input despite host capability advertisement.
The added readiness diagnostic is a source change and is not in the running
candidate. Text, formula and formatting qualification remain open.

A source fix now evaluates preconditions for new durable attempts before
recording input intent or dispatching; confirmed replay results retain their
existing behavior. Unverified baselines stop read-only steps as well. This fix
is not yet in the installed candidate.

### Corrected build installed in place

The root cause of text rejection was a second assignment to the helper doctor's
`nativeWindowActions`, which removed `typeText`. It is now assigned once, and a
test exercises the actual doctor response. The host also requires fresh helper
advertisement before exposing text or checked-state capabilities. These fixes
and the durable precondition gate were installed at the existing runtime path
from frozen source `office-text-state-20261004T191847Z`, digest
`11b46ce1fa40cf51415ea4827a0ce67d810eafad1e9fd13b361ff9110b311b54`.

All Go tests, vet and native Swift suites passed. The connected console and
rollback files are intact. The new signing identity invalidated the OS grants
even at the same path: launchd doctor again reports all permissions false.
Human re-enablement is pending; no Office input followed this upgrade.

## Verified block-entry procedure

A 73-step Endly/MCP operation populated a 5-row by 3-column sales table without
manual intervention. Each cell verified its address through the explicitly
enrolled NameBox, required an empty formula editor, entered Control+U edit
mode, typed into the observed XLIncellEditor, checked content and committed.
Entering edit mode first also qualified a text value longer than one chunk.
The source workbook was saved through Excel and 16 cells were independently
checked in OOXML. The complete analysis/chart/recovery task is still pending.

[`plan-cells.py`](plan-cells.py) emits this procedure as a typed JSON workflow;
it does not execute input or generate a workbook. Supply JSON on stdin with
`processId`, `processStartToken`, `windowId`, `windowTitle`, a unique `caseId`,
`startRow`, `startColumn` (A–Z), and rectangular string `rows` (up to 100 cells).
The emitter rejects unknown parameters, coerced or out-of-range physical IDs,
malformed birth tokens, control/multiline text, ragged blocks, column overflow,
and a final Return position beyond Excel's row limit. Its safety checks can be
run with `python3 examples/endly/microsoft-office/test_plan_cells.py`.
Use fresh identity and position evidence. The plan requires the cursor already
at the starting cell and all destination cells empty. Validate through
`mechanize_script_validate`, submit once through Endly's MCP runner, retain the
operation ID and inspect terminal state; do not resubmit an uncertain run. The
parameterized emitter was validated against the installed broker without
executing a second population.

Direct NameBox AXConfirm did not navigate reliably; its unknown record remains
preserved. The separate Go To dialog route successfully selected C3 and checked
NameBox readback. See Microsoft's [Excel shortcut reference](https://support.microsoft.com/en-us/accessibility/excel/keyboard-shortcuts-in-excel)
for the Control+G dialog command; actual controls and results still require
live observation. A helper-only update enabled enrolled nonsecure text combo
readback without changing the broker binary; all OS permission checks remained
granted.

## Recovery and partial analysis checkpoint

`Mechanize Sales Analysis.xlsx` is a separate GUI-created copy of the source.
Independent inspection verified all eight per-region profit/margin formulas and
cached results while the source hash stayed unchanged. Totals, chart and reopen
verification are not yet complete.

The first formula plan paused after nine verified mutations. Its unbound address
read steps could not safely be rerun from the later editing position. The original
run remains preserved. A fresh verified tail completed only the remaining edits.
The emitter now attaches each address guard to its edit action as a precondition,
while the text action still requires an empty editor. This avoids replaying a
standalone address check associated with an already committed edit.

The injected totals cancellation correctly produced a terminal cancelled run,
which cannot be resumed. The separate owner-pause implementation needed fixes:
carry pause intent to completion, wait for the durable callback, read committed
root metadata without waiting behind the executor lock, and verify final run
correlation/revision. Tests now prove pause/resume without replay, stale pause
rejection, and terminal cancellation immutability. The corrected package was
installed from frozen source `office-text-state-20261004T201219Z`. macOS invalidated
its grants after re-signing; live pause qualification awaits re-enablement.

The panel now points Show in Finder at the signed broker and hides stale permission
results when disconnected. Duplicate build registrations were removed again.

### Live pause/restart/resume result

Owner pause stopped the corrected totals plan after four verified steps. A
native teardown timeout retained generation 279's physical fence. The existing
read-only Datly `LeaseNeverDispatched` projection proved zero attempts for that
generation; the helper process was gone. After graceful broker shutdown, the
existing `Supervisor.ReconcileNeverDispatched` API repeated the ledger proof and
stop checks before releasing that generation. No lock-file deletion, invented
proof, business-effect rewrite or input replay was used.

The same durable run resumed after restart and completed 19 verified steps. Its
original four attempt IDs remained, with no resumed-prefix attempt IDs. This is
a successful recovery with an operator utility, not yet a fully automatic fault
recovery path. Saved totals independently match revenue 5,400, cost 3,500, profit
1,900 and margin 0.3518518518518519. The source workbook hash remains unchanged.
Chart/reopen and whole-suite acceptance remain pending.

### Chart persistence verified

The analysis workbook now contains one column chart with independently verified
source ranges, categories and numeric caches. Closing and reopening through
Mechanize/Endly produced a new window, preserved Region readback and the visible
chart, and left the saved file hash unchanged. The output remains a qualification
fixture: default chart positioning overlaps part of the totals row and margin
formatting needs refinement. No fully unattended or polished-suite claim follows
from this case. The chart-opening menu's original name-based predicate remains
unknown because the gallery exposes IDs but no names; creation was not repeated.

Excel ribbon radio buttons expose neither AXValue nor AXSelected in this case.
A conservative radio-only AXSelected fallback is implemented and unit-tested
but did not make these particular tabs readable. Insert-tab switching instead
verified the newly visible Recommended Charts control. Avoid assuming that a
created chart is selected: here Name Box remained C3.

## Parameterized Word text/format plan

`plan-word-report.py` reads one JSON settings object from stdin and emits a typed
plan for Endly/MCP. It neither controls the desktop nor writes a DOCX itself.
Supply fresh `processId`, `processStartToken`, `windowId`, `windowTitle`, a stable
`caseId`, discovered `headingIdentifier` and `normalIdentifier`, and single-line
`title` and `body`. Text fields are bounded to 255 UTF-8 bytes for this Find-field
staging recipe. It changes the GUI clipboard and Find query.

Start with an owned empty target document in an uninterrupted desktop interval.
The initial text precondition must prove it empty. Each document-changing paste
is bound to its physical window rather than an app-global Paste menu, so a
changed active Word document cannot silently receive that paste. Focused Find
controls and checked style controls must match fresh observations.

Submit through the pinned Endly `mcp/runner` service with the exact session,
purpose and consent binding. Keep the returned run/operation IDs. Tooltips,
permission prompts, unexpected content or focus changes may pause the plan;
inspect the original run and resolve the actual blocker before resuming. Never
change the case/request identity just to bypass an unknown effect. Saving and
exporting remain separate dialog-discovery stages.

This emitter passes live parser/type validation with quoted strings, backslashes
and Unicode. It rejects malformed identities, controls and oversized staging
text. It has not yet been executed end to end as a generated plan. The manually
qualified Word case used the observed Find/Paste menu routes and a bounded
app-focus reset for a tooltip. The generator deliberately uses exact-window
keyboard routes for Find/Paste; these need their own live qualification in a future controlled case; the earlier Word local-network system prompt is now resolved.

## PowerPoint two-slide case

Mechanize created `Mechanize Sales Brief.pptx` through the live PowerPoint UI,
containing the sales totals and regional findings. Read-only PPTX inspection
verified both slides and all expected text. Closing and reopening through
Open Recent produced a new physical window with both slides visible; the file
hash was unchanged. A first-run accessibility tip paused input before dispatch;
dismissing its observed Got it button allowed the original run to resume.

The canvas exposes disabled AXLayoutArea nodes without text children. Tab and
Return selected/edit placeholders; the focused Find field staged known text for
GUI copy/paste. Captures and saved-file checks supplied content evidence. Window
survival predicates alone are not content verification. Original title, filename
and unscoped save-name verification failures remain recorded; no failed paste
or save was repeated. Local PDF export also produced two verified, rendered pages. Unattended
slide-text verification remains an open requirement.

## OneNote first-use case

Mechanize completed OneNote's observed Get Started and Start Using OneNote
screens using the existing Office setup. A disposable OneDrive Personal notebook
`Mechanize Qualification 20261004` was created once; its original exact-window
predicate reconciled after asynchronous creation. The existing user notebook
was not edited. New Section 1 and a blank Untitled Page were observed.

Page editing remains unqualified. Current page exposes a disabled AXLayoutArea
without editable text children. The focused Search subtree contains two
AXTextFields, and its suggestion popup blocks exact-window keyboard input.
Known test text was staged only in Search; it was not pasted into the page.
Cloud sync, reopen persistence and PDF export remain to be tested.

## Private comparison recovery fix

The source resolver now admits the original `native.literalValueMatches`
postcondition for effect reconciliation under the same process, root, window
and locator checks as native value comparison. It preserves the expected typed
string and rejects other attributes/types. Evaluation still requires control
identity and fresh helper proof, returns False/Unknown when not established, and
exports no compared AXValue. Tests cover both declarations and original
postconditions, changed scopes, absence of proof, mismatches and permission
denial. This broker source change is installed in the October 5 development
runtime; live private-comparison reconciliation remains unqualified.

## Parameterized PowerPoint chart dimension plan

`plan-powerpoint-dimension.py` emits the observed GUI clipboard route for the
Format ribbon's Width:/Height: AXIncrementor controls. Supply fresh processId,
processStartToken, windowId, windowTitle, a stable caseId, control and decimal
value. It rejects malformed identities, unsupported controls, controls/newlines,
non-numeric values and values outside its bounded positive range. The displayed
units must be checked before execution. Width=8 and height=4 emitted plans both
ran successfully, and saved chart geometry verified 8 by 4 inches.

Use an owned deck with one independently verified selected chart. Chart Design
presence is a context guard, not an exact chart identity receipt. Fresh capture
inspection and saved-file geometry checks remain required. The emitter neither
creates a presentation file nor grants permissions.

## Chart portability and save-error recovery

Default Excel-chart paste remained linked to the source workbook. Paste Special
Microsoft Excel Chart Object generated an unsavable Object 4 on slide 3. The
agent-created object was removed using the displayed recovery action, and the
native chart was restored, resized, saved and reopened. Reopening required
selecting the exact owned source workbook in PowerPoint's Grant File Access
flow. Source file and saved deck hashes remained unchanged through that flow.
Editable chart embedding is not qualified. The independent PDF remains usable.

Source now has a separate `.showMenu()`/AXShowMenu action because pressing the
Paste menu button performed a default paste. The action requires explicit helper
advertisement, an enabled menu role, exact process birth, control consent and a
held fence. Older helper, wrong role, missing advertisement, missing enabled
state, missing process, wrong birth, absent fence and observe-only cases reject
before input. There is no press or keyboard fallback. It is built, tested and installed in the updated development runtime. The initial
macOS Accessibility check reported permission absent; live qualification is pending.

## Reusable independent deck verifier

`verify-sales-brief.py FILE.pptx` is a read-only verifier for this demonstrated
four-slide case. It checks the actual presentation slide order, exact text,
saved native chart, categories/values and 8 by 4 inch frame within slide bounds.
It reports external relationships separately. `--require-embedded` fails when
external relationships remain or no internal chart workbook with the expected
source cells can be verified. It never creates a presentation or controls Office.
The restored live artifact passes; linked-chart portability correctly fails.
Temporary negative fixtures with a missing chart, altered value and reversed
slide order were all rejected; production artifacts were untouched.

## Final-paragraph editing

`plan-word-paragraph-edit.py` accepts exactly processId, processStartToken,
windowId, caseId, heading, originalBody and replacementBody. It emits the narrow
eleven-step edit procedure for a focused disposable two-paragraph single-page
copy. Values must be public text; this procedure changes Find and the clipboard.
Inspect uncertain effects before resuming; never regenerate case IDs to replay.
The original manually composed plan was live-executed, while the parameterized
emitter is parser-validated only. `verify-word-paragraph-edit.py` independently
checks the exact replacement and neighboring paragraph XML preservation. See the
[case guide](../../../skills/mechanize-microsoft-office/references/word-paragraph-edit.md)
for Save As interruption findings and remaining export/reopen limitations.

Native outcome admission now validates enrolled declared recovery contracts before
intent/input in source. The frame-focus emitter requires windowTitle from fresh
capture evidence and uses a window-scoped focused flag. This updated emitter is
parser validated only. No historical unknown effects or predicates are rewritten.


### Read-only Word table preservation gate

`verify-word-table.py` inspects a saved DOCX against its baseline and a JSON
matrix of expected string cells. For example:

```sh
python3 verify-word-table.py baseline.docx saved.docx expected-table.json \
  --insertion-index 2 --baseline-sha256 BASELINE_SHA256
```

The index is zero-based among direct document-body children, before final
section settings. The verifier requires one new plain rectangular table and
preserves old paragraphs/runs, styles, section layout, header/footer references
and protected package parts. Nested/merged/tracked or non-text cells are refused.
It returns only counts, hashes and preservation flags. Its 13 synthetic tests
are file-inspection tests, not Office execution evidence.

On October 6, the current table qualification copy contains zero tables and is
correctly rejected. Its paragraphs and section XML match the **editing**
qualification copy, which is the appropriate baseline for this next case.
GUI insertion, save/reopen and rendered pagination remain pending. The current
PowerPoint brief also still fails strict self-contained verification because
external relationships remain; do not present that deck as a qualified independent
editable attachment.
