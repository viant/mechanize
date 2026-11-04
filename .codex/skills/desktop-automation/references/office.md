# Native Office checks

Use Computer Use first unless the user selects Mechanize. For Mechanize fallback,
retrieve `skill://mechanize-microsoft-office/SKILL.md` and its relevant case.
Chrome readiness is unrelated to native Office readiness. Keep domain rules and
real documents in the private task workspace; this guide describes generic UI work.

## Establish the operation

Use disposable copies for qualification. Record the source hash, exact intended
changes, output formats and quality checks. Preserve unrelated open documents.
Discover the current app PID, birth token and physical windows; bind actions to
the exact document. A saved file, an application receipt and a verified user
outcome are different evidence. Never repair a native output silently with a file
library; label any mixed authoring route as hybrid.

Batch deterministic steps, with fresh observation at dialog, selection and
navigation boundaries. Observe a path field after typing, before confirming it;
verify the resulting picker selection and opened document path. A setter return
alone does not establish a committed path, cell selection or edit.

Computer Use may return an accessibility diff after a setter. A missing control
in that diff does not mean it disappeared. Before resolving a different control,
merge the documented diff correctly or request fresh complete state. Do not reuse
old indices or repeat the setter merely to make the control appear in output.

For a repeat Mechanize procedure, avoid setup already performed by its qualified
native action contract. Semantic dispatch can acquire and verify the exact app's
foreground itself; do not prepend activation solely out of habit. Qualify both
already-foreground and background-app cases before removing that step. Likewise,
an explicit whole-dialog read or intermediate value check may be redundant when
the next action already resolves a fresh complete scope and checks the same fact.
Retain source identity, the final filename check before export, local-printing
verification, and saved-output QA. Never skip a required review boundary or reuse
an old element reference to obtain a faster result.

## Excel

1. Select the intended sheet/cell and verify both the selection and original value.
2. Enter the authorized value or formula and commit it. Verify dependent results.
3. Save, close, reopen the exact file, and inspect the changed area.
4. Independently verify saved values, formulas and cached calculations, required
   sheets, merged ranges, formatting and absence of formula errors. Check dates,
   percentages and leading-zero identifiers according to the task contract.

Before replacing nonempty editor text by keyboard input, establish full-text
selection independently of the Select All receipt. When Mechanize advertises
`native:textSelectionObservation`, use the exact editor's
`hasFullTextSelection` boolean as the replacement precondition. True means stable,
nonempty full selection; false includes a caret, partial selection or empty text.
Unavailable evidence is not false or permission to type. For an empty-field route,
prove emptiness separately. Verify the complete resulting text before Return or
Save. Focus, entering edit mode and a successful shortcut do not prove selection.
This check does not repair an existing uncertain edit or clear its durable effect.

For recalculation qualification, use a controlled input change on a disposable
copy and verify its expected dependent result. Restore the input only when the
task calls for a temporary change; do not undo the user's requested final edit.
Sort/filter behavior needs its own checks when relevant.

Qualify text conversion for the actual input route. Keyboard entry of a leading
apostrophe can preserve a literal date, while a TSV clipboard paste can retain
that apostrophe as data. Month-name dates and percentage-formatted destination
cells need explicit checks: Excel may convert the date or append a percent sign
while entering replacement text. Read back the complete buffer before commit and
verify saved cell types afterward. Cancel a known incorrect uncommitted edit
before applying a corrected entry route; do not repair by blindly appending keys.

For a bounded table paste, verify the single destination cell, exact rectangular
extent and every source field; exclude embedded tabs/newlines unless their import
behavior is qualified. Verify every saved destination value/type and preservation
of cells outside the range. Use a separate proven route for conversion-sensitive
fields. Keep batches within the tool's execution limit, with headroom for slower
observations. After a timeout, inspect the current edit buffer and saved progress;
do not rerun the batch. A kernel reset does not prove the last input was absent.

When an authorized reference provides the desired layout, native Paste Special
can transfer Formats and Column widths separately without copying values. Verify
the actual radio selection; a generic clipboard-format dialog is not Excel's
cell-format paste. Keep the reference unchanged and recheck all content afterward.
Raw style differences may reflect theme-font resolution or unused solid-fill
background metadata. Retain and classify those differences; visual review is still
required. Exact values and row dimensions alone do not establish layout fidelity.

Observed navigation routes on Excel 16.114.3:

- Computer Use: a NameBox `setValue` did not commit navigation. Clicking the box,
  selecting its text, typing the address and pressing Return worked; verify the
  resulting NameBox and formula editor. Bulk TSV paste requires a verified single
  destination cell; cancel a size warning and inspect the selection before retry.
- Mechanize: scoped Edit-menu Go To or `Control+G` exposes a small reference
  dialog. Rediscover its control identifier, focus and fill it, then confirm once.
  Do not copy historical control IDs or use the unsupported `Ctrl+G` spelling.
- Before `typeWindowText`, verify the selected cell and formula editor, and declare
  exact pre/postconditions. It is a terminating app action with a fresh physical
  window ID and focus role/name; do not prepend `.window(...)`.
- For known public file-path literals, `native.literalValueMatches` verifies a
  field without exposing arbitrary values. It must never probe secrets.
- If a save shortcut is explicitly refused before dispatch, inspect current state;
  an observed semantic File > Save may provide a qualified alternative. Unknown
  saves require reconciliation, not another shortcut or menu click.

Native Excel can normalize font/theme or fill metadata on Save. Retain source
and output differences and compare rendered appearance and both executor outputs
before attributing the change to an automation tool.

## PowerPoint

For the embedded Find/Replace panel, paste literal search and replacement text
into the focused fields; typing can trigger macOS substitutions, and an AX setter
can update displayed text without updating the value consumed by Replace. Check
the exact field values, match count, case option and destination slide before
Replace. Accessibility output may put `Value` before or after `Placeholder`;
compare the field's value rather than assuming one rendered attribute order.
Check saved shape text after a batch. Split multiline replacements by paragraph
only when each match is independently scoped and unambiguous.

An exposed thumbnail may be off-screen and refuse a click before input. Focus a
visible thumbnail and navigate by keyboard, checking the current slide number
after navigation before pasting. Rapid key sequences can miss a transition;
reconcile the observed slide instead of replaying the paste. For an authorized
editable status label, copy only the named shape from the reference, then verify
exactly one added shape per intended slide and unchanged original media. Review
placement on every slide; a shared position can overlap existing branding.

Preserve existing placeholders, editable shapes/charts, embedded workbook data,
image relationships, slide count and requested layout. Inspect every affected
slide, save/reopen, then export and review every PDF page. Valid ZIP/PPTX structure
does not prove image payloads decode; verify referenced images and chart data.
Native Save may rename media parts, so compare relationships by content.

For the observed embedded Find/Replace panel, fresh capture-bound clicks can
focus fields when scoped AX cannot. Then use focused-field fills, confirm the
unique match and use a fresh observed Replace target. Cmd+F may open a separate
floating Find toolbar; do not assume it is the embedded replacement field.
`clickWindowFrame(captureRef:...,x:...,y:...)` uses original image pixels and the
same session, grant and purpose. The permit already binds its window: there is
no `windowId` option. Refresh expired permits and never reuse historical pixels.

For local PDF export, verify Best for printing. The alternate online-service
option changes the export destination. Physical export-sheet titles may differ
from AX titles. When `native:focusedWindowScope` is advertised, inspect the owned
focused window/sheet using its exact PID and birth token. A complete dialog tree
can qualify a semantic radio-button click with a `checked` postcondition, avoiding
screenshot-based selection. If that scope is unavailable, inspect the exact
physical capture; do not guess titles or expand to an unbounded tree.

Verify the exact chosen filename before export. A screenshot may clip a long
filename, and a successful fill alone does not prove its value. When Mechanize
restricts that field's value read, use the supported `native.literalValueMatches`
precondition with the known nonsecret filename and exact focused-field scope.
A denied read does not justify broader value access. Keep the local-printing
selection check and resulting PDF verification as separate acceptance gates.

Declare export pre/postconditions before dispatch. An observed File-menu Save
enabled-state transition can establish return from the export sheet when the
runtime supports the original-postcondition contract. Keep predicate scope and
named-menu inputs identical. A sheet-scoped semantic Export action cannot adopt a
menu-scoped postcondition when the runtime rejects that scope change. After an
explicit pre-dispatch rejection, an independently qualified exact-window
confirmation may use its existing completion contract; never replay an uncertain
export or weaken the scope check. This UI transition does not replace PDF file QA.
A native AX error may occur after the export created a file: preserve the original
attempt, use the enrolled reconciliation contract and resume only confirmed
remaining work. Verify file hash/mtime remain unchanged when resume skips export.

## Readiness and recovery

An incomplete full-window tree can still permit a complete scoped dialog, menu
or focused-field observation. Missing evidence stays unavailable. Read-only
settling is bounded by the original deadline; it never repeats input. Do not
extend deadlines or weaken owner/focus checks to force a pass.

A floating window does not justify ignoring ownership. Native session input
requires fresh exact focus/window/process proof. An unavailable foreground refresh
is distinct from a known foreign foreground; preserve its closed failure code.
After explicit `notDispatched`, inspect current state before resuming the original
unfinished step. After `unknown`, inspect the original operation and durable
ledger; do not switch executors to bypass its barrier.

Session qualification can disappear during sleep or lock without revoking app
trust. Check actual session and system evidence before requesting another grant.
After wake, refresh readiness and resume only the original confirmed-undispatched
work. Preserve interrupted measurements and record recovery separately.

Small cell edits, single-label slide edits and successful exports qualify only
those operations and environments. They do not prove complete document authoring
or universal reliability. Keep detailed real-case evidence outside this repository.
For paired repeats, use [the measurement guide](benchmark.md).

Word: preserve required styles, pagination, comments/revisions and fields.
Outlook: draft, attachment, send and Sent verification are separate outcomes;
sending requires explicit authorization.
