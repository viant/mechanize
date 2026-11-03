# Native Office checks

Start on disposable copies when qualifying a new route. Existing file format, content, formulas, sheets/slides, charts and template design are the comparison contract. Reuse existing Office sign-in; application launch is not permission to overwrite another document.

Excel: inspect the selected cell/range, enter typed values/formulas, verify dependent recalculation with a temporary input change, restore the input, save locally, inspect the saved formula/cached result independently, and reopen. Preserve dates, percentages and leading-zero identifiers. Verify sort/filter behavior separately if requested. A source-cell formula string does not prove calculation.

Observed Computer Use case on Excel 16.114.3: bulk TSV paste into a verified blank A1 produced a 4-row, 2-column table. Setting NameBox via `setValue` did not establish navigation; explicitly clicking NameBox, selecting its text, typing B2, pressing Return, then observing `NameBox=B2` and the formula editor worked. A paste-size warning was cancelled before retrying on the verified single cell. Do not apply this as an unconditional workaround on other versions.

Observed Mechanize case on the same version: after the console-owned capture
update, permanent Office trust was reused across sessions without a new prompt.
Native activation, physical-window discovery and image capture worked. The active
workbook's full window observation was incomplete. A scoped Edit-menu observation
and its Go To action worked; the small Go To dialog exposed a writable reference
field and OK button. A two-step Endly fill/confirm batch selected B4, independently
confirmed by a fresh screenshot showing the selected cell and formula bar. This
qualifies navigation only, not arbitrary cell editing or whole-workbook reliability.
Rediscover the dialog identifiers; do not copy historical transient IDs.

An observed executor handoff left NSWorkspace reporting the controller app while
system AX reported Excel. Explicit Mechanize activation established agreement,
after which the paused menu action safely resumed with no unresolved effects.
Find & Replace fields accepted a two-step semantic fill batch. Replace All then
returned AX error -25204 although Excel displayed a one-replacement confirmation.
That attempt remains uncertain in the durable ledger: do not repeat it or claim
save/recalculation qualification from the alert alone. Use a declared, enrolled
outcome contract for future mutation trials; an uncontracted modal transition can
leave a completed edit impossible to reconcile automatically.

Follow-up inspection of that disposable copy confirmed the input changed from
2500 to 5000 and the formula result from 100000 to 200000. Computer Use dismissed
the informational confirmation, closed Find & Replace, saved and reopened the
copy. Read-only saved-file inspection confirmed the formula and numeric cached
result. Attribute this to a hybrid recovery, not a successful Mechanize durable
run: the original unknown effect remained preserved and was never replayed.

A later Excel 16.114.3 copy test qualified one numeric edit, recalculation,
Save, Close and reopen through Mechanize, with Computer Use native inspection and
read-only saved-file QA. B2 changed from 2500 to 5000; B4 retained `B2/B3*1000`
and recalculated from 100000 to 200000. Other cells and styles were unchanged,
and the original source hash was preserved. The qualified steps had zero
unresolved effects; earlier failed/uncertain trials remain recorded. This is a
small operation qualification, not full-workbook or repeat-speed evidence.

That route required the existing session-text and session-keyboard opt-ins plus
live qualification. Before typing, verify the selected cell and original formula
editor value. `typeWindowText` is a terminating app action with fresh physical
window ID and declared focus role/name; do not chain `.window(...)` before it.
Declare the exact native formula-editor precondition and postcondition separately.
Use the enrolled original-postcondition reconciliation contract if needed; an
extra `effect.reconcile` requires its own separate enrollment. Commit with Return,
save the copy, verify saved formula/cache, then close and reopen the exact file.
The named-key grammar uses `Control+G` for Excel Go To, not `Ctrl+G`.

A floating non-key window previously blocked physical text despite worksheet
focus. The qualified fix accepts a non-top window only with a unique fresh
AX-focused-window/physical-window match of owner, process birth, title and geometry,
and rechecks it before input. Missing or ambiguous evidence still refuses input.
For file-panel fields outside the value-read allowlist, compare a known public
literal with `native.literalValueMatches` before confirmation; do not broaden read
permissions or expose unknown field contents. A transient observation failure
immediately after a dialog transition requires a fresh bounded read, not repeated
input. Rediscover all transient dialog/control identifiers.

A six-sheet proposal-copy test extended the numeric edit route to an existing
formatted workbook. Mechanize selected a qualified sheet/cell through Go To,
changed one budget input, and verified the dependent row, paid total and conditional
added-value formulas. Save/reopen preserved all six sheets, formulas, merged ranges
and other cell values, with no cached formula errors. A physical Cmd+S attempt was
refused before dispatch (`foregroundAcquisitionUnavailable`); a fresh File-menu
Save succeeded. Keep that failure visible and prefer the qualified semantic Save
route for this state rather than retrying the shortcut.

An independent Computer Use edit on an identical copy produced matching saved
cells and styles across all six sheets. Both native Excel saves rewrote the same
font/fill metadata; retain such differences from the source and compare their
appearance and the two executor outputs before attributing them to automation.
This qualifies the observed edit/recalculation/persistence operation, not complete
proposal authoring or repeat-speed parity. Freeze and batch both proven procedures
before timing repeats, with file QA and recovery included in the boundary.

PowerPoint: use existing placeholders/objects, preserve chart data and embedded workbook relationships, inspect every affected slide, save and reopen, then export and inspect the PDF. Compare slide count, text, numeric consistency, image crops, native editability and layout. Do not replace editable charts with images or drop slides to meet a time target.

Observed Computer Use baseline: selecting Blank Presentation opened a one-slide
deck. With the slide editor focused, Tab selected the title placeholder; typing,
Escape, then Tab selected the subtitle. Both texts persisted after local Save,
Close and Open. Read-only PPTX inspection confirmed two native text shapes, and
the reopened screenshot showed no clipping. This is a small creation/persistence
check, not an export, complex-layout or timed-repeat qualification. The editor's
AX layout area reported disabled despite the supported keyboard route working;
do not equate that attribute with an application-wide editing prohibition.

Observed Mechanize export on the same one-slide fixture: exact app activation,
File > Export, filename fill and Best for printing selection worked after the
attached-sheet membership/focus fixes. The Export action returned AX error
-25204, but the PDF was created; independent text, page-size and rendered-pixel
checks matched the Computer Use export. The durable export effect remained
unknown and was paused without replay. This qualifies the observed file result,
not automatic outcome reconciliation or repeat-run reliability. The presentation
itself was authored by Computer Use, not Mechanize.

A subsequent fresh export declared a UI precondition and postcondition before
dispatch: the unique Save button in the exact document window was disabled while
Export was open and enabled after returning to the document. With
`requires.adapters: [native]` and host enrollment of
`plan.postcondition.reconcile`, the original predicate resolved the AX error
through a fresh read. After a confirmed stopped boundary, reconciliation left
zero unresolved effects; resume skipped the confirmed action. The PDF hash and
mtime stayed unchanged across resume, and independent text, page-size and pixel
checks matched the Computer Use baseline. This is one verified export/recovery
case, not a full-deck or repeated reliability claim.

Declare such conditions before input and retain exact process/window boundaries.
After uncertainty, inspect the original operation/run, establish its stopped
boundary, reconcile with the original effect/attempt and current revisions, then
resume only after confirmation. Never add a convenient predicate to an old
unknown effect. UI transition verification establishes that transition; saved
artifact correctness remains a separate mandatory check. Include recovery calls
and file review in timing/token comparisons.

A later 19-slide preservation test used Computer Use to focus two embedded
Find/Replace fields and Mechanize for entry, a capture-bound Replace click, Save,
local PDF export, Close and reopen. Label that route hybrid. The editable chart
and embedded workbook remained byte-identical, and the saved deck hash survived
reopening. Full-window AX observation was incomplete; focused-field and fresh
capture routes supplied bounded evidence. Cmd+F opened a separate floating Find
toolbar, not the embedded replacement field. Do not repeat its known unsupported
setter route. Capture clicks use `clickWindowFrame(captureRef:...,x:...,y:...)`;
window identity is already bound by the permit, so there is no `windowId` option.
Use original image pixels and the same session, grant and returned purpose.

For local PowerPoint PDFs, explicitly verify Best for printing; a new deck may
instead default to the Microsoft online-service option. A window-scoped Return
can commit the observed Export sheet. A predeclared File-menu Save enabled-state
transition supplied the original postcondition after asynchronous export. Named
menu inputs must match the declared scope. A successful reconciliation requires
its stopped-runtime guard, exact revisions and `commitConfirmed`; checkpoint
publication alone is not proof. Resume skipped the confirmed export, verified by
unchanged PDF hash and modification time. Keep failures and recovery overhead in
performance records. If a window shortcut is refused before dispatch, fresh
active-document evidence plus an observed semantic File command may provide a
qualified route; never replay unknown input or bypass denied consent.

This test also exposed malformed generated raster fallback data in its input
fixture. A valid ZIP/PPTX structure does not prove that every image decodes.
Validate raster payloads and resolve image relationships by content, since native
Save can rename media parts. Preserve failed checks, repair the baseline in a
separate local-artifact revision, and restart comparisons rather than silently
repairing outputs claimed as native. A raster reference PDF is not an identical
rendering-method baseline for a native PDF timing comparison.

A subsequent clean-input 19-slide test completed the same single-label edit,
Save, local printing PDF export, Close and reopen using Mechanize alone. Fresh
capture-bound clicks focused the embedded Find and Replace fields; focused
textbox fills and Return found exactly one match, then a fresh capture-bound
Replace click changed it. This removes the earlier Computer Use focus assistance
for that observed panel. Do not reuse its pixel coordinates or capture permits.
All 336 shape identities/types/names/geometries and active image bindings were
preserved, chart and embedded workbook bytes matched, all 66 raster images
decoded, and the reopened deck hash stayed unchanged. All 19 rendered PDF pages
matched the earlier independently reviewed native export pixel for pixel.

That export required the original-postcondition reconciliation: its initial
read returned an unavailable outcome before asynchronous export finished. Resume
skipped the confirmed export; PDF hash and mtime stayed unchanged. This is a
successful native edit/persistence case with recovery, not first-attempt export
reliability, complete deck authoring, or a timed comparison. Investigate the
underlying read failure before changing retry policy. Physical Export-sheet titles
need not be AXWindow titles; after scoped observation fails, use a fresh exact
physical-window capture instead of guessing another accessibility title.

A following diagnostic isolated `rootUnavailable` during the export transition.
The bounded native postcondition wait now settles this read-only error while
retaining the original selector/process and stopping on permission, ownership,
transport and stale-process failures. One installed-runtime retest completed its
19-page export and original postcondition in a single 3.56-second call, with zero
unresolved effects and no reconciliation or input replay. All rendered pages
matched the reviewed native PDF exactly. This single retest is evidence for the
fix, not a repeat-reliability or end-to-end speed claim. Preserve the original
postcondition and timeout; never replace this bounded read wait with export retries.

Word: preserve paragraph styles, pagination, comments/revisions and fields required by the task. Outlook: draft, attachment, send and Sent verification are different outcomes; no sending unless explicitly authorized.

For Mechanize fallback, retrieve `skill://mechanize-microsoft-office/SKILL.md` and only its relevant case. An offline QA reader must not silently repair or rewrite files claimed to be native-authored. Declare a hybrid route if local authoring is part of the work.
