# Excel blank-sheet insertion with a capture-bound click

Observed October 5, 2026, Excel 16.113.3 on macOS 27.0, through Mechanize MCP,
Endly and the signed native helper. The disposable sales-analysis workbook gained
exactly one blank Sheet2. Independent XLSX inspection verified that Sheet1's
content and formatting survived, including formulas/cached results, and that
protected chart, drawing, media, theme, shared-string and style parts were
unchanged. The original workbook remains in a byte-for-byte backup.

The sheet-tab plus control advertised no AXPress action. The tested route used
one inspected full-resolution exact-window capture and one capture-bound left
click. The helper's original separate subregion rendering rejected the current
pixel patch before dispatch. The stopped run had zero unresolved effects; fresh
observation showed only Sheet1 and the saved hash was unchanged. That historical
run remains retained. A helper update now renders the fresh full window using the
producer's geometry and crops locally for the same exact pixel/opacity comparison.
It does not loosen equality, hit testing, ownership, fence or one-use permit checks.
The newly captured post-update click succeeded, with Sheet2's identifier checked
inside the exact workbook window. Fresh observation reported Sheet2 selected and
blank. The observed Save button was then pressed once. Its UI postcondition alone
is not a save proof; independent XLSX inspection establishes the saved result.

`plan-excel-blank-sheet.py` emits a workflow from fresh process identity, captured
window identity/title, capture reference, original image dimensions, inspected
pixel coordinates, stable case ID and expected new default sheet name. Before
execution, require a complete current workbook observation, verify that the
expected name is absent, and independently preserve the original file. Use the
same session, approved grant and exact purpose for capture and execution. The
emitter does not capture, save, grant authority or automatically choose a point.
Its parameterized form is parser-validated only; the separately recorded live
case used the same action and outcome shape.

`verify-blank-sheet-preservation.py BEFORE AFTER NEW_SHEET` performs read-only
bounded package inspection. It ignores only original sheet views (selection and
focus), checks original worksheet XML content, rejects cells/drawings on the new
sheet, and compares protected parts byte-for-byte. It does not prove UI replay,
macros, external links or all workbook metadata preservation.

Blank-sheet rename, arbitrary sheet names,
multi-sheet workbooks and unattended recovery remain unqualified. Server business
status remains unverified without an enrolled authoritative outcome adapter.

## Close and reopen the saved two-sheet workbook

After independent file verification, an exact-window Cmd+W closed the workbook.
A complete fresh physical inventory proved that its window was absent. The
recent-file menu contained one exact `Mechanize Sales Analysis.xlsx` name.
The role/name query was rejected before dispatch because unrelated role metadata
was unavailable. No effect was unresolved. Fresh complete observation then proved
one exact name match, and the existing exact-name query reopened the file once.
Do not weaken role-query completeness checks or repeat an uncertain action.

The original Sheet2 identifier outcome passed. Fresh reopened-window observation
showed Sheet1's used range A1:G8 and selected blank Sheet2; the independently
checked saved hash remained unchanged. This establishes this saved two-sheet
case, not arbitrary workbook recovery.

`plan-excel-reopen.py` accepts fresh process/birth identity, exact current window
title, freshly unique recent-file basename, expected sheet identifier and stable
case ID. It emits an application-scoped exact-name action with a narrower
window-scoped result, preserving the implicit application root. An explicitly
menuBar-scoped action cannot substitute a different result root in the original
reconciliation contract. Before using the emitter, independently check the file,
prove its window is closed and the exact-name match is unique in a complete fresh
observation. Validate, submit once, inspect status and unresolved effects, then
independently check the reopened window and saved file. The emitter subsequently executed live for the independently saved ISO-date version of this same workbook; see [the date case](excel-date.md). This does not qualify arbitrary recent-file entries or workbooks.
