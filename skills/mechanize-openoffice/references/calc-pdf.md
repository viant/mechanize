# Calc, Excel formats, and PDF export

These workflows require case-by-case live qualification. Use them to define objectives and discover the actual UI, not as executable commands or proof of app coverage.

## Calc and Excel files

Discover the Spreadsheet creation/Open route, then verify the active Calc document and intended sheet. For CSV/text import, inspect delimiter, encoding, date and number interpretation before confirming. For XLS/XLSX, inspect the actual import/save choices and compatibility dialogs; do not promise features or formulas survive interchange merely because the file opens.

For a budget, tracker or comparison, define the requested columns, units, data ranges and formula results first. Examples of useful objectives are a total matching the stated inputs, consistent dates, and preserved formulas in the output. These are business checks, not selectors. Resolve the actual sheet/cell/range controls from fresh complete observations. Do not invent cell identifiers or assume the focused editor is the requested cell.

Checkpoint the source values before an edit. Use one qualified edit route and verify that the cell committed the intended value. Focused edit-control text and moving to the next cell do not prove a commit: an earlier OpenOffice Calc attempt used F2, `replaceText("Date")`, and Tab, but the saved ODS contained three empty sheets confirmed by fresh Mechanize capture. No cause is established; see `examples/endly/openoffice-mortgage/evidence.json` for the earlier run and saved artifact.

A later OpenOffice 4.1.16 case narrowly verified one committed Calc string in A1: after `replaceText("Date")` alone failed to persist the edit, a leading Space was inserted and removed with Backspace, then Return committed it. ArrowUp followed by F2 revisited A1, where an exact value matcher returned `Date`; after Return and Cmd+S, independent ODS `content.xml` inspection confirmed A1 has `office:value-type="string"` and text `Date`. Treat the key sequence as a version-specific observed procedure, not a general shortcut.

A corrected 106-step mortgage table run and ODS save later completed. A read-only verifier independently checked the saved package's summary, headers, dates, rates, stored formulas, cached results, and source URL. This qualifies the contents of that saved ODS against the example's requested table data. The run's Mechanize `businessStatus` remains `unverified`, and this file check does not qualify visual sheet formatting, print layout, or PDF export. Keep file-content verification separate from Mechanize business verification and visual inspection. For formulas, verify both the stored formula and evaluated result when the available read contract supports them; an image of a displayed number proves neither the formula nor full-sheet correctness. Respect current locale and number formats. If range selection, formula entry, commit verification or readback is unsupported, stop at that specific gap rather than paste a large guessed keyboard sequence.

For Excel delivery, stage the exact requested format and destination from the live dialog. Reopen/read the output and check the requested data, formulas, sheet names, totals and visible formatting. Preserve the original file unless the task authorizes replacing it.

One OpenOffice 4.1.16 mortgage workbook was saved as an `.xls` copy. The observed Save As format list offered `Microsoft Excel 97/2000/XP (.xls)`; `.xlsx` was not present. This qualifies only the observed XLS format entry and that saved example, not other workbooks or current Excel compatibility generally.

For that case, a fresh window-root snapshot avoided the full-app 1,000-node truncation. The window-scoped route used `Cmd+Shift+S`, then the observed Save window's unnamed `AXPopUpButton` via `office.window(title: "Save").getByRole("AXPopUpButton", name: "", exact: true)` to open the live format list. It selected the observed XLS item, filled `saveAsNameTextField` with `exact: true`, used `Cmd+Shift+G` and the observed `PathTextField` to choose the existing destination, returned to the filename field, and confirmed the save. The format confirmation was handled through the observed `Keep Current Format` control after verifying focus, then Space. Reobserve and validate each route for the current app version; these are not portable selectors.

The saved XLS was independently checked as BIFF8. `verify-legacy.py` read its headers, dates, rates, source notes, stored BIFF formula records and cached results; the corresponding DOC copy was checked for the complete report text. These file-level checks establish the saved copies' contents, but do not resolve UI input steps lacking their own postconditions or qualify the entire Mechanize workflow, every Excel format, or visual sheet formatting. Keep the original ODT/ODS intact when requested copies are produced.

### One named-sheet addition in the mortgage XLS copy

One copy received a sheet named `Automation Checkpoint`. A scoped read verified
the prior sheet-name literal `Sheet4`; one `replaceText` changed it to the new
name, then Return and Cmd+S were used. The read-only
`verify-calc-checkpoint.py` checks the pinned source and copy hashes, the blank
added sheet, all original cell values by sheet name, and the stored Sheet1 BIFF
formulas. Independent inspection found exactly one added sheet
(`Automation Checkpoint`, `Sheet1`, `Sheet2`, `Sheet3`) and preserved original
values/formulas by name. The original XLS hash stayed unchanged; the edited copy
has SHA-256 `127a1fca045d1d2b67544237a59e3cbef7ef1f80cd28cce9839ca2c94baf4767`.

The initial Insert > Sheet menu dispatch had no postcondition and remains
dispatched/unknown. The dialog capture and subsequent literal/file evidence do
not resolve it. This is a narrow saved-artifact check for one added sheet in
this copy, not general sheet-management qualification or a business-success
claim. During follow-up, OpenOffice exited with `SIGSEGV EXC_BAD_ACCESS`; the
observed accessibility stack does not establish a causal attribute. Restart
recovery later listed three documents as recovered, but the Start Recovery and
Next receipts remain unknown. Do not claim application stability or use later
recovery evidence to relabel those receipts. See
`examples/endly/openoffice-mortgage/evidence.json`.

## PDF from Writer or Calc

First verify the source document's content and layout. Discover the actual PDF export route and options, then stage destination, page/sheet range and any requested layout choices. Do not treat an unobserved Export menu or a print-dialog shortcut as a tested route.

For Writer, check headings, page breaks, clipping and reading order. For Calc, inspect print area, repeated headers, scaling and page orientation: a correct spreadsheet can still export as unreadable pages. Choose settings based on the user's intended PDF, not a blanket fit-to-one-page assumption.

After one qualified export dispatch, verify the output exists at the intended location, opens as a PDF, contains the expected text/data and pages, and renders legibly. Use an available PDF reader/rendering skill for the saved artifact; generating another PDF elsewhere does not prove the OpenOffice export. Inspect more than a filename or a thumbnail. If export becomes unknown, reconcile its original predicate before any second export.

Deliver the verified artifact with its format and any material compatibility/layout limits. If the GUI route is missing, explain the missing capability and offer an alternative only within the user's authorized scope, clearly separating it from OpenOffice workflow proof.

### Observed Writer PDF export (OpenOffice 4.1.16)

The mortgage Writer report produced a valid one-page PDF through the observed
`Export as PDF...` menu, the visually inspected PDF Options dialog's default
Export button (window-scoped Return), and the native filename/folder save route.
Independent PDF extraction confirmed the summary and source URL; a rendered page
was inspected without clipping. The layout was a plain single paragraph.

The menu invocation and final save workflow retained unresolved effects; the
final check incorrectly assumed that focus would return to the Writer text.
File verification does not clear those effects. Do not replay export because its
focus check fails. Inspect the intended output first, and define an export-specific
objective for future workflows. This qualifies the observed output, not complete
PDF recovery, polished layout, or Calc PDF export.

### Observed Calc PDF artifact (OpenOffice 4.1.16)

One copy of the existing mortgage XLS workbook was saved as
`Mechanize Calc Qualification.xls`; read-only spreadsheet inspection found the
same sheet names, cells, and stored BIFF formulas as the original XLS. The
source XLS remained unchanged. From that copied workbook, the observed Export
as PDF route opened options window `9979`. A fresh capture showed the `All`
pages selection and the default Export button. Return from that window reached
the PDF filename field; the exact filename was staged and a following Return
saved `Mechanize Calc Qualification.pdf`.

The saved PDF is 24,158 bytes, one page, SHA-256
`de67b8ba453124d013b15d62a483021928285bfba1e4bccb82c74d6bba64ae7c`. Independent
`pypdf` extraction found the table headers, dates, rates, spread and changes,
and source URL. A Poppler render was visually checked: the plain table is
legible, unclipped and fits on one page. The source XLS copy is 7,168 bytes and
has the original SHA-256
`c31a1eb6703ac0e883c311bb5f05768f29f160bfd74fb58103d372ebbcda7e63`.

The initial Options-menu dispatch (`808736d43c7b953570abd188cd479ca46bf8fb4f93880dbfc4a89dccd1050639`)
remains dispatched/unknown because it had no independent postcondition. The
later options-window inspection, filename-field check, enabled menu-data
postcondition and saved-file inspection do not resolve that earlier receipt.
The artifact check also does not establish Mechanize business success;
`businessStatus` remains unverified. This evidence covers only this copied
workbook and one-page PDF artifact; it does not qualify the PDF export route,
other spreadsheets, multi-page layout, or general Calc/PDF support. Details
and the render path are in
`examples/endly/openoffice-mortgage/evidence.json`.
