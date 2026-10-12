# Excel ISO date formula and formatting

Observed October 5, 2026, Excel 16.113.3 on macOS 27.0 through Mechanize MCP,
Endly and the signed native helper. The disposable sales workbook's previously
blank Sheet2 gained one A1 formula, `=DATE(2026,10,5)`, displayed as `2026-10-05`.
Saved XLSX inspection verified cached serial 46300 in the 1900 date system and
the selected ISO number format. Sheet1 content, original style records/number
format definitions, chart, drawing, media and theme parts were preserved. The
pre-edit workbook remains in a byte-for-byte backup.

1. Independently preserve/check the saved file and freshly verify the intended
   blank sheet is selected in the exact owned workbook window. The cell emitter
   does not choose or bind a sheet by itself.
2. `plan-cells.py` generated the live cell-entry workflow from fresh process/birth,
   physical window/title, stable case ID and the one-cell DATE formula. The
   qualified editor route used Control+U, guarded text input and Return; each
   result was checked. A1 entry ended with NameBox A2.
3. ArrowUp returned to A1. Cmd+1 opened the uniquely owned Format Cells window.
   The first attempt was rejected before key dispatch when Excel was no longer
   foreground, leaving zero unknown effects. After activation, the **original**
   run resumed and completed; the formula-entry run was not repeated.
4. A fresh exact-window capture showed Date already selected because Excel
   autoformats DATE formulas. The Type table exposed focus metadata but not
   selected-row text. One inspected capture-bound click chose the ISO example
   `2012-03-14`. The typed predicate established Type-table focus only. A separate
   capture independently showed that ISO row selected and sample `2026-10-05`.
   Focus alone must never be described as proof of exact format selection.
5. Return in the current Format Cells physical window restored the focused Excel
   Content Area. The observed Save button saved once, with exact formula readback.
   A new capture showed A1 as `2026-10-05`, not clipping or hashes.
6. `verify-date-cell.py BEFORE AFTER SHEET 2026-10-05` independently checks the
   bounded XLSX package, exact single A1 formula/result, saved ISO preset,
   original worksheet/style/format preservation and chart/media bytes. The
   captured display is separate evidence for actual rendering. The verifier
   qualifies this blank-sheet fixture and 1900 date system only.

The installed digit codec accepts a single named ASCII digit in a chord and
requires one verified main-keyboard layout mapping, refusing numeric-keypad
fallback and ambiguous layouts. Cmd+1 now has this live dialog-opening evidence.
No arbitrary text, raw numeric key code or command sequence is enabled.

Reobserve dialog IDs and original image coordinates; the observed `_NS:176`
Type-table ID is not portable. Full and inactive/active captures can differ;
reject a changed image and inspect again before any click. Capture and click
must use the same session, approved grant and exact purpose.

Locale/calendar changes, 1904 workbooks, multi-cell date ranges, sorted/filtered
dates, unattended type-row proof and broad date parsing
remain unqualified. Server business status remains unverified without an enrolled
authoritative outcome adapter. Do not clear older unknown Office effects using
this independent saved-file evidence.

## Close/reopen and saved rendering

The saved date fixture was closed with its exact physical window's Cmd+W. A
complete fresh window inventory proved absence before reopening. The actual
parameterized `plan-excel-reopen.py` output then executed through MCP and Endly,
checking Sheet2 in the reopened window. A separate read-only operation privately
compared the formula to `=DATE(2026,10,5)`. Fresh capture showed `2026-10-05` in
A1 without overflow hashes; saved file SHA256 remained unchanged. These runs had
zero unresolved effects. This qualifies the emitted reopen workflow for this
case; fresh unique recent-file lookup, owned process identity, absent document
window and independent saved-file checks remain required for another case.
