# Excel Save As copy and custom number-format IDs

Observed October 5, 2026 through Mechanize MCP and Endly on Excel 16.113.3.
The independently verified date workbook was preserved while GUI Save As created
`Mechanize Sales Analysis - sorting qualification.xlsx` in the existing local
qualification folder. Both sheets' contents, style semantics and protected
chart/drawing/media/theme/shared-string parts were preserved. The original file
hash stayed unchanged.

The qualified Cmd+Shift+S route focused `saveAsNameTextField`. Its full literal
replacement set a new XLSX basename. Fresh capture independently confirmed the
local destination and Excel Workbook (.xlsx) type. The actual panel was an
AXSheet with physical window title Save; it was not a new-document AXWindow.
The app-owned OKButton Save control was pressed once, with the new workbook
window title checked. The target path was independently absent before Save;
no overwrite or compatibility dialog was accepted.

Excel renumbered a custom number format from ID 165 to 164 while retaining its
exact ISO format code and updating the style's reference. Byte-for-byte comparison
of styles.xml therefore failed even though the rendered meaning was preserved.
`verify-save-as-copy.py BEFORE AFTER` resolves each custom numFmtId to its exact
formatCode before comparison. It does not ignore other attributes, child order,
counts or style components. Duplicate definitions, dangling references and
custom definitions in builtin ID space are rejected. Original worksheet views
are omitted because GUI selection is expected to change. This verifier is a
bounded fixture preservation check, not an all-part workbook or macro audit.

## Sort preparation, still unqualified

One inspected capture-bound click selected Sheet1 in the new copy. The observed
Go To route selected C3:G7. A fresh capture showed the header and four regional
rows inside the selection, total row 8 outside, and Count 25. The observed unique
application-level Sort... item opened the owned Sort window. Capture showed
headers enabled, Values, A to Z, and no chosen column in the Sort by popup.

No sort was applied. The anonymous popup still needs a scoped selection route and
independent exact column/direction/outcome checks. Never use an unobserved index,
guessed label or an unchanged focus flag as evidence of a selected sort key.
This case does not qualify sorting, filtering or unattended row association.


## Read-only saved-sort acceptance gate (source only, October 6)

`examples/endly/microsoft-office/verify-excel-sort.py BEFORE AFTER
--baseline-sha256 RECORDED_ORIGINAL_SHA256` inspects the existing XLSX files
without writing them. Record the original hash before any GUI action. The checker
is deliberately limited to this regional fixture and Region A to Z in C3:G7:
East, North, South, West. It rejects an unchanged or already-sorted baseline.

For each region it requires C:G cell values, cached results and styles to move
together, with exactly the observed row-local `Drow-Erow` and `Frow/Drow`
formulas translated to the destination row. Header, totals, all outside-range
content and other sheet content must remain unchanged. Only worksheet views
and the previously documented custom number-format ID renumbering are normalized.
Every remaining package part, including chart caches, drawing relationships,
workbook metadata and shared strings, must remain byte-identical, and the
package inventory must remain identical. Excel may legitimately refresh those
parts on Save: rejection requires independent investigation, not widening an
allowance or treating a failed check as acceptance. This is not a general formula
translator, recalculation validator or arbitrary-workbook sort verifier.

Synthetic tests cover row association, stale formulas, caches, formatting,
headers/totals, other sheets, charts/relationships, inventory and baseline hashes.
Passing them does not qualify GUI sorting. Read-only inspection of the existing
sorting qualification copy still shows North, South, East, West, so the live
sort remains pending. The previous Excel Sort Tab uncertain effect was reconciled
confirmed; that navigation result supplies no evidence that sorting was applied.
The three unrelated Word uncertain effects remain barriers and must never replay.
