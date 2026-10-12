# Literal formula and formatting — October 4, 2026

Guide 0.3.0; Excel 16.113.3 on macOS 27.0. Exact observed case: a newly
created disposable workbook, Sheet1!A1, `=SUM(17,23)`, result `40`, Bold on,
saved as `Mechanize Formula Qualification.xlsx`. Saved OOXML independently
confirmed the formula, cached value and bold font. Reopening this particular
file is not yet qualified.

Use fresh process/birth/window identities, explicit desktop consent and the
session-text opt-in. The current host must enforce declared preconditions; older
builds accepted but did not evaluate them. Never use this guide to justify input
on an unchecked baseline. Do not infer the next workbook title from numbering:
Excel created Book3 when an earlier predicate expected Book2; that earlier
creation record remains unknown.

1. Observe the exact workbook, active cell and focused Content Area. Activate
   Excel immediately before each input sequence. An intervening user interaction
   can change the foreground application.
2. Require the exact workbook's enrolled `XLFormulaEditor` value to be empty.
3. Issue one `typeWindowText` action with literal `=SUM(17,23)`, exact captured
   window ID, focusRole `AXLayoutArea`, focusName `Content Area`, and an original
   exact-text postcondition/reconciliation predicate on `XLFormulaEditor`.
4. This test delivered its single chunk, then stopped `textFocusChanged` when
   Excel changed AX focus. Stop at the boundary and reconcile the original
   predicate. Never retype the formula or replay a remainder. Longer multi-chunk
   entry through this transition is not qualified.
5. After confirmed text evidence, Return commits the formula. The next-row
   editor read empty; ArrowUp restored the exact formula. Native window capture
   showed A1 = 40.
6. Bold was one exact window-scoped `checkbox` named `Bold`, with `checked=false`
   precondition and `checked=true` postcondition/reconcile predicate. AXPress
   returned -25204 but original-state reconciliation confirmed the change.
7. Save to a new nonexisting local path using the observed Save panel, filename
   field, Go to Folder panel and Return. Inspect the resulting XLSX separately.

This qualifies one formula and one formatting state with bounded recovery. It
is not evidence for arbitrary text, ranges, formulas, charts or business success.
Full operation IDs and preserved unknowns are recorded in
`examples/endly/microsoft-office/evidence.json` in the source repository.
