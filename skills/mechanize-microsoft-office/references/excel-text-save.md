# Excel text, save, export and reopen

Guide version 0.2.0; Excel 16.113.3 on macOS 27.0, October 4, 2026.
This case proves a four-character cell value through GUI execution and saved
artifacts. It does not qualify arbitrary numeric input, formulas, charts or
production reliability.

## Exact editor reads and keyboard input

The tested formula editor has identifier `XLFormulaEditor`, native role
`AXTextArea`. Its optional AXSubrole and ordinary AXValue may be absent. The
qualified helper supports a bounded complete AXStringForRange read after the
operator explicitly enrolls this identifier for value reading. Unknown/secure
classification, missing character count, truncated range, changed length and
oversized text fail closed. This capability does not make AXValue writable.

Use a separate blank workbook and prove its empty current editor value before
input. Each tested named-key action targeted the exact current physical window,
PID and process birth. The fixture entered `test`, verifying each prefix through
`native.valueEquals` against that workbook's formula editor. Return committed
A1; ArrowUp returned to A1 and the editor independently read `test`.

The closed keyboard codec supports named letters/chords, not general literal
text, digits or punctuation. Do not encode arbitrary text as an unsupported
chord or reinterpret an input error as absence. General text/formula entry needs
additional qualified routes.

## Save a new local file

Inspect the current exact-window inventory before any window-key call; modal
Save and Go To Folder windows have their own physical IDs. Do not reuse the
workbook's ID for a modal window.

1. Open Save As once. The tested `Cmd+Shift+S` window-key route reached the
   uniquely focused `saveAsNameTextField`; use this result check for future runs.
2. Fill the exact filename field with the new output basename. Plaintext literal
   fill returned the helper's exact replacement proof.
3. In the actual Save window, `Cmd+Shift+G` focused `PathTextField`. Fill the
   intended folder, then send Return to the actual Go To Folder window. The
   original postcondition confirmed focus returned to `saveAsNameTextField`.
4. Inspect the staged filename, folder and file type. Confirm the destination is
   new before saving; do not accept an overwrite as an incidental dialog.
5. The uniquely observed `OKButton` Save action produced the new workbook title.
   Independently inspect the XLSX package; a title or file existence alone is
   insufficient. The fixture had exactly `test` in Sheet1!A1.

On this macOS version the Save panel tree included a foreign-owned
`com.apple.appkit.xpc.openAndSavePanelService` splitter. Window-scoped observation
conservatively rejected that mixed-ownership subtree. Complete app observation
still identified app-owned filename and Save controls. Do not dispatch to a
foreign-owned element or relax the ownership check. An earlier window-scoped
Save As result check remains unresolved; later staged-dialog work did not rewrite
that original effect.

## Local PDF export

The observed format popup was `_NS:115` in this particular dialog, with
`AXPress`; re-observe IDs for another version or instance. The actual menu name
was `PDF `, including its trailing space. The dialog's final action remained
`Save`. Wrong expectations of `PDF` or `Export` caused retained unknown effects;
do not repeat those selections or rewrite the original expectations.

For a fresh case, match the observed exact format name and check the newly
present Workbook/Sheet controls, then inspect the staged PDF settings. Prefer
`Best for Printing` for this local fixture. The electronic-distribution option
explicitly uses a Microsoft online service. The tested local-mode selection was
verified visually; its focus-based ledger predicate remained unknown, so do not
call that selection durably confirmed.

After a fresh capture confirmed the filename, directory, PDF type, Workbook
scope and local printing mode, Return in the exact Save window exported once.
The UI result check initially timed out. A stopped boundary followed by the
original focus/result reconciliation later committed the export effect as
confirmed. No repeated Save was sent.

Independent verification found one Letter-size PDF page containing `test`,
rendered legibly without clipping. The XLSX hash was unchanged by PDF export.
This is one simple export case, not a layout or print-scaling matrix.

## Close and reopen

After confirming the XLSX on disk, the exact-window Cmd+W route closed the saved
workbook. A fresh complete window inventory showed only the other workbook.
The observed Excel recent-file menu entry reopened the exact qualification
workbook. A read of its enrolled `XLFormulaEditor` returned `test` again.

Keep unresolved earlier effects, UI confirmation, independent file checks and
server business status separate. The fixture has independent artifact evidence;
its server business status remains unverified because no authoritative business
outcome adapter is enrolled.
