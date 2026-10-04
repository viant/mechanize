# Mortgage rate brief in OpenOffice Writer and Calc

**Status: IN PROGRESS. The ODT/ODS originals and DOC/XLS copies are verified at the file level, and one-page Writer and Calc PDF artifacts have verified text/rendering. One named sheet is verified in a separate Calc copy. Calc `businessStatus` and some UI input effects remain unresolved; polished report formatting and Calc print layout are pending. The Calc PDF Options-menu dispatch and the Insert Sheet menu dispatch remain unknown. OpenOffice later crashed during an accessibility observation; recovery evidence does not establish app stability or clear recovery receipts.**

## Goal

Use Endly to orchestrate Mechanize UI automation that creates a concise mortgage-rate brief in OpenOffice Writer and a supporting comparison table in Calc. The brief compares Freddie Mac's latest weekly U.S. national averages released October 1, 2026, with the prior weekly release from September 24, 2026. Source figures and calculation intent live in `data.json`.

The survey released October 1 covers September 24–30. These are weekly survey averages, not daily rates, APRs, or a quote for a particular borrower.

The intended save folder is `/Users/awitas/Documents/Mechanize Examples/Mortgage Rates 2026-10-01`. The original `.odt` Writer brief and `.ods` Calc workbook remain alongside `.doc` and `.xls` interchange copies and a `.pdf` Writer export. Each file is verified separately; the output path must be resolved from the live dialog.

## Definition of done

- Endly workflows use Mechanize to create and save both native OpenOffice documents through the UI; no headless document generation.
- The Writer brief is under 180 words, identifies dates, rates, source, changes, spread, and survey limitations.
- The Calc table contains the source values and formulas described in `data.json`; displayed results agree with the source arithmetic.
- Each document is reopened or otherwise independently inspected through the UI, and its filename, format, contents, and actual path are verified.
- The workflows record meaningful checkpoints and stop safely on uncertainty. A prior step is inspected and reconciled before any action is replayed; a possibly completed save is checked before attempting another save.
- Endly execution and verification evidence is recorded here before this example is marked qualified.

The ODT MIME type and exact report paragraph were verified from the saved Writer file. The saved Calc ODS passed independent content verification, but its Mechanize `businessStatus` is still unverified. The DOC and XLS copies also passed separate read-only content checks. Writer PDF text and rendering were checked, but its GUI export effects remain unresolved. See `evidence.json` for distinctions between operation and artifact evidence.

## Existing Writer copy/edit qualification

One existing ODT was reopened through Mechanize+Endly, edited in its exact single focused `AXTextArea`, and saved as a separate ODT copy. The exact appended paragraph and its bold style were verified from `content.xml`; the original ODT hash remained unchanged. A read-only check is available with `python3 examples/endly/openoffice-mortgage/verify-existing-writer-edit.py`. This is a narrow artifact qualification for one paragraph. The Save As confirmation remains dispatched/unknown and `businessStatus` remains unverified; file proof does not resolve the operation receipt. It does not qualify general existing-file editing, multiple paragraphs, other document shapes, or polished layout. Run IDs, window identity, capture paths, and both checkpoint hashes are recorded in `evidence.json`.

## Calc A1 commit qualification

The initial F2 → `replaceText("Date")` → Tab attempt (`2d2fe9d8332c95a0cfa1e490f49072ec58c0120e0c93d28d981e74e75273f235`) verified the edit-control text and next-cell focus only. Its subsequent save (`c8bd013b76ab10b3eb271b0358a8aa0da7a17c05ec5217f255bd680bae0233b5`) produced a 7,444-byte ODS with SHA-256 `bca67935ca1b8bee8cda6c1e6962b245588faf602c4b0ad4ddcb00ec80902b42`; a fresh Mechanize capture showed all three sheets empty. This was not proof of a committed A1 value, and no cause is established.

A later narrow run inserted a leading Space in the edit control, removed it with Backspace, and pressed Return. On revisiting A1 with ArrowUp followed by F2, the exact value matcher verified `Date` (run `1ab7bab80fea348adb140bf3b7173770660b5392caa96064a93e42c605660454`). Return followed by Cmd+S saved the ODS (run `68583ba05cdf92cd88ed304f0152a887fabb0903d6d5b6c399ac09c85eb1d9d3`). Independent `content.xml` inspection confirmed cell A1 stores text `Date` with `office:value-type="string"`. This qualifies only that one A1 string and its saved representation. The earlier empty-save history remains in `evidence.json`.

## Full Calc table file verification

The corrected Calc run `648f59ef0ecddcc1023f4754e331cb239d90d60d338124e491468341cac7393d` completed 106 steps, and save run `96984bd1b1f4977e003c6c90bd5a76d867bd3e0cc7fc55c3cb33d813466270b9` completed. The saved ODS is 16,419 bytes with SHA-256 `dd5ddce6afaa9cf836d7356e67a7d4665137718c7893bea9d5d8c0808a47fbc6`. The read-only `verify-artifacts.py` check passed for the summary, headers, dates, rates, exact stored formulas, cached results, and source URL. Verified formula results are 61, 68, 25, 18, and 7 in cells D2, D3, B4, C4, and D4. This is file-content verification; the run's Mechanize `businessStatus` remains `unverified`. It does not verify visual sheet formatting or print layout.

## One named-sheet addition and crash/recovery record

In the separate `Mechanize Calc Qualification.xls` copy, one scoped Calc edit changed the verified sheet name `Sheet4` to `Automation Checkpoint`. Saved XLS inspection found exactly one added blank sheet, preserved all original values by sheet name and preserved Sheet1's five BIFF formulas. The original XLS hash remained `c31a1eb6703ac0e883c311bb5f05768f29f160bfd74fb58103d372ebbcda7e63`; the edited copy SHA-256 is `127a1fca045d1d2b67544237a59e3cbef7ef1f80cd28cce9839ca2c94baf4767`. The read-only `verify-calc-checkpoint.py` confirms these checks:

```sh
PYTHONPATH=/private/tmp/mechanize-xls-validation python3 examples/endly/openoffice-mortgage/verify-calc-checkpoint.py \
  '/Users/awitas/Documents/Mechanize Examples/Mortgage Rates 2026-10-01'
```

This is a narrow saved-artifact check; the initial Insert > Sheet menu receipt has no postcondition and remains dispatched/unknown. Later literal and file evidence do not resolve it.

OpenOffice exited after a focused-element observation with `SIGSEGV EXC_BAD_ACCESS` at `0x20`. The observed stack included `CopyAttributeValue`, `_AXXMIGCopyAttributeValue`, and `autoreleasePool`; the causal accessibility attribute is unproven. A later restart listed three documents as successfully recovered, but Start Recovery and Next action receipts remain dispatched/unknown. Recovery does not clear those receipts or establish app stability. The read-only Writer artifact verifier continued to pass for both the original ODT and its separate edited copy after recovery. See `evidence.json` for exact report, PID, run IDs and unchanged hashes.

## Hybrid frame-based sheet selection stage

`hybrid-sheet-select.yaml` is a one-click stage for a sheet tab that has already been inspected in a fresh capture. It does not capture automatically, open/activate a document, save, or change cell data. It is not live-qualified; do not run unless the current Mechanize catalog exposes `native:windowFrameClick` and `mechanize_capture_window_frame`.

First select the exact Calc document/window and inspect its current title, process birth, and physical window ID. Using the existing owned session and grant, call the capture producer for that exact target and purpose. Inspect the returned image and metadata; use only integer pixels measured in the original returned PNG (including its `widthPixels`/`heightPixels`), never resized-preview or screen coordinates. The stage inputs must use that same `sessionId`, `grantId`, exact `purpose`, `officePid`, `officeBirth`, `windowTitle`, and returned `captureRef`. Set `sheetName` to the actual sheet name; the stage targets its displayed `Sheet <name>` tab.

Run the stage promptly: the capture reference is a one-use, 30-second click permit, not a permission grant. Do not switch documents, type, save, or perform another native mutation between capture and click; that invalidates the permit. If it expires, capture and inspect a fresh frame using the still-valid grant; do not ask for a new grant when the existing one covers the exact target and purpose. The wrapper has no default `x` or `y`; Endly rejects coordinates unless they are canonical nonnegative integer strings/numbers within the bounded frame-pixel range. Its preview prints a fixed summary rather than permit/point fields, but use only public dummy values for any preview invocation because diagnostic logs may record init inputs; never preview a live `captureRef` or credential resource. Its `AXTable` enabled postcondition confirms the named control in the exact window after the click; it does not prove a saved change or business completion. If the click outcome is unknown, inspect/reconcile that exact operation and current sheet before replaying or obtaining another capture.

## DOC and XLS interchange copies

Mechanize/Endly saved `Mortgage Rates 2026-10-01.doc` (10,752 bytes, SHA-256 `876733115c0e9c667ae5360c14c4aa46d329100914c5d11eb21c5f961befb823`) and `Mortgage Rates 2026-10-01.xls` (7,168 bytes, SHA-256 `c31a1eb6703ac0e883c311bb5f05768f29f160bfd74fb58103d372ebbcda7e63`) in the output folder, preserving the ODT and ODS originals. The live Save list exposed `Microsoft Word 97/2000/XP (.doc)` and `Microsoft Excel 97/2000/XP (.xls)`; it did not expose `.docx` or `.xlsx`.

The observed Save route used a fresh window-root snapshot after the full-app tree hit its 1,000-node truncation. `Cmd+Shift+S` opened the window-scoped Save dialog. The unnamed `AXPopUpButton` was targeted exactly with `office.window(title: "Save").getByRole("AXPopUpButton", name: "", exact: true)`, then the actual format entry was selected from the observed menu. The filename field was addressed with `exact: true`; `Cmd+Shift+G` opened the observed `PathTextField` for the existing folder. After filling the path and filename, the observed `Keep Current Format` control was focused and Space was sent. Treat this as a version-specific observation, not a reusable selector or proof for every input step.

`verify-legacy.py` independently extracted the DOC text with macOS `textutil` and confirmed the full report. It checked the XLS BIFF8 structure, headers, dates, rates, source notes, stored BIFF formula records, and cached values. Some UI input steps had no declared postcondition and remain unresolved; these file checks do not resolve their effect-ledger state or establish Calc `businessStatus`.

The legacy file verifier needs `xlrd==2.0.2` and `olefile==0.47` from `requirements-legacy.txt`. To keep these dependencies isolated, run:

```sh
python3 -m venv /tmp/mechanize-legacy-verify
/tmp/mechanize-legacy-verify/bin/python -m pip install -r examples/endly/openoffice-mortgage/requirements-legacy.txt
/tmp/mechanize-legacy-verify/bin/python examples/endly/openoffice-mortgage/verify-legacy.py \
  '/Users/awitas/Documents/Mechanize Examples/Mortgage Rates 2026-10-01'
```

## Open Save As dialog

`open-save-as.yaml` opens Save As in one exact, freshly discovered OpenOffice
window and verifies that the focused identifier is `saveAsNameTextField`. It
requires an existing owned `sessionId`; it does not open a session, choose a
format or path, or save the file. Supply `endpoint`, `credentialResource`, a
unique `requestId`, and the current paired `officePid`/`officeBirth` and
`windowId`. The plan receives those values as parameters and serializes the
runtime PID and window ID as numbers; no fixture identities are embedded.

Print and locally compile the prepared typed source without MCP or UI actions:

```sh
endly-mcp-runner -r=examples/endly/openoffice-mortgage/open-save-as.yaml -t=preview \
  endpoint=http://127.0.0.1:4987/mcp credentialResource=preview-only \
  sessionId=preview-session requestId=preview-only \
  officePid=123 officeBirth=100:1 windowId=456
```

The preview confirms source preparation only. Opening Save As does not stage or
complete a DOC/XLS conversion; choose and verify the requested format and
destination in a separately qualified workflow.

## Writer compose stage

`writer-compose.yaml` prepares a reusable stage for a **new, empty Writer document**. It uses the verified focused-textbox `replaceText` route, checks that the exact text element is empty before the mutation, and verifies the literal summary afterward. It does not save or export a file. The public summary default matches `writer_summary` in `data.json` and remains under 180 words.

Print the prepared typed request locally without calling MCP:

```sh
endly-mcp-runner -r=examples/endly/openoffice-mortgage/writer-compose.yaml -t=preview \
  endpoint=http://127.0.0.1:4987/mcp credentialResource=preview-only \
  requestId=preview-only officePid=123 officeBirth=100:1
```

To run the `session`, `stage`, `wait`, and `report` tasks, provide the real endpoint, credential resource, unique request ID, and PID/start-token pair from fresh OpenOffice discovery. A session ID is optional; when omitted, the workflow opens one. Run the staged edit only after creating a new empty Writer document and verifying its current process and focus. The preview is not live workflow or save qualification.

## Checkpoint and recovery principles

Capture and verify the active application, document identity, and relevant visible state before each dependent UI action. Checkpoint after document creation, content entry, formula entry, and save. Preserve the original operation identity and inspect its status or the UI after interruption. Do not replay a click, typing sequence, or save when its outcome is uncertain; first reconcile whether the intended effect already occurred. If recovery cannot establish the state, stop and report the uncertainty rather than risk duplicate or conflicting content.

## Reusable Calc stage

`calc-compose.yaml` accepts a fresh `officePid`, `officeBirth`, `windowId`, MCP
`endpoint`, credential resource and unique `requestId`; `sessionId` is optional.
Its prerequisite is an already-saved Calc workbook with only A1=`Date` committed
and independently verified, with selection at A2. Do not run it against the
completed example or another populated document. It composes the remaining cells
and saves once after the entry operation succeeds. It does not create the workbook
or establish its Save As destination.

```sh
endly-mcp-runner -r=examples/endly/openoffice-mortgage/calc-compose.yaml -t=preview \
  endpoint=http://127.0.0.1:4987/mcp credentialResource=preview-only \
  requestId=preview-only officePid=123 officeBirth=100:1 windowId=456
```

The local preview and typed compiler validate 106 composition steps and two save
steps. No live replay of this parameterized wrapper has been qualified. YAML
anchors share repeated predicate metadata; they were verified through Endly's
actual loader. No SSH or shell execution is part of the workflow. After a live
save, run the read-only verification explicitly:

```sh
python3 examples/endly/openoffice-mortgage/verify-artifacts.py \
  '/Users/awitas/Documents/Mechanize Examples/Mortgage Rates 2026-10-01'
```

A successful save operation does not imply that this independent check passed.
The verifier checks both Writer and Calc, so the verified Writer artifact must
also exist at the supplied destination.

## Writer PDF evidence

OpenOffice exported `Mortgage Rates 2026-10-01.pdf`. Independent inspection found
one page with the complete report and source URL; its rendered page has no
clipping. The layout remains a plain paragraph. The export workflow's assumed
return-to-editor focus check failed, and its unresolved effect is preserved.
This Writer artifact does not establish general PDF recovery or the Calc export route; the Calc PDF artifact is documented separately below.

## Calc PDF artifact evidence

The saved `Mechanize Calc Qualification.pdf` is a one-page PDF from a separate copy of the mortgage XLS workbook. Independent `pypdf` text extraction checked headers, dates, rates, spread, changes and source URL; a Poppler render was visually inspected as legible, unclipped and one page. The source XLS copy was independently checked against the original and has the same SHA-256. The PDF is 24,158 bytes with SHA-256 `de67b8ba453124d013b15d62a483021928285bfba1e4bccb82c74d6bba64ae7c`.

The initial Export Options menu action (`808736d43c7b953570abd188cd479ca46bf8fb4f93880dbfc4a89dccd1050639`) remains dispatched/unknown; later capture and artifact checks do not clear that receipt. The later filename staging/save steps and independent file checks establish this PDF artifact only. `businessStatus` remains unverified. This does not qualify the Calc PDF export route or general PDF support. Exact paths, file hashes, window/capture evidence and run IDs are recorded in `evidence.json`.

## Existing Writer paragraph edit stage

`writer-edit.yaml` requires an already-owned session, fresh OpenOffice PID/start
token, unique request ID, and explicit `oldText`/`newText`. Before running, inspect
the exact active editing copy and confirm that the focused AX text element is the
one intended single paragraph. The stage does not open, copy, save, or format a
document. It guards Writer kind, compares the entire old paragraph, performs one
`replaceText`, and verifies the entire replacement through a private literal
comparison. A mismatch stops the edit. The business key includes request and
process identity; reuse the original request identity for status/reconciliation
rather than creating another edit when dispatch is uncertain.

Endly preview and the running Mechanize typed validator passed for the two-step
stage using public placeholder text. This parameterized wrapper has not been
live-replayed; the underlying existing single-paragraph edit is the separately
recorded qualification case. Preview prints its inputs, so use public fixture text
for preview and never use credential values. Credential resource references are
passed separately through `credentialResource`.

```sh
endly-mcp-runner -r=examples/endly/openoffice-mortgage/writer-edit.yaml -t=preview \
  endpoint=http://127.0.0.1:4987/mcp credentialResource=preview-only \
  sessionId=preview-only requestId=preview-only officePid=123 officeBirth=100:1 \
  oldText='Public original paragraph.' newText='Public revised paragraph.'
```

Run the saved-artifact verifier separately after a qualified save. Validation or
an operation acknowledgment does not prove that the intended file was persisted.

Read-only checks for the new Calc artifacts are available as
`verify-calc-checkpoint.py` (using `xlrd` and `olefile`, the existing legacy
requirements) and `verify-calc-pdf.py` (using `pypdf`, available in the bundled
workspace Python). Both take the output directory. They check the exact qualified
fixtures and retain `businessStatus: unverified`; they do not clear unknown UI
receipts. The PDF verifier checks the pinned bytes of the visually reviewed
artifact rather than inferring layout from text extraction.
