# Writer, Word formats, and file workflows

These are discovery recipes. Blank Writer creation through the observed menu, one narrow single-paragraph Writer text replacement, and saving that case as ODT have live qualification. One exact existing ODT was also opened, edited in a single focused paragraph, and saved as a separate ODT copy; that artifact's text was independently checked. Its Save As confirmation remains dispatched/unknown, and `businessStatus` remains unverified. One DOC copy of the blank-document brief was independently checked at the file level. Other existing files, DOCX, other document shapes, and multi-paragraph replacement remain unqualified. Use current observed controls and validated typed actions, never literal selectors copied from another app or a guessed keyboard shortcut.

## Find and open

If the user asks to find a named document without supplying its path, start with available read-only discovery and the actual Finder/Open-dialog search route; do not require a path before looking. Ask for missing edit values while locating and inspecting the source, and pause dependent edits until those values are known.

Establish the exact requested file or narrow candidate set: user-supplied path, the current document, or observed recent documents. Match name, location and expected content; do not choose the first same-named file. For a path-opening task, discover the app's actual Open route and the resulting owned file chooser. Read [native file-dialog guidance](skill://mechanize-desktop/references/native-file-dialogs.md) before selecting a path-entry or acceptance route; its Chrome fixture does not qualify an OpenOffice chooser.

Checkpoint the previous document and any unsaved state before opening another file. Verify the opened document with fresh window identity and distinctive source content. An Open command acknowledgment or changed caption alone is insufficient. If a format/import dialog appears, inspect its options and choose the user's intended interpretation before continuing.

## Read and shape the edit

Read the selected document through available scoped semantic content, not an assumed editor identifier. In the known Writer fixture the focused editor had no identifier. Bound the read to the requested section when possible; a truncated tree does not establish full-document coverage. Use a fresh window image after the prescribed two resolution failures to understand the visible page.

For a report or letter, map the request to title, section order, body edits and expected layout. For a targeted correction, identify the exact original passage and preserve neighboring text. Record a pre-edit checkpoint and an exact desired result. Read-only file inspection, if available for the owned artifact, may complement GUI evidence; it does not prove a UI action was dispatched.

One text-replacement case is qualified on OpenOffice 4.1.16: a newly created Writer document with a single-paragraph focused `AXTextArea`. After checking the expected empty literal value under exact fresh process and control scope plus consent, a validated Mechanize/Endly `replaceText(publicLiteral)` action replaced that text element; byte-exact helper readback and an independent capture verified the full paragraph. One narrowly scoped existing-file edit is also recorded below. Discover current method schemas and capabilities first, and require fresh editor/process/window scope and consent. `replaceText` replaces the entire targeted text element, so confirm that element is exactly the intended edit scope. These cases do not qualify replacement in other existing documents, multi-paragraph content, or other document shapes. An earlier AXValue `.fill` attempt was dispatched with no effect observed and remains unresolved; that outcome is not relabeled by either replacement result. Do not rely on `.fill` for text replacement based on this evidence. Do not substitute bulk keyboard input or repeated typing. After one qualified dispatch, independently compare the intended content; do not expose protected text in logs or evidence claims.

## One existing ODT copy and edit case

On October 3, 2026, Mechanize and Endly opened the existing mortgage report at `/Users/awitas/Documents/Mechanize Examples/Mortgage Rates 2026-10-01/Mortgage Rates 2026-10-01.odt` through the observed Open panel. The exact window was `9919`; a fresh capture at `/private/tmp/mechanize-office-edit.png` showed the original report. An earlier Open run (`3ee60f9590cc0fd2a851ec52d9fc492321f8533dd95fc2c83e8c081566e3648f`) had an obsolete expected 648-character literal versus the observed 695-character value and remains unresolved. The later open/copy/edit sequence does not relabel that attempt.

The focused single `AXTextArea` was checked with pre/post `literalValueMatches`. One `replaceText` appended exactly: ` Automation check: this existing report was reopened, copied, and edited through Mechanize.` The edit run was `4651d804262f0c04c47c641c00782ab60045964404506c825d14ed152c045e1c`; `Cmd+S` saved the separate copy at `/Users/awitas/Documents/Mechanize Examples/Mortgage Rates 2026-10-01/Mechanize Writer Editing Qualification.odt`. Independent ZIP/XML inspection found the exact appended paragraph; the pre-format copy SHA-256 was `fe188a57f434e13047386f41827ef7a47c5424ced0edc2aee81dbf779f6c2d96`. The original remained at SHA-256 `0452592858b9e53224f1b60adb09be9bfeac4a22a913ce1257f2374fd488b9ab`.

The copied paragraph was then selected with `Cmd+A` in exact Writer window `9919` and formatted bold with `Cmd+B`. Text pre/postconditions passed for the selection and bold action; these comparisons establish unchanged text, not the formatting. Runs: select `ce4261d0c13b646b75c25e4699336ff30e8fdec286a3824be85bdb41b38cbdee`, bold `a1c10415939050a481a3cd520016b73beadb8d2e7a8137147179e376c9118147`, save `627d7a6b7260f111874b8d6be4a717946a61555c81cf6923f07ac68e5403fe24`. Independent saved `content.xml` inspection found the exact edited paragraph preserved with a generated text style whose font weight is bold (including Asian and complex-script weights). Final copy SHA-256: `156a162edfc54e972f10cee810e1c9e816fbd92e7af0f1d7ccb6ea2a18d8b30d`. This qualifies only bold formatting of that one paragraph in this copy; it does not qualify headings, tables, page layout, or general formatting.

The Save As copy confirmation run `573e804d2a9edb99f7acc2600807458ffa028cfd96896733595dbd807dadaae1` remains dispatched/unknown. File-level proof that the separate copy contains the expected text and bold paragraph style does not resolve that operation receipt or establish business success; the operation `businessStatus` is unverified. This record qualifies only this exact single-text-element edit, one-paragraph bold format, and separate ODT artifact. It does not qualify general opening/importing of existing documents, editing other documents, multi-paragraph replacement, broader layout, or Save As completion as an operation. Structured details are in `examples/endly/openoffice-mortgage/evidence.json`.

## Save and interchange

Choose the intended output path and format before dispatch. Writer's working format is ODT; requested Word interchange may be DOC or DOCX only if the actual Save As format list offers it. Do not silently change the requested format, extension, or destination. Discover any compatibility confirmation and preserve requested tables, styles and page layout; a successful export acknowledgment cannot establish fidelity.

One DOC-copy case was observed on OpenOffice 4.1.16. After selecting the observed Save As menu item, a window-scoped `Cmd+Shift+S` opened the native Save dialog. A fresh window-root observation avoided the full-app tree's 1,000-node truncation and exposed one unnamed `AXPopUpButton`; the observed locator was `office.window(title: "Save").getByRole("AXPopUpButton", name: "", exact: true)`. Focusing and opening it exposed the actual format menu. `Microsoft Word 97/2000/XP (.doc)` was selected from that live list; `.docx` was not offered in this observation.

The exact Save window was then scoped for `saveAsNameTextField` with `exact: true`. The route filled the literal filename, used `Cmd+Shift+G` to enter the existing output folder through the observed `PathTextField`, returned to the filename field, and confirmed the save. On the format confirmation, the observed `Keep Current Format` control was focused and Space was sent. These selectors are version-specific observations: rediscover the current window, popup, menu label, and field before use. Input steps without declared postconditions remain unresolved even when the saved artifact is later verified.

The one `.doc` copy was independently inspected with macOS `textutil`; the extracted text contained the complete expected summary. This establishes the saved DOC file's summary text, not the unresolved UI effects or a general Word interop guarantee. Preserve the ODT source when creating a requested copy, and do not claim DOCX support unless the live format list offers it.

Saving as ODT is qualified only for the newly created single-paragraph Writer case on OpenOffice 4.1.16. In that observed version, `AXPress` on **FileSaveAs** showed a Save panel but left app/panel accessibility unresponsive. A no-AX window-key `Escape` on the freshly observed modal recovered the UI; refresh transient foreground state before resuming because activation did not guarantee Writer was still foreground. The verified save then used documented `Cmd+S` from the focused Writer textbox to open a responsive native Save panel. The observed `saveAsNameTextField` was filled with the literal filename using `exact:true`; `Cmd+Shift+G` opened `PathTextField`, which was filled with the existing destination folder. Return restored `saveAsNameTextField`; a final Return saved. In the installed version's ID-based selectors, `exact:true` was required. Discover current capabilities and schemas, reobserve controls and dialogs, and validate the typed workflow before acting; do not reuse selectors or assume this route in other versions/apps.

For this case, body-literal readback and read-only ZIP inspection verified the saved ODT MIME type (`application/vnd.oasis.opendocument.text`) and exact summary paragraph. This evidence qualifies that one-paragraph ODT save only. It does not qualify saving other document shapes, opening/importing existing documents, DOC/DOCX interchange, or Calc/PDF workflows. A visible Save panel, filename entry, Return action, or file existence alone is not proof of a successful save.

Separate these checkpoints: edited document verified; Save As dialog staged with exact destination/format; save outcome verified; output reopened/read back. Existing-file replacement must fall within the user's authorized task. Do not resolve an ambiguous overwrite by guessing.

Verify persisted content and format through an available qualified artifact reader or a freshly reopened document, plus layout evidence where needed. A file's existence, caption change or enabled Save As menu does not prove correct saved content. If evidence is unavailable, preserve the unsaved document and report the exact unresolved save checkpoint.

## Observed document recovery

After an OpenOffice process exit, a later Mechanize launch showed Document
Recovery for the known mortgage ODT and ODS. A complete fresh observation identified
`Start Recovery >` as an enabled button with writable focus but no usable AXPress.
Focusing that exact button and verifying the focused-element name succeeded;
Space through the focused button initiated recovery. Fresh observation then showed
both documents as `Successfully recovered` and an enabled `Next >` button.
Focusing the exact Next button, verifying focus, then Space reopened both documents.
Independent saved-file verification confirmed their original hashes and contents.

Use this only as an observed recovery recipe: inspect the actual recovery list,
buttons and document identities first. Never discard recovery data or replay Start
Recovery based on an uncertain response. The two key actions retained unresolved
workflow effects because no original business postcondition was declared; later UI
and file evidence did not relabel those effects. Reuse an existing owned session
for follow-up inspection instead of opening one session per read/action.
