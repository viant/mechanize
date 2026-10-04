---
name: mechanize-openoffice
description: Use connected Mechanize MCP to find, open, read, edit, save, or export Apache OpenOffice Writer and Calc documents on macOS, including Word/Excel formats and PDF. Apply to work in the OpenOffice app; ordinary document generation without that app uses the relevant document skill.
---

# OpenOffice through Mechanize

Use Mechanize MCP with Endly orchestration. Discover live methods and capabilities, use an owned session with the task's exact purpose, and retain its authorization throughout the task. Follow [Mechanize desktop](skill://mechanize-desktop/SKILL.md) for consent, typed workflows, effect state, and reconciliation. Live discovery takes precedence over dated examples.

Start with the requested result: source document, desired edits, output format and destination. For a creative deliverable, turn the brief into concrete checks: headings and reading order for Writer; inputs, formulas and totals for Calc; page layout and legibility for PDF. Preserve existing content outside the requested edit.

## Choose the task reference

- Before selecting an app, resolving a control, or handling a failed read, read [discovery and evidence](references/discovery.md). For a broader app qualification pass, use [Mechanize app discovery](skill://mechanize-app-discovery/SKILL.md).
- For finding/opening documents, Writer, Word formats, editing, and saving, read [Writer and file workflows](references/writer-files.md).
- For Calc, Excel formats, and PDF export, read [Calc and PDF workflows](references/calc-pdf.md).

## Carry the task through verified checkpoints

Use fresh exact app/process and window scope, observed semantic controls, and one target per mutation. Validate the actual typed workflow against `mechanize_describe` before running it. Each durable mutation needs its own business key and an independently observable postcondition. A parsed action, AX success, operation completion, or enabled menu item alone does not prove the user's document was changed or saved.

Prefer scoped AX/semantic controls first. If the control/action is unavailable or unreliable, use an app shortcut only when observed or qualified for the exact OpenOffice version and context. For fixable scope/locator problems, make at most two bounded semantic-resolution attempts; known unsupported behavior skips repeated attempts. When those routes do not work, capture the fresh exact owned window and use a pointer action only if the live catalog advertises one bound to that capture and window. Never guess coordinates, reuse stale capture targets, or invent a keyboard/text tool. Reuse the current grant for actions it covers. Verify the business result separately: a screenshot proves visible layout only, not document text, formulas or saved bytes.

For an unknown mutation, inspect the exact run/effect and fresh state before any replay or alternate route. Reconcile the original immutable postcondition when supported. A later successful action cannot relabel an earlier unknown effect.

Current qualification is narrow: opening a blank Writer via the observed menu, replacing the text of one newly created Writer single-paragraph text element, and saving that case as ODT were verified through live-qualified Mechanize/Endly routes. One existing ODT was also opened through the Open panel, edited in a single focused `AXTextArea`, and saved as a separate ODT copy; the exact paragraph text and a bold style in the saved XML were independently checked. Only that text/artifact and one-paragraph bold-format case is qualified. Its Save As confirmation remains dispatched/unknown, and `businessStatus` remains unverified even though independent package inspection verified the copy's bytes. A DOC copy of the blank-document report and XLS copies of the Calc workbook were also independently checked at the file level. One separate Calc copy has a single named-sheet addition verified in saved BIFF content; its Insert > Sheet menu receipt remains unknown. The Calc run's `businessStatus` remains unverified, and file checks do not clear unresolved input effects or qualify general interchange. One Calc PDF artifact also has verified one-page text and rendering, but the initial Options-menu dispatch remains unknown and its output did not verify that operation receipt. The Writer PDF artifact likewise has verified text/rendering while its export effects remain unresolved. OpenOffice later crashed during a focused accessibility observation; subsequent recovery showed documents recovered, but the recovery receipts remain unknown and application stability is not qualified. These results do not qualify replacement in other existing Writer documents or multi-paragraph content, broad existing-file import, general formatting/layout, DOCX/XLSX, general Calc coverage, or general PDF export support. The references give discovery recipes, not portable executable commands; discover current schemas and capabilities first. Do not use CUA, osascript, UNO, or headless generation as proof that the Mechanize GUI workflow worked.

Finish with the saved artifact when verified, the checks performed, and any unresolved effect or missing qualification. Keep a partially completed document and its durable checkpoint identifiable; do not present it as a completed deliverable.
