# Word report: create, format and save

Observed on Word 16.113.3, macOS 27.0, October 4, 2026. This case created a
separate disposable document, inserted a title and sales-summary paragraph,
applied Heading 1 to the title, and saved DOCX through Mechanize MCP and Endly.
Independent OOXML inspection confirmed exact paragraph text, Heading1 on the
title and normal body formatting. Local PDF export and saved-document close/reopen now have independent artifact
and live readback evidence for this case.

## Text entry and formatting

Use fresh process/birth/window identities and preserve existing documents.
Window keyboard operations require the actual top owned window. A visible Word
tooltip prevented a Return step; do not ignore it or pretend it is the document.
A verified switch to Excel and back to Word cleared that tooltip. The original
paused run then resumed its unexecuted Return without repeating the already
verified Heading 1 action. No unresolved effect was bypassed.

The page content exposed an AXTextArea named Page 1 content through AXDescription,
but reported AXEnabled false. Do not override that state to force a direct setter
or typed-window action. A GUI clipboard route worked for the owned new document:

1. Open the observed Find... menu command. The focused AXTextField supported
   whole-value fill, exact private comparison, and app-targeted Cmd+A/C.
2. Stage a bounded agent-authored title in that field and verify it before copy.
   Escape returned focus to the document. The menu Paste action inserted it, and
   private exact comparison verified the page text.
3. The observed Heading 1 ribbon gallery item was uniquely scoped to the current
   window and exposed a readable checked state. Verify false before selecting it
   and true afterwards. Return switched the new paragraph to Normal, also checked.
4. Stage the body with the same Find/copy route. After Escape, explicitly restore
   the intended document/caret. Select-all followed by ArrowRight placed the caret
   at the end in this case. Do not assume Find preserved the original selection.
   Paste and compare the full title plus LF paragraph separator plus body.

This is a narrow workaround that changes the system clipboard. It does not read
or export previous clipboard content. It is unsuitable where replacing a search
term, selection or document content would destroy required user state. The
initial long-text route remains a product qualification gap.

## Save and inspect

Use the observed Save As... command and inspect the actual dialog. Its name field
was saveAsNameTextField. Cmd+Shift+G on the fresh Save window opened PathTextField;
set and verify the intended directory, Return, then commit the exact filename.
Choose a destination that does not overwrite an existing file.

The saved fixture contained two paragraphs: Regional sales analysis as Heading1,
and the verified demonstration-data summary as normal text. Validate the DOCX
package independently, not merely its title bar or a successful Save receipt.
Retain a source hash before export and reopen checks.

## Print/PDF first-use boundary

The Print window exposed a PDF menu button and a separate PDF button. The menu
contained Save as PDF… with a Unicode ellipsis, not Save as PDF. Its menu was
aliased beneath two controls; scoping the item under the PDF menu button avoided
an ambiguous global match. These discoveries do not prove completed PDF export.

A macOS UserNotificationCenter prompt asking whether Word could discover local
network devices interrupted this first Print workflow. Word's own AX focused
root became unavailable and activation could not verify foreground ownership.
The PDF save dialog was visible behind the system prompt. Do not conclude that
all such failures mean a missing native adapter or a hung application, and do not
keep issuing input against the background document. Inspect the foreground
system dialog and ask the user to resolve the permission choice. Local PDF
export does not require discovery of network printers.

Save, export and reopen are separate checks. Preserve an interrupted print/save
operation and its unknown effects; inspect the current dialog after it is
unblocked instead of repeating Print or Save as PDF.


## Completed export and reopen check

After the user dismissed the local-network prompt, the existing PDF Save dialog
responded through its focused filename/path fields. The workflow resumed that
dialog instead of repeating Print. A new PDF was saved in the qualification
folder. It rendered as one legible page without clipping. Extracted text matched
the expected content after Unicode NFKC normalization of font ligatures and
whitespace normalization. The DOCX hash stayed unchanged.

The PDF-save operation's original focused-body postcondition did not verify;
its unknown record is preserved. Independent artifact evidence is separate from
that original receipt. Do not repeat a save merely to obtain a different receipt.

A complete window inventory proved the report absent after closing. The observed
Open Recent entry reopened it with a new physical window ID. Find followed by
Escape established the page's focused text root; private comparison verified the
complete expected two-paragraph content. DOCX hash and paragraph styles remained
unchanged. The close operation's original expected focus on another fixture did
not verify and remains recorded without rewriting its expected value.

The parameterized plan emitter is parser/type validated but has not yet been
executed end to end. These results qualify this report case, not all Word
editing, all templates or unattended recovery from every interruption.
