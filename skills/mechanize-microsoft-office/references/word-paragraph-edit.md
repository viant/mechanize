# Word: replace the final paragraph of a disposable copy

Observed October 5, 2026 through Mechanize MCP and Endly on Word 16.113.3,
macOS 27.0. One two-paragraph sales report copy was edited and saved. Independent
DOCX inspection confirmed the exact replacement text, unchanged paragraph count,
and preserved text/formatting XML for the neighboring Heading 1 paragraph.
The source DOCX SHA256 remained unchanged. A fresh Word capture showed the
heading and replacement paragraph legibly on one page. PDF export and reopen of
this edited copy have not yet been qualified.

## Scope and prerequisites

This is a final-paragraph operation for an owned, disposable, two-paragraph,
single-page document with complete fresh AXTextArea content. It is not an
arbitrary paragraph/range editor. Establish the actual document and focused
AXTextArea and compare the entire original page privately before input. Supply
fresh process birth and physical-window identity; reject changed focus, window,
content or incomplete observation. Preserve source hashes and unknown effects.

The parameterized `plan-word-paragraph-edit.py` emitter is MCP parser/type
validated. The earlier manually composed eleven-step plan was live-executed;
the parameterized emitter has not been independently executed end to end.

## Observed edit procedure

1. Verify the full original heading, LF separator and body.
2. Open Find with the qualified physical-window Cmd+F route. Fill its focused
   AXTextField with bounded public agent-authored replacement text, privately
   compare, select and copy it. Escape restores the document text root.
3. Verify the original page again. Cmd+A followed by ArrowRight restores the
   caret at the end. In Word for Mac, Cmd+Shift+ArrowUp selected the final
   paragraph in this case. Do not substitute generic macOS selection semantics.
4. Paste once into the same physical window. Privately compare the full heading
   plus replacement body before saving. Save once, then inspect the resulting
   DOCX independently. GUI readback alone does not prove a completed save.

Selection/copy intermediates verify content and focus, not clipboard contents
or exact selection extent. The final full-page comparison and independent
preservation checks provide the narrow outcome evidence. This procedure changes
Find text and the clipboard; it must never be used to stage credentials.

## Save As and interruption findings

An existing document's Save As panel appeared as an AXSheet, unlike the AXWindow
seen for a new document. A scoped field lookup encountered incomplete coverage;
fresh focused-root evidence identified saveAsNameTextField unambiguously. Do not
reuse a new-document panel predicate for an existing-document sheet.

The attempted Go To Folder acceptance routes did not establish acceptance and
retain their original uncertain receipts. A uniquely named Close control cleared
the path field instead of dismissing the panel. Qualified Escape eventually
cancelled the picker; an initial foreground rejection was resumed under the same
run, without input replay. The default save directory already matched the source
folder. Saving the separate copy used that observed directory.

Immediately after Save As, an attempted ZIP inspection found an incomplete file;
a later read found a valid DOCX without another Save. Window-title transition is
not an artifact-completion predicate. Unknown earlier folder-picker effects were
not cleared by cancellation or later file proof.

The edit operation reports execution succeeded and business status unverified.
Its durable snapshot remains paused with ten verified mutation records and no
unresolved effects; the initial read-only verification is not a mutation record.
Do not confuse this stored status with a user request to pause the overall goal.

## Stronger saved-file preservation evidence

The saved edit was rechecked from bounded package snapshots. The verifier now
requires identical part inventory, unchanged nonedited document structure and
section/page settings, and unchanged protected parts such as styles, relationships
and images. In settings and document properties it permits only named revision
IDs, timestamps and text/time statistics; other changes fail. Original and edited
hashes remained unchanged from the recorded GUI case. Synthetic negative fixtures
reject page-size changes, heading-style changes, image/style/settings changes,
missing/added parts, ambiguous part names and XML entity declarations. These
fixtures test the verifier, not Office automation or rendered-layout preservation.

## Retained edited-copy reopen uncertainty

A later menuBar-scoped Open Recent filename action was dispatched, but the edited
copy remained absent from a complete physical window inventory. Its original
window-scoped content predicate did not verify, and reconciliation rejected it
because it substituted the original menuBar root. The run was stopped at its
durable boundary; the unknown effect remains unchanged. No replay, alternate
open action, or caller-authored outcome was used. Reopen remains unqualified.

New source validation rejects native comparison outcomes that broaden or replace
an explicitly scoped mutation root. References receive the same check at durable
admission before an input intent. This is a narrow admission improvement, not
a new outcome adapter or authority to clear historical unknown effects.
