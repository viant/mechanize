# Excel, Word and Outlook handoff: October 14, 2026

Observed on Office 16.113.4/macOS 27.0 through Mechanize MCP and Endly. A new
workbook contained a four-indicator comparison, calculated difference formulas,
interpretation and dated public source URLs. A companion Word brief had thirteen
paragraphs and a Title-style heading. Independent read-only OOXML checks verified
the saved content, formula caches and document style. Both files were attached
to one authorized email and observed in the account's Sent folder. Recipient
inbox delivery was not checked. This is case evidence, not unattended reliability.

## Copy known public text through the GUI

Excel's observed Search field accepted the agent-authored tab/newline-delimited
table and longer report text. Exact `native.literalValueMatches` comparisons
checked the full staged value before GUI Select All and Copy. Clearing the Search
field restored its prior empty query. This changes the system clipboard; it does
not read or export previous clipboard contents. Use only an owned staging field
whose existing state can be preserved, with ordinary public text, never secrets.

Pasting the table into the verified blank A1 cell populated separate cells and
calculated formulas. Format → AutoFit Selection made the labels readable. Go To
selected a separately verified empty range for notes. After staging, Search could
retain focus: a fresh capture-bound click on the intended grid cell restored
document focus before Paste. Do not paste into an unverified focus target.

The same verified clipboard route populated a newly created Word document. Select
All then ArrowLeft placed the caret in its first paragraph; the freshly observed
Styles gallery's Title item formatted that paragraph. Inspect the result rather
than assuming a style action changed only the intended text.

## Save checks matter

Several Office AX actions returned error -25204 despite opening the requested
document, gallery or Save panel. Fresh observation established the next state;
those actions were not repeated. Exact physical-window keyboard input worked in
the native Save panels when direct field filling lacked an AX-window proof.

Word reported Saved to my Mac while the new DOCX was zero bytes. Another Save and
closing the owned document did not complete the file. With no other Word documents
open, a graceful Mechanize `app.quit` completed the bytes. Only then did independent
ZIP/XML inspection pass. This is a case-specific recovery, not a reason to quit
Word with other user work open or to assume every zero-byte save will recover.

## Finder file objects became Outlook attachments

The Outlook attachment popup was not qualified for capture-bound clicks in this
case, and a menu-bar Browse action did not produce a picker. Do not repeat either
route merely because an action receipt reports success.

Finder's Go to Folder sheet accepted the exact known workbook path through GUI
paste. A capture verified the full path and selected result before Return. The
resulting Documents window visibly selected the correct filename and file type.
GUI Copy copied that file object. After confirming the owned Outlook body had
focus, Edit → Paste created a real attachment card, with the expected name/type
and size. The document file was then uniquely selected in the observed Finder
list, copied and pasted the same way. Verify each attachment separately. Do not
generalize file-object paste to all formats; a text path, link or inline image
does not prove an attachment. Row counts and arrow-key offsets are not reusable
selectors: discover the current folder and selection every time.

## Send once, then inspect Sent

The recipient was pasted into the focused To field and committed with Tab. The
subject was pasted through the GUI, avoiding the known AX-only subject-model
problem. The full subject passed a private literal comparison; screenshots
verified the recipient, complete body and both attachment cards. A denied value
or static-text read did not justify expanding policy.

Send returned an uncertain AX result. A system Focus-status-sharing prompt was
identified separately and its optional sharing was declined. No Send retry was
issued. Go to Folder selected the correct account's Sent folder, and the sent
message showed its full subject, body, recipient context and both attachment
cards. Preserve the original uncertain action receipt separately from this
independent business-outcome evidence.
