# PowerPoint sales brief: observed case

Observed October 4, 2026 on PowerPoint 16.113.3/macOS 27.0 through Mechanize MCP,
Endly and the signed native helper. Bundle ID is `com.microsoft.Powerpoint`.
The initial two-slide text case and later four-slide revision have guided
PPTX save, close/reopen and local PDF evidence. The four-slide revision includes
a transferred Excel chart with independently checked cached values. Its saved
external relationship prevents self-contained editable-chart qualification.
Unattended arbitrary presentations and general layout/pointer coverage remain open.

## Create and edit

1. Discover the current process/birth and welcome/template state. In this case
   the initial Office welcome screen advanced to the template gallery without
   agent input. The selected Blank Presentation's Create button opened a deck.
   Its AXPress returned an error despite creating the deck; the original window
   predicate reconciled before continuing. Do not click Create again.
2. The observed Outline View menu switched view. Slide Editor Pane and Outline
   Pane reported disabled AXLayoutArea with no editable text children. Do not
   waive that metadata or claim direct text input is supported.
3. On the blank title slide, an exact-window Tab selected the title placeholder;
   Return entered editing. Inspect a fresh capture before entering text.
4. Cmd+F opened an enabled focused AXTextField. Fill that field with known text,
   privately compare its exact value, then targeted Cmd+A/C copy it. Targeted
   Escape returned focus to the slide's AXScrollArea. Exact-window Cmd+V pasted
   into the selected placeholder. This changes the GUI clipboard and Find query.
5. Fresh captures verified text and placement. Escape, Tab and Return moved from
   title to subtitle. Cmd+Shift+N added a title-and-content slide, verified by the
   observed Slide 2 of 2 status. The same staging route filled its title/body.

A surviving document window proves neither selected placeholder nor pasted text.
This case used operator capture inspection after each paste and independent
read-only PPTX XML inspection after save. Do not publish a parameterized
unattended text plan until it can verify these content/selection boundaries.

## Save, reopen and export

Cmd+Shift+S opened Save. Fill `saveAsNameTextField` and verify with
`literalValueMatches`; ordinary value readback was not available in this case.
Use the fresh Save window's Cmd+Shift+G, observed PathTextField, and fresh path
window Return to choose the destination. Inspect format, filename and folder
before pressing the observed OKButton. Name-based document checks must be scoped
to the exact window: the same title also appears in menus.

The saved `Mechanize Sales Brief.pptx` contained exactly two slides and the four
expected text strings. Cmd+W followed by complete empty window discovery proved
closure. Open Recent's exact file item reopened a new physical window with both
slides visible, and the file hash remained unchanged.

The observed Export menu opened a PDF dialog. Its default electronic-distribution
option uses Microsoft's online service. This case selected the observed
**Best for printing** radio and verified `checked == true`. After verifying the
PDF filename and local destination visually, pressing OKButton exported two
pages. Read-only PDF extraction matched the slide text after Unicode/whitespace
normalization; Poppler renders were legible and unclipped.

## Recovery and limits

A first-run “Make your documents more accessible” tip created a separate top
window and blocked the next keyboard step before dispatch. The observed Got it
button dismissed that informational tip. Fresh window inventory confirmed it
was gone; the original paused run resumed successfully, with no duplicate slide
or paste. This is evidence for one bounded recovery case, not general recovery.

The first title's AXCell literal predicate, a raw filename value predicate and
an unscoped save-title predicate remain unknown at stopped durable boundaries.
Captures and artifact evidence are recorded separately; failed mutations were
not repeated and predicates were not rewritten to clear uncertainty.

Source now admits the original `literalValueMatches` predicate for native effect
reconciliation under the same process/root/window constraints. That broker
change is not installed or live-qualified yet; it does not make missing canvas
text accessible. Existing runtime reconciliation still rejects that predicate.

## Four-slide revision and Excel chart transfer

A later guided revision produced a coherent four-slide brief: takeaway, regional
findings, revenue chart, and next actions. The observed Ion theme was applied.
The source workbook contained one chart. In Excel, Go To > Special > Objects
selected it; NameBox read `Chart 1` and Chart Design appeared. A fresh copy,
PowerPoint activation, new slide and exact-window paste transferred the chart.
Saved PPTX inspection verified its cached categories North/South/East/West and
values 1200/1800/900/1500; the source workbook hash was unchanged.

Chart dimensions are editable through enabled, focusable AXIncrementor controls
named `Width:` and `Height:` on Format. Direct plaintext fill is not qualified
for those roles. The observed route stages a known numeric string in the focused
Find AXTextField, privately compares it, copies it, exits Find, explicitly focuses
the numeric control, verifies focused state, then uses targeted Cmd+A/Cmd+V and
Return. Saved OOXML geometry independently verified 8 by 4 inches. The observed
Align Center menu centered the chart on the slide.

The parameterized emitter at
`examples/endly/microsoft-office/plan-powerpoint-dimension.py` takes fresh
process/birth/window identity, title, stable caseId, control (`Width:` or
`Height:`) and a positive decimal value at most 56 in the displayed units. Both
emitted width=8 and height=4 plans ran successfully through live MCP/Endly. It
requires a chart context but does not prove the identity of a selected chart:
use an owned disposable deck containing one independently verified chart and
inspect selection before execution. Window/focus predicates do not prove the
new geometry. Save and independently inspect the PPTX; retain the original run
and caseId if stopped. The route changes the clipboard and Find query.

The revised deck was closed, an empty complete window inventory observed, then
reopened through Open Recent into a new physical window. Its saved hash stayed
unchanged. The linked chart caused a Grant File Access dialog for the exact
owned source workbook. Selecting that workbook through the scoped file picker
resolved the prompt, and the chart was visible after reopening. This is an app
file-access dependency, separate from Mechanize's desktop grant.

### Paste and save limitations

Default chart paste stores an external workbook relationship. This case is not
self-contained editable-chart qualification. A Paste Special attempt with the
observed Microsoft Excel Chart Object option produced an unsavable object:
PowerPoint later reported an issue with Object 4 on slide 3. The displayed
Remove and Continue recovery action removed that agent-created test object.
The chart was restored, resized with the emitted plans, saved and reopened.
Previous working files were retained. Do not repeat that OLE paste recipe.

A surviving document window and even a successful key-dispatch receipt did not
establish save success. Check for delayed application error dialogs, validate
the actual file, and reopen it before claiming persistence.

The ribbon Paste AXMenuButton advertises both AXPress and AXShowMenu. Its press
performed a default paste rather than disclosing options. Source now exposes a
separate native `.showMenu()` action, restricted to enabled AXMenuButton or
AXPopUpButton controls advertising AXShowMenu, with exact process identity,
consent, fence and helper capability checks. Tests/build pass. The updated development runtime is installed, but its initial
macOS Accessibility check reported permission absent; live qualification is pending. Older helpers fail closed; do not treat
`.click()` or a keyboard action as an automatic menu-disclosure substitute.


## October 6 read-only portability follow-up

The current saved `Mechanize Sales Brief.pptx` still fails
`verify-sales-brief.py --require-embedded` because external relationships remain.
This check confirms an existing limitation; it is not a new GUI execution case.
Before treating the deck as an independent editable email attachment, qualify
an observed GUI procedure that removes the dependency while preserving chart
values, save/reopen it, and rerun the strict verifier. Do not edit PPTX XML directly
as a substitute for that GUI proof or replay the earlier unknown paste effects.
