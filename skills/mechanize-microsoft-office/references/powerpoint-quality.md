# PowerPoint content, design and portability quality

Planning and acceptance guidance adapted from the bundled Presentations skill.
Read the [observed brief case](powerpoint-brief.md) before execution. Its current
chart retains an external workbook relationship; the October 6 strict embedded
check still fails. Quality advice does not resolve that limit or qualify a new
paste, chart-editing, menu-disclosure or layout operation.

## Audience and design

Identify the audience, purpose, requested slide count and source material. An
N-slide request means N total unless explicitly described as content slides plus
a cover. Preserve requested order and existing design during narrow edits. Follow
the supplied template when it is a design reference; a source deck used only for
facts or images need not dictate design. Do not add a cover to a one-slide request.

Give each slide a clear purpose. Use direct topic titles for explanations and
supported takeaway titles for findings. Preserve material caveats, units, dates,
comparisons and requested evidence; do not invent a recommendation or stronger
claim to make a slide sound decisive. Keep authoring/validation commentary out of
slides and speaker notes. Retain factual citations in the requested location,
with material audience disclosures visible where needed. Notes are not a place
to hide a limitation needed to interpret the slide.

Use the template's dimensions, fonts, hierarchy and spacing. Adjust content and
layout to fit before shrinking text. Inspect reading order, contrast, whitespace,
image crop and proportions at presentation size. Do not treat a particular theme,
font size, palette or ban on shapes as a universal rule. Preserve original logos
and supplied artwork where required.

## Editable evidence and charts

Keep requested editable text, tables, charts and diagrams native when a qualified
route can create and preserve them. A screenshot or PDF can show an object but
cannot demonstrate editability. Preserve requested rows, columns, labels, images
and data. If the GUI route cannot provide the required object, disclose the gap
before substituting a static image or changing the deliverable.

Check charts against source values: series/category order, dates, units, signs,
percentage scaling, labels, axis bounds and source ranges. Chart formatting may
not inherit the workbook's formatting. For a percentage axis, 0.31 normally means
31%; verify the displayed result. Reconcile numbers repeated in text, tables and
charts with the same underlying calculation. Rounded sums, ratios and mixed units
need deliberate checks; a simple arithmetic scan cannot prove all of them.

Distinguish these states before handoff:

| State | What it establishes | What still needs checking |
| --- | --- | --- |
| Chart image or cached preview | Visible appearance at capture time | No proof of data editability or refresh |
| Editable chart linked to an external workbook | Editing/refresh may depend on that file and access | Portability and relationship resolution |
| Chart with an embedded workbook | Data can be carried inside the deck | Valid relationships, category/value agreement, required formulas and target-app behavior |
| Embedded snapshot of literal values | Those values may be self-contained | Original workbook formulas, links and lineage are not preserved by a snapshot |

Do not equate an editable chart with a self-contained attachment. If the original
workbook, formulas or lineage are required, preserve and verify them; replacing
them with a value snapshot is a scope decision, not an automatic repair. Embedded
status alone is insufficient if references are broken or point to wrong cells.

The observed default paste produces an external relationship. The recorded Paste
Special Excel Chart Object attempt produced an unsavable object and must not be
replayed. Do not patch the PPTX package to claim a successful GUI embedding fix.
Qualify an observed GUI route on a disposable deck with save/reopen, chart-data and
relationship checks before claiming that limitation is resolved.

## Visual and native verification

Inspect each final slide at full size; a contact sheet helps check overall flow
but cannot establish text fit. Look for clipped/wrapped headings, overlap,
broken connectors, missing glyphs, placeholders, inconsistent footers and wrong
chart labels. For narrow edits compare changed slides with the originals and
scan the deck for unintended changes. Count all slides and verify required content.

Save, inspect delayed error dialogs, close and reopen using qualified case
procedures. Where authorized and supported, test representative object editing
or resizing in a copy and verify the saved result. Do not claim PowerPoint checks
from an independent renderer, or Google Slides portability from a PowerPoint-only
test. Report unavailable editability and cross-application tests precisely.
See [handoff quality](handoff-quality.md) before sharing or attaching the deck.
