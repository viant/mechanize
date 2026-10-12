# Word structure, templates and review quality

Planning and acceptance guidance adapted from the bundled Documents skill.
[Report creation](word-report.md), [paragraph editing](word-paragraph-edit.md) and
[capture-bound focus](capture-bound-focus.md) qualify only their observed cases.
The guidance below does not qualify general styles, tables, fields, comments,
tracked changes, content controls or template operations through the GUI.

## Preserve structure and scope

Determine whether the request is a read-only review, narrow edit, new document,
template adaptation or revision workflow. Identify the reader and purpose; retain
qualifications, dates, units and source meaning. Review title and headings as an
outline before formatting. Do not import facts, authorship, commitments or stale
dates from a template merely because its visual structure is being reused.

For a controlling template, inspect its distinct page and section patterns,
orientation, margins, title block, heading hierarchy, numbering, tables,
headers/footers, page numbering, captions, fields and editable slots. Preserve
its style and required structure. Inspect body text, table cells, text boxes,
headers/footers and controls relevant to the edit; body paragraphs alone are not
a complete document inventory. If a required region is inaccessible, report that
gap rather than claiming full coverage or rebuilding the document around it.

## Styles and layout

Use semantic paragraph styles for their intended roles when a qualified route
exists. Bold large Normal text is not structurally a heading. Preserve the
established hierarchy and list numbering. Do not confuse a numbered paragraph,
a manually typed number and a linked multilevel heading. Changing a shared style
can affect the whole document; avoid doing so during a local text correction.
The existing fixture's Heading 1 title is case evidence, not a universal title rule.

Choose prose for explanations and tables for comparable records or attributes.
Preserve required rows and columns; size columns for their content and allow
wrapped text to remain visible. Inspect continuing table headers, captions,
heading-to-paragraph breaks, figure anchors, widows/orphans and section boundaries.
Use the template's typography and colors rather than imposing blanket black
headings, borders, spacing, page counts or decorative conventions.

Fields, page numbers, TOCs and cross-references can display cached text. Inspect
both their visible result and intended function when requested. Do not replace
fields with static strings or flatten equations merely to get a clean preview.
A supported field update and its verified result are separate from a save.

## Review state

Distinguish visible markup from stored review state. Hiding revisions does not
accept them; resolving a comment does not necessarily remove it. Preserve
comments, tracked changes, reviewer identity and unresolved decisions unless the
request authorizes their modification. A generic request to polish a document
is not permission to accept all revisions or strip reviewer comments.

When reviewing, keep comments tied to the intended text, including repeated
phrases and anchors outside the body. When edits are requested as tracked changes,
verify the intended review behavior rather than silently supplying plain edits.
Only use an observed, qualified GUI route; report unsupported review operations.
For an explicitly requested clean copy, confirm what acceptance/rejection and
comment removal mean for that task before acting if the disposition is ambiguous.

## Verification

Compare exact intended text and surrounding content after each bounded edit;
selection and caret focus need fresh proof. Then inspect pagination at readable
zoom: every page for new/broad changes, affected pages and downstream pagination
for narrow changes, plus a check for unintended structural changes. A text read
cannot detect overlap, missing glyphs, clipping, detached captions or header drift.
An image/PDF may hide comments or revision metadata, so visual appearance alone
cannot prove their presence, absence or anchor correctness.

Save and reopen through the qualified case route; verify the requested content,
styles and review state that can actually be observed. Optional read-only package
inspection and independent rendering follow [handoff quality](handoff-quality.md).
Do not use OOXML patching, comment-strip/accept scripts or file-authoring libraries
as a substitute for GUI editing or unsupported review operations.
