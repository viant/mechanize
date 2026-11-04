# PDF creation and export

Use Computer Use first for native authoring and PDF export; use Mechanize for a
qualified Office operation when the user selects it or current evidence supports
the fallback. The same acceptance checks apply to both. This guide does not
qualify a new application, export route, or document type by itself.

## Choose the creation route

- For a new PDF without a GUI requirement, use the available PDF or source-document
  artifact skill, including its rendering checks. Label this as file-library
  authoring, not Computer Use or Mechanize execution.
- For a requested native workflow, author and verify the editable source with
  the chosen UI executor before exporting. A correct export of an existing file
  does not prove that executor can create its source content.
- Preserve editable originals. PDF export does not replace a requested workbook,
  document or slide deck. Interactive forms require separate field-value and
  appearance checks; do not flatten them by default or claim form qualification
  from ordinary Office export tests.

## Before export

Record the exact source revision, output path, intended pages/sheets/slides and
required quality in the private task workspace. Verify the source is saved with
the intended values and layout; do not export an older saved revision after an
uncertain edit. Choose a fresh destination for qualification.

For Excel, inspect print areas, selected sheets versus entire workbook, paper size,
orientation, margins, scaling, repeated headings and page breaks. Fit-to-page can
make text unreadable; a smaller page count is not a quality improvement. For
PowerPoint, distinguish slides, notes and handouts, and include hidden slides only
when required. For Word, inspect pagination, tracked-change/markup output and
section-specific page settings when relevant.

## Execute with either controller

Computer Use: discover the actual export or print dialog after it opens. Resolve
fresh controls from current accessibility state; use a fresh screenshot when
necessary. A returned diff is not a complete tree. Read back the final destination,
format and page scope before confirming once.

Mechanize: retrieve the current desktop skill and relevant Office export case.
Use exact process/birth and dialog scope, with explicit typed effect identity for
mutations. Use an advertised focused-window scope or exact physical capture when
the parent document tree omits the dialog. A known nonsecret output filename may
use `native.literalValueMatches`; never widen value access after a denied read.
Follow [Office checks](office.md) for local-printing settings and predicate scope.

Prefer a local export when that is the intended destination. An online conversion
service is a different destination and must not be selected incidentally. Verify
the displayed choice rather than assuming a default or historic control ID.

After confirmation, wait for the original operation. A timeout, successful click,
closed dialog or existing PDF alone does not establish a completed export. Check
whether the expected new file was actually produced. Preserve uncertain receipts;
reconcile the original operation rather than re-exporting to obtain a passing
result. Hand off executors only at a verified boundary under the parent skill.

## Verify the saved PDF

Reopen and parse the actual output. Check page count and page dimensions against
the intended scope, required text and numbers, reading order where required, and
absence of unexpected blank or omitted pages. Confirm required fonts, images and
charts render correctly; text extraction alone cannot detect clipping or overlap.

For workbook PDFs, match a distinctive heading or required content from every
intended worksheet to the exported pages. An Entire Workbook or Workbook radio
selection and plausible page count do not prove coverage. Check rendered text
size after scaling: one-page-wide output can be technically complete but unreadable.
If Print-to-PDF and native Save As both fail the same content/layout gates, retain
both failures and diagnose source pagination or export scope before another run;
changing the executor alone is not evidence that the output will improve.

Render every page and inspect it at a legible scale. Check table edges, long labels,
footnotes, headers/footers, page breaks, glyphs and chart legends. Match calculations
to the verified source. For a paired comparison, render both outputs at identical
resolution using the same renderer. Use pixel comparison when identical rendering
is expected; otherwise report observed differences and assess them against the
same content and layout requirements. Binary hashes can differ because of PDF
metadata and do not by themselves establish a visual difference.

After any correction, re-export and review the resulting pages. Retain prior
attempts in the measurement history. Report a PDF as ready only when the final
saved output passes all required checks; flag missing checks explicitly.

## Measure and keep evidence private

Follow [time, tokens and quality](benchmark.md): freeze equivalent source content,
output settings and acceptance checks for both executors. Separate source creation
from export-only timing, while also reporting the requested end-to-end interval.
Include observation, completion polling, rendering, review and recovery. Record
actual executor per stage, runtime revision, sample count, first-attempt failures,
human interventions and authoritative token counters. Start a new cohort after
material fixes; do not present an earlier passing cohort as a retest of new code.

Public fixtures must be independently synthetic. Never copy actual source text,
commercial figures, internal URLs, document metadata, screenshots, PDFs, logs or
case-specific benchmark reports into the public repository, including ignored
folders. Renaming a real document does not sanitize its content. Keep real-case
evidence in the private workspace and inspect staged files and diffs before commit.
