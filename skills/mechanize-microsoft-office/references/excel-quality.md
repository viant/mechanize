# Excel analysis and calculation quality

Planning and acceptance guidance adapted from the bundled Spreadsheets skill;
not a catalog of qualified Mechanize actions. Use the [text/save case](excel-text-save.md),
[formula case](excel-formula.md), [percentage case](excel-percentage.md),
[date case](excel-date.md), [sheet insertion case](excel-blank-sheet.md) and
[Save As case](excel-save-as-copy.md) for their exact execution limits. Sheet
rename and sorting remain unqualified; a staged sort dialog is not a sorted result.

## Plan from the question and source

Identify the requested measure, audience, source grain, period, units and required
output. Preserve raw source values and stable record IDs. Check duplicate keys,
missing records, numeric text, date interpretation, filters and hidden rows before
aggregating. A narrow edit preserves unrelated sheets, formulas, charts, controls,
styles and annotations. Do not redesign a workbook just because another layout is
simpler. Keep macro-enabled formats and native features when required; do not
silently save them into a format that loses them.

For new analysis, keep the main answer easy to find and the calculation traceable:
source/assumptions feed useful calculations, then summaries. These can be labeled
areas on one sheet; separate tabs only when they serve a real workflow. Keep one
authoritative editable assumption and link matching results rather than duplicating
business logic. Independent review checks should observe the model rather than
create circular dependencies. Keep actuals distinct from forecasts and captured
scenario snapshots distinct from live results. Do not add scenarios, dashboards,
cover sheets or audit tabs unless useful to the requested task.

## Values and formulas

- Store numbers and dates as values with display formats. Keep identifiers with
  leading zeros as text. A displayed percentage such as 31% normally represents
  0.31, not 31. Formatting alone does not validate the underlying value.
- Use the requested reporting date and fiscal/week convention; TODAY() changes
  with time and is unsuitable for a fixed reporting date. Check the GUI locale's
  input interpretation and formula separators. Do not assume invariant file
  format codes can be pasted unchanged into every localized dialog.
- Anchor only the part of a reference that should stay fixed: `C8`, `C$4`, `$A8`,
  `$B$3`. For a per-period rate use `=C8*C$3`; for a fixed rate use `=C8*$B$3`.
  Check first, middle and last copied formulas across and down. These examples
  explain semantics; they do not qualify bulk fill or new formula-entry routes.
- Use bounded aligned ranges. Sum detail once, excluding included subtotal rows.
  Calculate an overall rate from matching totals, not the average of percentages
  unless that weighting is intended. Preserve units, population and rounding.
- Choose exact/approximate lookup deliberately. A first match is not aggregation;
  check duplicate keys and blank matched values. A SUMIFS zero does not establish
  source coverage. Preserve valid zeros and distinguish missing/not-applicable
  results from numeric zero. Do not blanket-wrap errors with `IFERROR(...,0)`.
- Preserve rule boundaries and valid zero overrides. A blank override may mean
  use the base while zero means use zero. Missing required factors must not be
  silently ignored by aggregation functions. Keep unexpected errors visible.
- Filter dates at the source grain: with a real month-start date, an inclusive
  start and exclusive next-month boundary includes the last day's timestamps.
  A test for equality to month start only works for matching monthly keys.
- Preserve working template formulas and native features. Excel Tables,
  PivotTables and What-If Data Tables are different features. Formula familiarity
  or native Excel support does not establish a qualified GUI operation. Report
  unsupported requests before substituting a static result or a different feature.

## Recalculate and verify

Observe the applicable calculation state through an available qualified route.
Do not silently change application-wide calculation/iteration settings. An
error-free view, formula text, saved cached result or successful Save is not proof
that dependent results update. In a disposable copy, when authorized and supported,
change a representative input, verify affected outputs and charts, restore it,
then save and reopen. Keep temporary values out of the delivered workbook.

Select tests from the business logic: blank versus zero, absent/duplicate keys,
period boundaries, rule thresholds, rounding and overrides. For scenario work,
check the selector and a later-period driver, preserving actuals and exposing
missing inputs only in the affected case. A comparison must evaluate each case;
linking two columns to one active result is not a comparison. If iteration is
required, verify settings, convergence and save/reopen separately. If these actions
are not qualified, state that recalculation or iteration remains unverified.

Trace headline metrics to sources and independently reconcile key totals with
appropriate tolerances. Scan affected formulas/results for shifted references,
unintended cycles and errors such as #REF!, #DIV/0!, #VALUE!, #NAME?, #N/A, #NUM!,
#SPILL! and #CALC!, distinguishing intentional missing-data markers. A healthy
summary must not hide failed prerequisites. Preserve notes and overrides with
record IDs across any separately qualified sorting or refresh.

Inspect changed sheets and dependent charts at readable zoom with cells unselected:
look for ####, clipped values, illegible headers, broken charts, misleading axes,
wrong signs/units, missing labels and stale series ranges. For a new workbook,
review every sheet. For a narrow edit, compare the affected views with the source
and investigate unintended changes elsewhere without reformatting unrelated data.
Use [handoff checks](handoff-quality.md) for persistence and optional file QA.
