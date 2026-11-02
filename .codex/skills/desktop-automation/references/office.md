# Native Office checks

Start on disposable copies when qualifying a new route. Existing file format, content, formulas, sheets/slides, charts and template design are the comparison contract. Reuse existing Office sign-in; application launch is not permission to overwrite another document.

Excel: inspect the selected cell/range, enter typed values/formulas, verify dependent recalculation with a temporary input change, restore the input, save locally, inspect the saved formula/cached result independently, and reopen. Preserve dates, percentages and leading-zero identifiers. Verify sort/filter behavior separately if requested. A source-cell formula string does not prove calculation.

Observed Computer Use case on Excel 16.114.3: bulk TSV paste into a verified blank A1 produced a 4-row, 2-column table. Setting NameBox via `setValue` did not establish navigation; explicitly clicking NameBox, selecting its text, typing B2, pressing Return, then observing `NameBox=B2` and the formula editor worked. A paste-size warning was cancelled before retrying on the verified single cell. Do not apply this as an unconditional workaround on other versions.

PowerPoint: use existing placeholders/objects, preserve chart data and embedded workbook relationships, inspect every affected slide, save and reopen, then export and inspect the PDF. Compare slide count, text, numeric consistency, image crops, native editability and layout. Do not replace editable charts with images or drop slides to meet a time target.

Word: preserve paragraph styles, pagination, comments/revisions and fields required by the task. Outlook: draft, attachment, send and Sent verification are different outcomes; no sending unless explicitly authorized.

For Mechanize fallback, retrieve `skill://mechanize-microsoft-office/SKILL.md` and only its relevant case. An offline QA reader must not silently repair or rewrite files claimed to be native-authored. Declare a hybrid route if local authoring is part of the work.
