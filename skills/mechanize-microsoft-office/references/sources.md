# Source provenance and adaptation boundaries

Guide 0.15.0, adapted October 6, 2026 from Codex bundled Office packages
26.909.12148. This update adds operational quality knowledge without adding live
GUI qualification. The [0.14.1 qualification inventory](qualification-status.md)
and all original case references retain their evidence and unresolved effects.

## Source-to-guidance map

| Source package and resources | Mechanize adaptation |
| --- | --- |
| spreadsheets: SKILL.md, structure/formulas/verification sections | [Excel quality](excel-quality.md): source grain, traceable calculations, typed data, anchoring, missing values, aggregation, scope preservation and native recalculation checks |
| documents: SKILL.md; template-distill.md; tasks/headings_numbering.md | [Word quality](word-quality.md): semantic styles, template structure, complete edit-slot coverage and visual pagination checks |
| documents: tasks/comments_manage.md; tasks/clean_tracked_changes.md | [Word quality](word-quality.md): review-state distinctions, anchor preservation and separate structural/visual evidence |
| presentations: SKILL.md; references/native_evidence.md; references/finalization.md | [PowerPoint quality](powerpoint-quality.md): audience and slide count, template fidelity, native objects, chart/workbook portability and slide-level QA |
| All three packages' verification and handoff guidance | [Handoff quality](handoff-quality.md): saved-file checks, separate native behavior claims and final attachment identity; Outlook authorization and uncertainty rules remain from local case evidence |

The source Spreadsheets skill explicitly excludes live Excel control. Its content
and calculation principles are adapted here, not its execution contract. These
references are self-contained and do not require the bundled packages at runtime.
Source files were inspected as reference material, not invoked as authoring skills.

## Deliberate exclusions

- Artifact Tool, python-docx, OOXML patching, build scripts, output-marker calls,
  cloud import routes and finalizers are not Mechanize GUI authoring paths.
  Their existence does not bypass consent, disabled controls or unknown effects.
- Python/OOXML/rendering may be optional independent saved-file QA only with user
  permission; they cannot repair output or count as GUI creation proof. Follow
  [the QA boundary](handoff-quality.md#independent-saved-file-qa).
- Source-specific visual defaults, fixed colors/font sizes, punctuation bans,
  universal table borders, scenario architecture and prescribed tab counts are
  not imported as mandatory design rules. User scope and templates take precedence.
- Artifact-tool feature limits are not Excel GUI capability limits. Conversely,
  native Office feature availability does not establish Mechanize qualification.
- No bundled instruction to automatically accept revisions, strip comments,
  materialize chart workbooks, add suggested follow-ups or change delivery formats
  expands the user's request. Native unsupported features remain explicitly open.

## Reproducible source identity

Source root at adaptation: `~/.codex/plugins/cache/openai-primary-runtime/`.
Each path below is relative to that root; SHA-256 pins the exact inspected source.
These are provenance identifiers, not required deployment paths or executable links.

| Source file | SHA-256 |
| --- | --- |
| `documents/26.909.12148/skills/documents/SKILL.md` | `db351f7db520a130f33227999e55d9cc61a95b93660e1506d9a9a9fe90c9f916` |
| `documents/26.909.12148/skills/documents/template-distill.md` | `f9b829cd868732d56c3218473a1afa234ceca4aa808fbe0f96a1ab5470d768a1` |
| `documents/26.909.12148/skills/documents/tasks/headings_numbering.md` | `2ab97eb4f50358e9839f7fa5a91632c2b7e673356a20104e588ef54c67b9ca0b` |
| `documents/26.909.12148/skills/documents/tasks/comments_manage.md` | `0d7481ea7dc02d30b2c449570404663ff3843988c4296238e91a732707965014` |
| `documents/26.909.12148/skills/documents/tasks/clean_tracked_changes.md` | `c6da6ee2286845978c3a42b37b6fcfeb0a81d47f73e849c9bb718290f7d13d39` |
| `spreadsheets/26.909.12148/skills/spreadsheets/SKILL.md` | `499172cadf77be41b6ec7d87981463aec0859e10aba9cc0b864143e42955474b` |
| `presentations/26.909.12148/skills/presentations/SKILL.md` | `e0d28835f8ada4ef5f41ab0425dd818d9c9ab9a66a8e47df2cee5add15cce32f` |
| `presentations/26.909.12148/skills/presentations/references/native_evidence.md` | `b200c212c97c8f933a1f16d6f9fb1e1fd91b6b77e42ff5301216a92ebe3c480d` |
| `presentations/26.909.12148/skills/presentations/references/finalization.md` | `24e1dfe83c9a0373b9139f818a93683ebdc21dfff06ec6e89557488bb637b243` |
