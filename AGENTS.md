# Public repository data boundary

Treat this repository, its Git history, and associated public review surfaces as public.

- Never commit nonpublic client or business information: source documents, commercial terms, budgets, audience definitions, internal workflows, contact details, case identifiers, internal file paths, screenshots, recordings, logs, or real-case benchmark artifacts. Never commit credentials or token contents.
- Use independently synthetic, business-neutral fixtures and examples in code, tests, documentation, skills, and benchmarks. Renaming a client alone does not make its data safe to publish.
- Keep business-specific rules and real execution evidence in the authorized private task workspace outside this repository. Do not use an untracked or ignored repository directory as the confidentiality boundary.
- Keep reusable automation generic. Public performance reports may describe generic operations and aggregate measurements without client context, proprietary figures, or private artifacts.
- Before every commit, inspect the staged file list and diff for confidential content. Stage intended paths explicitly. Apply the same review to commit messages, PR descriptions, issue text, and attachments before any public publication.

These restrictions do not require making an authorized internal business workflow generic; they require keeping its specific data and rules out of public Git.
