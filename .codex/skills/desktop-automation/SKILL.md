---
name: desktop-automation
description: "Operate websites and desktop apps with Computer Use first, using Mechanize for private credential entry or qualified Microsoft Office fallback. Use for UI automation, saved-file verification, and recovery across those executors."
---

# Desktop automation

Use Computer Use first for ordinary browser and native-app interaction. This skill controls executor selection and verification; separate domain skills own the business task. It does not turn a file-generation request into a GUI requirement. Keep examples synthetic and business-neutral; client data, workflow-specific rules and case evidence belong outside the Mechanize repository.

## Select the next operation

| Operation | Preferred route | Fallback trigger |
| --- | --- | --- |
| Public web navigation, forms and reads | Computer Use DOM when available | A verified capability gap or repeatable failure after a fresh observation |
| Ordinary desktop interaction | Computer Use native accessibility, then fresh screenshot | Qualified Mechanize operation that addresses the observed gap |
| Password or saved credential entry | Mechanize private credential flow | Human entry if no authorized private route exists |
| Excel, PowerPoint, Word or Outlook UI | Computer Use first | Mechanize when its current operation is qualified and is more reliable or measurably more efficient |
| Offline artifact creation requested by user | Relevant artifact skill | Do not label file-library authoring as GUI execution |

An explicit user choice of executor takes precedence. Prefer native app identity for desktop Office. Chrome extension readiness is relevant only to web operations, never a prerequisite for native Excel or PowerPoint.

## Work from current state

Define the requested end result and an observable completion check before input. Reuse the signed-in session and the user's designated app/tab. Read the Computer Use documentation returned on entry. Use fresh controls and exact target scopes; batch known deterministic actions only until a navigation, dialog or selection boundary requires observation.

Treat stale or failed observations separately from failed actions. If a click errors while opening a document, read state before clicking again. For editable controls, a setter return is not a committed value or selection. Verify focus and application state before dependent input.

Use [Office checks](references/office.md) for native files. Use [private credentials](references/credentials.md) only for authentication. Do not expose passwords, token contents or Vault records in prompts, screenshots, tool arguments or logs.

## Switch executors without duplicate effects

Keep one controller per affected app/tab. Before a handoff, confirm the original executor is terminal/quiescent and reconcile possibly dispatched input. Preserve operation IDs, intended effect, observed result and saved-file revision. Then obtain fresh state with the destination executor and perform only remaining work. Do not use a new executor or run to bypass a denied permission, active input guard, or unresolved durable effect.

For Mechanize, discover its current capabilities and retrieve its desktop skill, plus the relevant Office case when needed. Reuse existing permanent grants automatically; a missing grant ID is not a reason to prompt. Request consent only after `permissionRequired`, scoped to the failing operation. A user message saying “approved” does not replace the runtime grant. Never approve the agent's own consent requests.

Distinguish app grants, macOS permissions, browser connection, process identity and executor readiness. If the permission panel and operation disagree, inspect the actual helper launch route and signed identity before asking for another approval. Do not reset TCC, weaken trust or broaden grants as a diagnostic shortcut.

## Reliability and efficiency

Verify business outcomes and saved content, not just tool success. Poll the same live operation after a timeout; never replay an uncertain submit, save, export or credential submission. Keep unsuccessful attempts visible and resume at the first unfinished verified boundary.

When comparing Computer Use with Mechanize, use identical synthetic inputs, output requirements and review gates. Time preparation, operation completion, save/export, reopen, review and recovery. Report warm/cold setup and sample size. Formula correctness, editable native objects and fidelity are acceptance gates, not optional speed tradeoffs. A small cell or slide test does not establish full-document reliability. Keep task-specific benchmark contracts in their separate domain workspace.

At handoff, name the actual executor per stage and the remaining limitations. Say “verified for this operation and environment,” not “fully reliable” without matching end-to-end evidence. Preserve user-owned files and keep test copies separate.
