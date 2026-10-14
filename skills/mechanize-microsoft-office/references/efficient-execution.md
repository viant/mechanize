# Efficient Office execution

Use this for repeat tasks on a matching runtime. The October 14 PowerPoint run was an exploratory first-run baseline: 18m44s included planning, UI discovery, recovery, review and email. It does not measure routine repeat performance. Two uninterrupted slide-entry sequences took about 25 seconds each, excluding review. A later repeat deck-only run took 5m03s; see the [benchmark scope and comparison](powerpoint-handoff-timing.md#repeat-benchmark-after-the-tasksubtask-update). A 3–5 minute create-and-email goal remains untested.

## Select the current route

| Task | Preferred observed route | Avoid rediscovering on the same runtime |
| --- | --- | --- |
| PowerPoint title/body text | Excel Search stages known public text; verified GUI copy; PowerPoint placeholder paste | Floating PowerPoint Find field rejected by AXWindow foreground checks |
| Word report or Excel table | Current [market-trends handoff](market-trends-handoff.md) | Per-character typing when the verified bulk route fits |
| Outlook recipient, subject and body | GUI clipboard paste into the verified owned draft field | AX-only subject fill, which did not commit the send model |
| Local XLSX, DOCX or PPTX attachment | Exact-path Finder selection; copy file object; Outlook Edit > Paste | Repeating the blocked attachment popup or no-op Browse action |

These preferences apply to the recorded case and runtime, not every app version. Discover fresh PID/birth, windows and controls. Identify a new document from before/after window inventory; do not assume names such as Presentation1. Keep runtime identities, mailbox addresses, filenames and recipient choices out of reusable defaults. An existing Excel staging field must be owned and its prior state preservable; if unavailable, treat a new route as discovery instead of assuming support.

## Task and subtask contract

Turn the user's request into one concrete task, then use the applicable subtasks below. These are logical work units within the current task, not instructions to create new chats or parallel desktop agents. One controller owns native UI input. Independent content preparation or read-only file inspection may be parallelized when authorized; dependent GUI steps remain sequential.

Example task: **Create a PowerPoint companion from the verified report, save it locally, and email it to the user-designated recipient.** Carry forward the user's recipient, content scope, app choice and existing send authorization; do not substitute example addresses or silently add an email step.

| Subtask | Inputs and work | Completion evidence passed forward |
| --- | --- | --- |
| 1. Prepare | Requested scope, source report and existing facts; draft all slide text and choose an appropriate built-in layout/theme | Ordered content, units/sources, destination filename and required review criteria |
| 2. Establish app state | Read Mechanize desktop skill if not already read in this conversation, then Office skill and current task procedure; discover current runtime/app/window | Owned session, current process/birth/window identity, usable canvas or exact recovery need |
| 3. Create artifact | Prepared content and established canvas; use the current observed bulk text route, grouping proven navigation with each transfer | Verified slide count and per-slide content/layout; original operation IDs for stopped actions |
| 4. Save and verify | Created artifact and destination; save, inspect file, close/reopen and review final changed slides | Exact path, valid file, content/count, portability check and stable hash where applicable |
| 5. Prepare handoff | Verified artifact plus authorized recipient/subject/body; compose and attach through the current Outlook/Finder route | Recipient token, committed subject, full body and completed actual attachment |
| 6. Send and confirm | Reviewed message and explicit send authorization | One send attempt; exact Sent item and attachment, or clearly recorded uncertainty with no duplicate send |
| 7. Record result | Evidence and actual timings from the preceding subtasks | User-facing artifact/send status, phase durations and only new reusable findings for the skill |

Skip subtasks outside the request. For Word or Excel tasks, replace slide authoring/review with the corresponding document or workbook procedure; keep the same artifact-to-handoff dependency. Use the user's requested complexity rather than a fixed slide/page count.

For each applicable subtask, record its input, completion evidence, status and elapsed time in a compact task-local record. Start dependent work only after its prerequisite is verified. Preserve completed work after an interruption; resume at the first unfinished boundary instead of rediscovering the entire workflow. Record discovery/recovery as a separate subtask only when a mismatch actually occurs. A paused or uncertain action is not a completed subtask.

## Prepare once; run in bounded groups

Prepare the complete slide titles/bodies, source facts, units and filenames before UI editing. Reuse already-verified source content for a companion artifact unless the user requests updated data. Reuse session authorization; new capability discovery does not create new send authorization.

Use one session for the workflow. Retain its purpose, fresh app identities and current window IDs in a task-local helper instead of repeatedly rewriting ad hoc wrappers. Save requests/results with unique business keys and refuse accidental reuse. Do not persist credentials in those files.

Group already-observed navigation, text transfer and paste steps in one Endly run. Keep desktop mutations sequential. Check executionStatus; when running, poll that operation before dependent input. A script returning from its submission call is not completion. Do not use fixed long sleeps as readiness checks.

| Boundary | Necessary verification |
| --- | --- |
| Before a new input group | Exact app/window and intended focus/selection; refresh after app or popup changes |
| Before GUI copy | Private comparison of the known staged public text and focused field |
| After each slide | Slide count, text, selected placeholder and legible layout in a fresh capture |
| Before and after Save | Filename, destination and format; sheet closure and valid nonzero saved file |
| Final deck | Inspect changed final slides; check content/count; close/reopen once and verify persistence |
| Before Send | Recipient token, committed subject, complete body, actual attachment and upload completion |
| After Send | Inspect Sent for the exact message and attachment; never resend to obtain a cleaner receipt |

One full initial observation may establish the UI. Thereafter use exact window, named menu or focused-element scopes and emit only relevant roles/names/IDs, focus, enabled state, truncation and errors. Retain full evidence privately when needed. A compact display must not conceal an error or truncated source. Do not dump state evidenceJson or whole app trees into the conversation.

Capture only after a meaningful transition or for a required visual check. Display the image only if the current capture returned one; an old file is not fresh evidence. Inspect the completed result before running dependent commands. After applying a theme, review final layout once; avoid another full review without changes or unresolved concerns.

## Repeat-run refinements from the last session

The 303.49-second repeat contained 116.38 seconds of measured Endly operations and 187.11 seconds outside them. The remainder includes discovery, capture, review, file checks, transport and agent reasoning; it is not measured idle time. Prioritize the transitions below before trying to reduce the approximately 24-second slide-entry operation. These refinements have not received another performance benchmark.

| Transition | Next-run guidance |
| --- | --- |
| New document → first slide | Take a before/after window inventory. Bind the uniquely new owned window and its observed title, then verify its blank canvas. Do not guess Presentation1, select the first window, or overwrite the old deck's identity. If the difference is ambiguous, inspect it. |
| Completed slide → next slide | Return the operation's final status and fresh capture together. Inspect the capture, then use the already-prepared next slide content immediately. Keep one bounded Endly run per slide and one review boundary; do not rebuild wrappers or rediscover stable controls between slides. |
| Design → theme | Keep Design activation separate because it returned an uncertain AX result in both cases. After that result, make one exact-document observation for Design Tab Commands and the intended theme. If observed, continue with the separate theme operation; retain the original uncertainty and never reclick Design merely to obtain success. |
| Theme → Save | Once the theme is positively observed and uniquely scoped, the theme-selection, Escape and Save As sequence worked as one bounded run. Discover the actual Save window after it opens; the document window ID is not the Save window ID. |
| Save window → filename | Prepare the destination name before authoring. Return fresh Save window discovery and relevant focused-field state together. Transfer the filename using the recorded GUI route, then capture name, destination and format before committing Save. |
| Save → reopened review | After Save, check sheet closure and valid saved bytes within a bounded wait. Independently verify content, then close the owned deck. Confirm that specific deck disappeared, even if other documents remain. Reopen the exact recent item, bind its new window ID, and capture final slides sequentially for one final review. |

Prebuild content and command templates during preparation, but insert fresh discovered identities at execution boundaries. Keep a task-local record with `sessionId`, purpose, app process/birth pairs, document window/title, transient dialog window, completed subtask evidence, and any unresolved operation IDs. Clear transient dialog IDs when they disappear. A cached identifier is a convenience, not evidence that its window still exists.

Use the current runtime's supported wait duration to let a roughly 24-second slide operation complete in one tool call where possible. If a call yields a running cell/process, wait on that handle with a useful bounded interval instead of issuing repeated very short calls. This is waiting for the existing operation, not sleeping before action or resubmitting it. Preserve cancellation and progress updates; never block communication for more than 60 seconds. The timing wrapper must include completion polling and stop on non-success before dependent input.

For small observation/act/capture groups, return compact status plus the current image in the same tool result when the tool transport supports it. Inspect the image before the next input group. A capture filename alone does not prove that the current call produced an image. Do not automatically run all remaining slides after a capture without reviewing required content and selection boundaries.

Use exact document scopes for semantic controls when multiple Office windows are open. Two Design controls were present during the repeat; the current deck's title scope resolved them. Reuse verified scope within an unchanged subtask, and refresh it after close/reopen, a new popup or an ownership mismatch.

For the next benchmark, time observations, captures, file inspection, tool waits and review intervals separately. Also record preparation time, which was excluded from the repeat's 5m03s. This identifies removable overhead without calling required verification waste or attributing a warm-app/content-reuse gain entirely to the skill.

## Recovery without repeated discovery

Activate the intended app before semantic menu actions. For known first-use tips, inspect and dismiss the actual observed informational button. For Outlook Contacts completion, staging the next text in Excel and returning to Outlook cleared the popup in the recorded case; verify it is gone before main-window Tab.

After a refusal or uncertain result, record the original operation and inspect current state. Do not repeat the same unsupported action as a diagnostic. Use an applicable recorded recovery if fresh evidence establishes its prerequisites. Unknown effects block replay. Resume the original run when supported, preserving its predicates and verified progress; a separate continuation must contain only proven undispatched work. Do not change permissions or weaken checks to reduce latency.

If a new UI or runtime mismatch requires exploration, mark that interval separately and keep discoveries case-specific. Do not turn a normal delivery task into an open-ended runtime investigation when a qualified route already completes it.

## Timing and reporting

Record start/end wall-clock times for preparation, authoring, save/verification and email. Separately tag discovery/recovery intervals as they occur; do not invent a retrospective split. Log operation ID, final status and elapsed time through completion, including polling. A five-second submission timeout is not total execution latency. Use a monotonic clock for durations within the same timing process and wall time for readable timestamps. Across tool subprocesses, verify a shared monotonic origin before subtracting values; otherwise use wall timestamps and record that limitation.

Report total wall time alongside measured tool latency and observed recovery causes. State sample size for per-slide or per-copy timings. Do not add nested or overlapping timings together. A repeat benchmark should use a fresh owned artifact, comparable slide count and review gates. Email benchmarks require explicit send authorization; never send duplicates for measurement. Claim an improvement only after a comparable run demonstrates it.
