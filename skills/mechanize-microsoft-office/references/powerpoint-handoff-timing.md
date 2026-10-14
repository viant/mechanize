# PowerPoint market-trends handoff and timing

Observed October 14, 2026 through the signed Mechanize MCP broker, Endly and native GUI. This is a guided four-slide text deck case, not unattended arbitrary-deck qualification.

## Verified outcome

PowerPoint created an editable title slide and three title/content slides, applied the built-in Ion theme, and saved a 709,568-byte PPTX. Read-only package inspection confirmed all four slides, expected text, and no external relationships. The deck was closed, complete empty window discovery confirmed closure, and File > Open Recent reopened it. Every final slide was visually checked; the saved hash remained unchanged. Finder file-object copy and Outlook Edit > Paste attached the PPTX. The explicitly authorized message was sent once and independently observed in Sent with the PowerPoint attachment. Sent establishes submission, not recipient inbox delivery.

## Current observed procedure

1. Inspect first-launch setup and template gallery. In this case Start Using PowerPoint advanced to the gallery; Blank Presentation was already selected. Create returned AX error -25204 but produced one deck. Preserve that receipt and observe; do not repeat Create.
2. On the blank canvas, exact physical-window Tab and Return select and edit the title. Use Escape, Tab, Return to move from title text to subtitle/body. Cmd+Shift+N adds the next title/content slide; Tab, Return enters its title. Verify count and each slide's actual text visually.
3. The older PowerPoint Find clipboard recipe is blocked by the installed foreground-window checks: Find is a floating AXToolbar without a qualifying AXWindow. Do not repeat or force its setter. With Find active, the observed File > Close dismissed only Find; fresh discovery confirmed the deck remained. This is state-specific, not a universal close-panel recipe.
4. Use the Excel Search clipboard procedure from [market-trends handoff](market-trends-handoff.md), explicitly activating Excel first. Fill the known public text, privately compare it, focus, select/copy, and clear Search. Activate PowerPoint and paste into the visually verified placeholder. This does not edit workbook cells. One intermediate private predicate stopped; only its undispatched copy tail proceeded with the same original predicate after fresh observation. No failed fill was replayed.
5. Dismiss the observed first-use accessibility tip with its enabled Got it button and refresh window discovery before continuing. Do not assume every floating window is this tip.
6. Design > Ion applied to all slides. Design's AXPress returned -25204 although the tab changed; observe before continuing. Escape twice and Home/PageDown navigated final slides. From an unselected slide canvas, Tab twice, Return, Cmd+A selected the body text for one reviewed correction; screenshot selection before replacement.
7. Cmd+Shift+S opened Save. The filename was pasted through physical keys to the fresh Save window. Verify name, Documents destination and PowerPoint Presentation (.pptx) format before Return. Wait for the sheet to disappear and nonzero valid saved bytes; the dispatch response preceded persistence.
8. Compose Outlook through the verified recipient, subject and body clipboard steps. Activate Outlook before named-menu actions. When recipient completion opens Contacts, switch to Excel to stage the next text, return to Outlook, and verify Contacts is gone before using main-window Tab to commit the address. Verify recipient token, exact subject privately, full body, and attachment card before sending.
9. Finder Go to Folder with the exact PPTX path selected the file. Screenshot verified the file/type/size; Finder Cmd+C then Outlook Edit > Paste attached it. Wait for the upload indicator to disappear. Send returned -25204, but Sent independently confirmed the message and attachment; no Send retry was made.

## Measured baseline and optimization

Measured wall time, including agent planning, tool transport, observation, first-run setup and recovery: **18 min 44 sec**. Timing started at 12:03:16 PDT and ended after the opened Sent item was verified at 12:22:00 PDT. This excludes earlier context preparation and the later guide update.

| Phase | Wall time |
| --- | ---: |
| Setup, creation, design and correction, through Save As | 11 min 14 sec |
| Save, inspect, close/reopen and final review | 2 min 24 sec |
| Compose, attach, send and verify in Sent | 5 min 06 sec |

Twelve successful measured clipboard transfers had a median of **7.50 sec**, range **6.97–7.58 sec**, excluding the separate app activation. Two uninterrupted new-slide/title/body sequences took **24.9 and 25.4 sec** from first command to paste completion; screenshots and agent review add overhead. These samples are not an end-to-end repeat-run benchmark.

Priorities for optimization:

- Skip the known-blocked Find staging route on this runtime; use the verified clipboard route directly.
- Activate the intended app before semantic menu actions, and check fresh popup/window state before physical keys.
- Batch already-qualified navigation and copy steps, stopping at slide, save and send verification boundaries.
- Emit compact observations (focused controls, relevant names, truncation and errors) while retaining full evidence privately; avoid repeated full app dumps.
- Investigate qualified floating AXToolbar ownership/focus support and intermittent predicate timing in the runtime. Do not weaken identity, foreground, unknown-effect or content checks as a speed fix.
- Benchmark a second run after first-launch prompts are gone before claiming a speedup. Keep planning/recovery overhead separate from actual tool execution latency.

## Repeat benchmark after the task/subtask update

A second four-slide deck was created through Mechanize on October 14 with PowerPoint and Excel already open. The same final text and Ion theme were used. Each slide grouped observed navigation and two verified clipboard transfers into one Endly operation, followed by visual review. Exact window scopes distinguished the new deck from the original open deck.

Measured from fresh session/app discovery at 12:44:42 PDT through final reopened-slide inspection and hash verification at 12:49:46 PDT: **303.49 seconds (5m03s)**. The previous deck-only phase was **817.81 seconds (13m38s)**, a **62.9% lower elapsed time** in this repeat case. The comparison includes agent/tool overhead within each timed interval. It is not a controlled attribution to the skill: content was prepared, first-launch prompts were gone, and the repeat needed no content correction. Helper preparation before session discovery, documentation afterward, and email were excluded. Do not compare 5m03s directly with the original 18m44s including email.

The four complete slide operations took **22.70, 24.06, 24.09 and 23.62 seconds** (median **23.84 seconds**). All measured Endly operations totaled **116.38 seconds**, including the stopped Design action; observations, captures and agent review account for additional time and were not individually timed. One known Design AX error was preserved and the actual changed tab was observed without retry. An initial wrapper expected Presentation1; discovery showed Presentation2, and the wrapper used that observed title before input. Discover new windows by before/after inventory and observed identity rather than assuming document numbering.

The saved PPTX contained four slides with exact matching text, no external relationships, and 709,568 bytes. Close/reopen and all four final slide views passed; the hash was unchanged after reopening. No email was sent during this benchmark.

Use a monotonic clock within a single timing process. If the tool environment uses separate clock origins across subprocesses, do not subtract their monotonic values: use the recorded wall timestamps for the overall interval and disclose this boundary. This run's per-operation timings used a single-process monotonic clock; overall elapsed time used wall timestamps across subprocesses.

### Where to investigate additional overhead

Timestamp differences between measured operations were 31.29 seconds from Design return to theme/Save As, 26.63 seconds from slide 3 completion to slide 4 start, 23.76 seconds from theme/Save As return to filename entry, and 22.20 seconds from new-presentation return to slide 1 start. These intervals contain observation, capture, review and orchestration, not just idle delay. Their components were not separately timed. The [repeat-run transition guidance](efficient-execution.md#repeat-run-refinements-from-the-last-session) targets these boundaries while retaining required checks. No further speedup is claimed from this guidance-only change.
