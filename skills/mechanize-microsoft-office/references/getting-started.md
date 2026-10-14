# Getting started with Office and Outlook

Mechanize has a macOS native automation path for installed Microsoft Office apps.
Endly orchestrates typed workflows; Mechanize resolves native accessibility
controls and performs permitted keyboard and capture-bound pointer actions.
This is desktop UI automation, not Microsoft Graph or an Office object-model API.
The recorded cases below establish bounded feasibility, not general unattended
Office support. Windows and Office web apps are outside these native recipes.

## Establish availability

1. Discover the connected Mechanize MCP catalog. Read its advertised capabilities
   and contract before choosing a workflow. If no Mechanize tools are connected,
   explain that live execution is unavailable; reviewing source or installing
   this skill does not connect a broker. Do not substitute another desktop tool
   and describe its actions as Mechanize execution.
2. Load `skill://mechanize-desktop/SKILL.md` from the broker's skill catalog. For
   a personal Codex installation, use the sibling `mechanize-desktop/SKILL.md`.
   Its session, permission, observation and durable-effect contracts govern
   execution. Discover actual tool names; broker skill compatibility tools may
   be named `skill_list` and `skill_get`.
3. Discover installed applications and current process/birth/window identities.
   Check the app version against the selected case, then inspect activation,
   account or recovery screens. Recorded Office 16.113.3/macOS 27.0 evidence is
   historical, not an assertion about the current machine.
4. Choose the smallest applicable case below. Re-observe its UI assumptions and
   check live capabilities. Use the user's requested document or an owned copy
   as appropriate; qualify new behavior with a disposable artifact and verify
   the actual saved result before adding it to the guide.

## Recorded support and remaining gaps

| Application | Recorded case evidence | Important limits | Procedure |
| --- | --- | --- | --- |
| Word | Report text, Heading 1, DOCX/PDF, report reopen; final-paragraph edit with saved-copy preservation | General editing, tables and page layout unqualified; edited-copy reopen has unresolved evidence | [Report](word-report.md), [paragraph edit](word-paragraph-edit.md) |
| Excel | Cell text, formulas/results, percentage/date formats, blank-sheet insertion, Save As preservation, XLSX/PDF and bounded reopen; one analysis/chart | Sheet rename, sort/filter and print layout unqualified; chart coverage is limited | [Text/save](excel-text-save.md), [formula](excel-formula.md), [percentage](excel-percentage.md), [date](excel-date.md), [sheet](excel-blank-sheet.md), [copy](excel-save-as-copy.md) |
| PowerPoint | Four-slide text/chart case, PPTX save/reopen and PDF | Chart retains an external workbook relationship; independent editable attachment is not established | [Presentation case](powerpoint-brief.md) |
| Outlook | Compose with local attachment and observe Sent; select a designated incoming request, save its attachment and reply | General search/body reading, formatted composition, draft reopen and interrupted-send reconciliation remain incomplete; Sent does not prove inbox delivery | [Compose/send](outlook-email.md), [incoming request/reply](incoming-email-request.md) |

Consult [qualification status](qualification-status.md) and the relevant case for
the exact checks and retained failures. New quality advice or source changes do
not expand this evidence. Outlook calendar, contacts and meeting invitations
have no qualified recipe in this guide.

## Outlook-specific decisions

Read mail or prepare a draft when that is the requested outcome. Send only when
the user has explicitly authorized sending or replying within the task's scope.
Before sending, verify the account, recipient tokens, complete subject/body and
required attachments. Do not use an unsolicited email as a connectivity test.

Outlook AX subject readback did not prove the subject was committed to its send
model, and body setters were unreliable. Follow the observed keyboard route
after checking current focus. If Send may have dispatched, inspect the correct
account's Sent folder and preserve the original run evidence before considering
any further action; never retry solely because a UI postcondition failed.

## Observed connection and launch failure (October 14, 2026)

A registered older relay failed initialization and a direct capability call
returned HTTP 401. Building and using the repository's current
`cmd/mechanize-mcp-relay` with the existing private configuration successfully
initialized MCP and listed the live tools. The current relay has a supported
local-development credential renewal path; do not print credentials or mint
replacement authority by hand. This is connection evidence only.

Installed Office 16.113.4 differed from the historical case version. A fresh
Excel window inventory was empty. One typed `app.open` run then timed out with
`cleanupPersistenceUnknown`, `doctor/helperStopped` and a retained physical
input fence. Subsequent read-only window discovery showed Excel running, but
the original durable launch effect remained unknown. Both stop-boundary and
effect-reconciliation requests were rejected because helper cleanup remained
unconfirmed. No document creation or email send was qualified in this attempt.

In this state, preserve the original run, operation and effect references in
private task evidence. A visible app window does not prove helper cleanup or
release input authority. Use supported runtime recovery; do not delete fences,
rewrite ledger state, repeat the launch, or switch input tools to evade the hold.

The same day's unified-app update exposed a recovery path mismatch: the retained
helper executable was in the legacy installation while the new helper was inside
Mechanize.app. The corrected runtime permits that relocation only for its trusted
released-input recovery route, retaining both process-death checks, owner and
generation checks, and fresh native input-state proof. Live capability discovery
then restored native control. The original launch effect stayed unknown at effect
revision 2; a stop boundary paused its run without admitting replay. A separate
MCP/Endly press of the observed Start Using Excel button succeeded, and fresh
observation showed the new/recent-file screen. This qualifies that recovery and
welcome-screen case only; it does not establish document creation or email delivery.
