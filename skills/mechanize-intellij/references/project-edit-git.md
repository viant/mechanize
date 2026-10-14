# Project, editor and Git workflow — October 14, 2026

Tested with IntelliJ IDEA 2026.2.1 (`com.jetbrains.intellij`) on macOS through Mechanize MCP → Endly → native actions. A separate local text-only Git fixture had no remote. The folder, initial files and `git init` were harness setup through the shell, not qualified IntelliJ operations. All subsequent editor changes, Git Add, both commits, branch creation/checkout and project closing were GUI actions. Read-only filesystem/Git checks established their results.

## Task and subtask handoffs

| Subtask | Inputs | Required result |
| --- | --- | --- |
| Open project | Exact authorized directory; existing window inventory | New project window and correct project/path, preserving other projects |
| Open/edit file | Current project; exact file and intended content | Correct editor focus, saved bytes/diff match |
| Create branch | Correct repo, base/current branch, unique requested name | New branch exists and checkout state matches intent |
| Commit | Authorized changed paths, reviewed diff and message | Expected commit/parent/file list and working-tree state |
| Close project | Exact owned project; saved/committed state | That window disappears; other project windows remain |

Use one desktop controller and fresh process/birth/window identity. Keep project and dialog identities separate. Scope semantic controls to the exact dialog or positively focused subtree; whole-app trees and even a named project scope were sometimes incomplete with many projects open. Truncated observations cannot establish uniqueness.

## Open a project and navigate to a file

1. Observe File, then select its exact Open… menu item. The observed native dialog was Open File or Project.
2. Its physical-window Cmd+Shift+G opened Go to Folder. The focused `PathTextField` rejected direct fill with `foregroundAXWindowUnavailable` before dispatch. The verified fallback staged the exact public path through an owned Excel Search field, privately compared it, copied it through GUI keys and pasted with Cmd+A/Cmd+V into the fresh Go to Folder window. See the [Office clipboard case](../../mechanize-microsoft-office/references/market-trends-handoff.md). Do not assume Excel is available or use an unrelated field without preserving its state.
3. Capture verified the full path and result before Return. The resulting picker showed the expected fixture directory. Semantic Open lookup was incomplete; Return on the observed picker opened the project prompt.
4. In New Project, New Window opened a separate project. Do not choose This Window or Close Other Projects merely to simplify discovery.
5. The first-open trust prompt was inspected. For this agent-created text-only fixture, Tab moved focus from Preview in Safe Mode to Trust Project, and a targeted semantic click trusted only that fixture. Trust all projects in Documents remained unchecked. Do not generalize this decision to downloaded or unknown projects.
6. Verify the project/path in the new window. Cmd+Shift+O opened Files search. Fill the focused textbox with the exact filename; wait for the results to update. A capture verified the selected file and fixture path, then targeted Return opened it. Focused-element observation identified `Editor for <filename>` as an enabled AXTextArea.

The selected Recent Projects item later returned success but did not reopen the fixture. Recent-project reopening is unqualified in this case; use the verified Open path and check the resulting project state. Never treat the menu receipt as reopen evidence.

## Edit and save

In the owned plain-text editor, `focusedElement().getByRole("textbox", name:"Editor for <filename>", exact:true).fill(text)` followed by File → Save All persisted the exact intended text in two edits. Generate the DSL string with proper JSON escaping; raw embedded newlines caused an unterminated-string rejection before input.

Whole-file replacement was appropriate only because the fixture's entire content was owned and known. It is not a general narrow-edit recipe for user source code. Verify the current file/baseline and intended scope before replacing content. Check actual saved bytes or diff; advertised editability and dispatch success are insufficient.

A later staleFocus failure left the file unchanged. Activation and fresh focused-element observation established the editor again before continuing. Preserve the original failed run, and confirm which steps were undispatched before issuing a continuation.

## Commit through the IDE

Cmd+K opened Commit with Commit Message focused. Direct fill worked for the public message. Shift+Tab twice reached the Changes outline in this case; inspect current focus and rows rather than assuming that tab order always holds.

Initially the outline reported that unversioned files were unavailable during scanning, then showed no rows despite Git reporting untracked files. Find Action (Cmd+Shift+A) could find and invoke Refresh VCS Changes but did not immediately resolve this state. Returning to the owned notes editor with Escape and selecting the observed Git → Add staged that file. Cmd+K then exposed the staged file and the remaining unversioned group.

With the observed unchecked Unversioned Files group last in the list, End, Space, ArrowRight selected and expanded it. Focused observation verified the exact two checked paths. These offsets are case-specific, not reusable file selectors. Amend was observed unchecked and was not toggled. Cmd+Return submitted one commit. Git initially reported no HEAD while the operation completed asynchronously; a later read confirmed the new commit. Do not resubmit during that interval.

After editing the tracked file on the demo branch, the same commit pane showed only that file checked. A second Cmd+Return produced a new child commit, not an amend. Independent Git checks verified two commits, exact messages/content, the demo branch and a clean working tree. No push was attempted; the existing skill's earlier push evidence is separate.

## Create and check out a branch

Git → Branches… opened a focused Branches Tree, but New Branch menu/row presses did not open the dialog. Row focus returned `focusUnconfirmed`. Physical Escape on the popup was rejected as an unsupported layer; targeted Escape on the positively focused Branches Tree dismissed it.

The working route was Cmd+Shift+A, fill the focused search field with New Branch, wait for the actual New Branch… result, then targeted Return. This opened Create New Branch with Branch Name: focused. The search result also displayed a shortcut; that shortcut was not tested and is not a qualified alternative.

Read-only checkbox checks verified Checkout branch true and Overwrite existing branch false. The active project was the independently identified single-root fixture. Root-value reading was denied, and Root popup focus/showMenu did not qualify. Do not use this procedure for an ambiguous multi-root project until the exact repository is established.

Direct Branch Name: fill returned success but failed the exact literal comparison; Create did not produce a branch. The verified recovery used GUI clipboard text and targeted Cmd+A/Cmd+V on the observed focused Branch Name: textbox. A private `native.literalValueMatches` check then passed for the entire name. Create was enabled; targeted Return submitted the dialog. Independent Git checks confirmed the unique branch was created and checked out. The main Mechanize repository remained on its original branch.

One clipboard run stopped after Copy but before clearing its staging field. State inspection proved those five steps completed and no unresolved effects remained; only the undispatched paste work continued. A later guarded attempt to restore the staging query could not verify its expected value, so it did not clear the field. Record incomplete cleanup instead of overwriting an unverified field.

## Close and verify

The observed File → Close Project item returned success without closing the project. Find Action with Close Project, wait for that exact result (distinct from Close All Projects and Close Other Projects), then targeted Return did close the fixture. Complete physical-window inventory confirmed its absence and that all 21 original project windows remained.

## Evidence and limits

One fixture, two exact saved editor changes, two verified commits, one created/checked-out branch, and one verified project close. This is case evidence, not an unattended reliability claim. Project opening was verified once; attempted Recent Projects reopening was not. Screenshot storage reached its limit during discovery; later checks used permitted semantic observations and independent file/Git results. Screenshots were not fabricated or obtained through a different GUI controller. No rebase, merge, conflict resolution, multi-root branching, arbitrary source editing or remote push was qualified in this case.
