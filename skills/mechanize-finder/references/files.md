# Finder folder navigation and file evidence

This reference records one narrow Mechanize/Endly Finder route. It qualifies navigation to a user-authorized known folder in the observed environment; it does not qualify finding a named file in Finder, selecting a result, opening a file, or verifying its contents through the UI.

## Navigate to a known folder

Discover current Mechanize capabilities and method schemas first. Open an owned session with the task's exact purpose and observe the fresh Finder process and window; use the paired process ID and start token from that observation. Do not copy process IDs, start tokens, window IDs, element references, or selectors from a prior run into a recipe.

In the verified case, Finder's complete `menuBar` observation exposed **Go to Folder…** with `AXPress`. Press the observed item only after confirming it is unique in the exact Finder process/window. A fresh modal observation then exposed the path text field. The recorded route focused that exact field, filled the user-authorized folder path, and compared the literal value before accepting it. After Return, a fresh `native.valueEquals` check matched the resulting window title to the requested folder. Treat the menu label, field identifier, key route, and window title as fresh observations, not persistent selectors or localization guarantees.

Do not accept a path that was not provided or authorized by the user. A typed path in the dialog is only staged input; verify the exact literal before submission and independently verify the resulting Finder window. If the path field is missing, ambiguous, or not readable, stop at that checkpoint rather than guess another route.

## File identification limits

The qualified folder view exposed a focused ListView in a complete 67-node observation, but filename values were withheld. No semantic file-row identification, selection, open, or reopen was verified. A matching folder title does not prove that a requested file is present or opened. Before claiming a file was found, require fresh complete evidence that uniquely matches the filename and location; before claiming it was opened, verify the resulting document identity and distinctive contents.

An attempted window capture was refused with `captureOffDisplay` because the observed window extended beyond the physical display. A subsequent `moveTo` attempt was refused because `windows.list` evidence was incomplete with invalid/duplicate roots. Neither attempt moved or captured the window. Do not repeat those routes or bypass the refusal with guessed coordinates or another automation surface. If a new complete discovery does not advertise and support a route, report the missing evidence and stop.

Filesystem inspection can independently verify saved bytes when the task calls for artifact verification, but it does not prove that Finder displayed, selected, or opened the file. Keep the UI claim and any separate artifact check distinct.

## Later verified window recovery and capture

A subsequent Mechanize helper update handles the observed owned AXScrollArea entry
in Finder's AXWindows list as a non-window. It still rejects foreign owners,
unreadable/unknown roles, duplicate window identities, and ambiguous titles.
With that build, exact-title window lookup and reading ListView's role succeeded.
The exact folder window was moved through `getByRole("window", name: observedTitle,
exact: true).moveTo({"x":100,"y":100})`; native position readback and fresh physical
window discovery confirmed the new bounds. A refreshed full-window capture then
showed the five expected DOC/ODS/ODT/PDF/XLS files. Coordinates were appropriate for
that observed display/window geometry; discover current bounds instead of reusing
those numbers blindly. This supersedes the earlier movement/capture limitation
for this case only. Filename-row selection and opening remain unqualified.
