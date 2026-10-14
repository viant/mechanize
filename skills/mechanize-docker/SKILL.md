---
name: mechanize-docker
description: Inspect Docker Desktop through Mechanize, resolve its separate UI identity, and use the observed dashboard/search workflow. Container lifecycle controls remain unqualified in the recorded case.
---

# Docker Desktop through Mechanize

Guide version 0.1.0. Read [observed identity, search and limits](references/desktop-discovery.md) before use. Tested Docker Desktop 4.92.0 on macOS, October 14, 2026. Use the Mechanize desktop skill for current capability, consent and execution contracts.

The installed launcher and running dashboard have different bundle identities. Discover them rather than requesting control for a guessed identity. The observed dashboard was the nested Docker Desktop app, `com.electron.dockerdesktop`; the outer launcher was `com.docker.docker`.

| Subtask | Completion evidence |
| --- | --- |
| Identify UI | Installed app identity plus fresh dashboard PID/birth/window |
| Inspect dashboard | Current owned-window capture and its actual visible state |
| Open search | Observed Cmd+K shortcut, resulting focused search visible in capture |
| Perform container work | Exact container identity, authorized action and independently confirmed result; not qualified by this case |

Native activation, dashboard capture and opening search are verified. The dashboard AX tree exposed only window/group nodes. Capture-bound click evidence could not be published, and later ordinary captures hit the artifact storage limit. Do not infer that dashboard controls are semantically accessible or that an advertised pointer capability is usable without a fresh capture permit.

Do not stop, restart, remove or reconfigure existing containers merely to explore. Use an explicitly owned disposable fixture for lifecycle qualification. Do not substitute Docker CLI execution and label it native GUI evidence. A runtime evidence-storage failure is not authority to delete ledger data or alter permission policy. Record the blocker and retain original action receipts.
