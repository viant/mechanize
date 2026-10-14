# Docker Desktop discovery — October 14, 2026

## Identity and discovery

The outer installed `/Applications/Docker.app` identified as `com.docker.docker`, version 4.92.0. Opening that bundle through Mechanize returned `launchPostconditionUnknown`: independently observed identity differed. Bundle-only observation was ambiguous (two app instances), and physical-window discovery for that bundle returned none. The launch was not repeated.

Read-only installed-bundle inspection identified the nested `Docker Desktop.app` as `com.electron.dockerdesktop`. Mechanize discovery under that actual identity returned the existing Containers - Docker Desktop dashboard. Pin its fresh PID and birth token; launcher identity and a zero-window result do not establish that Docker is absent or stopped. Do not hardcode the observed PID/window ID into a skill.

## Verified operations

- Native activation of the exact dashboard process succeeded.
- Exact-window screenshot capture showed Containers, a running engine and one existing container. This establishes visible dashboard state at capture time, not daemon health or complete inventory.
- Window-scoped AX observation was complete but exposed only the window and one group. Named native menu discovery worked (Docker Desktop, Edit, View). Complete AX discovery did not expose the rendered container controls.
- The dashboard visibly advertised Cmd+K for search. A physical-window Cmd+K opened a search overlay; fresh capture verified its empty input and suggested results. The overlay visibly documented Escape to close. Escape dispatch later succeeded, but no subsequent image established closure because storage was full.

A short public query was typed with physical-window keys; input dispatch succeeded, but result capture failed. Query content, search results and opening a result remain unverified. No existing container was mutated, and no disposable container was created in this run.

## Capture and storage failures

Two capture-window-frame attempts returned `captureFailed`, phase publication, cause unavailable, cleanupConfirmed true. They returned no usable captureRef/image for input. A later ordinary capture explicitly returned `artifact storage limit exceeded`. The later quota error establishes a storage blocker; it does not conclusively prove the cause of each earlier frame failure.

Do not replay a click without a published fresh frame or display a previous screenshot as current. No retention/deletion tool appeared in the inspected catalog. Keep unresolved launch evidence separate from the subsequently verified dashboard identity. Do not manually delete evidence files or edit the database to make a run appear successful.

## Next qualification task

After the operator restores evidence capacity through supported administration, rediscover the dashboard and try one fresh capture-bound frame. If usable, inspect Images/Containers navigation on a disposable fixture, then qualify exact-container start, logs, stop and cleanup with before/after results. Re-observe all targets; no saved coordinates or container names are reusable authority. Logs may contain credentials or private application data; keep evidence scoped and exclude secret values from the reusable skill.

Container search, image pulls, run/create, logs, start/stop/restart, delete, volumes, Compose and settings changes are currently unqualified. Describe these as pending work, not supported recipes.
