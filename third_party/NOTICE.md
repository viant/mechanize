# External feature references

The researched implementations are not directly ported by this work. The
AXSwift adaptation was removed at the user’s request; explicit missing-value
handling is implemented directly in Mechanize’s existing checked-state reader.
The single-flight Chrome connection is independently implemented in JavaScript.

Research references, reviewed October 5, 2026:

- AXSwift: optional AX reads and observer lifecycle
  https://github.com/tmandry/AXSwift
- Playwright extension: connection UI, pending connections and tab ownership
  https://github.com/microsoft/playwright/tree/main/packages/extension
- BrowserOS: browser/controller/status separation
  https://github.com/browseros-ai/BrowserOS

The saved license texts are research references, not evidence that upstream code
has been imported. Any future direct reuse requires explicit provenance and
license-compatibility review. Mechanize retains its own Go/JS orchestration,
Scy, consent, immutable effects and recovery design.

The native pointer backend statically links RobotGo v1.3.5, purego v0.11.1 and the Go runtime. Their license texts are included in licenses/.

The optional local browser engine depends on the unmodified `playwright-core`
1.64.0 package (Microsoft, Apache License 2.0). Its LICENSE, NOTICE and
ThirdPartyNotices.txt are preserved under the packaged runtime's
`node_modules/playwright-core/` directory. Mechanize's relay and orchestration
are separate code; the dependency is not a direct port of Playwriter.

CDP session design reference (October 9, 2026): Playwriter commit 525732a474a14224d46469c2b85737dbcdc23e07, extension/src/background.ts and playwriter/src/cdp-session.ts. Mechanize independently implements reusable debugger sessions, detach invalidation, bounded command waits and child-session routing. The Playwriter MIT notice is included in licenses/Playwriter-MIT.txt. No Playwriter service, telemetry or arbitrary-code MCP endpoint is embedded.

The Chrome accessible-name provider bundles unmodified `dom-accessibility-api`
0.7.1 (MIT), from https://github.com/eps1lon/dom-accessibility-api. Its complete
license is preserved in licenses/dom-accessibility-api-MIT.txt. Mechanize supplies
an inert sanitized DOM projection; credential values are not passed to the
dependency. The build-only bundler is pinned separately in the extension lockfile.
