# Browser MCP Implementation

Current user-approved contract:

- Standalone Docker server using Mechanize DSL; no native app, helper or extension.
- No OAuth or Agently dependency. Compose publishes to host loopback.
- One isolated Chromium context/tab per MCP session, reused while active.
- Five-minute idle release and immediate session-termination cleanup.
- Optional deployment-time storage-state profile, kept outside Git.
- DOM extraction and inline PNG screenshots, with optional scale in (0, 1].
- No scratchpad artifact publication.

See docker/browser-mcp/README.md for deployment and verification commands.
The Docker smoke test checks actual MCP execution, profile seed loading, isolation,
reuse, idle expiry, active termination, disconnect cleanup, DOM and scaled images.
Lifecycle unit tests cover timer and creation races. Real-site test evidence and
real profile state remain outside the repository. Cookie presence alone does not
prove that a website login remains usable.
