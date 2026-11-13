# Chromium MCP Server

This independent Linux service executes Mechanize browser DSL through MCP. It
does not require the native Mechanize application, a desktop helper, or a Chrome
extension. Each MCP session owns an isolated browser context with one tab.
Requests reuse that tab. Five idle minutes close the context; another request in
the same live MCP session creates a fresh context. Explicit session termination
closes its context. Login state is not written back automatically.

## Quick start: anonymous browser

Requirements: Docker with Compose. From the repository root, prepare private
runtime configuration outside Git and start with no website login state:

```sh
export MECHANIZE_RUNTIME_DIR="$HOME/.config/mechanize-browser"
mkdir -p "$MECHANIZE_RUNTIME_DIR/secrets"
chmod 700 "$MECHANIZE_RUNTIME_DIR" "$MECHANIZE_RUNTIME_DIR/secrets"
cp docker/browser-mcp/config.example.json "$MECHANIZE_RUNTIME_DIR/config.json"
chmod 600 "$MECHANIZE_RUNTIME_DIR/config.json"
export MECHANIZE_CONFIG="$MECHANIZE_RUNTIME_DIR/config.json"
export MECHANIZE_SECRETS_DIR="$MECHANIZE_RUNTIME_DIR/secrets"
export MECHANIZE_UID="$(id -u)"
export MECHANIZE_GID="$(id -g)"
unset MECHANIZE_STORAGE_STATE
docker compose -f docker/browser-mcp/compose.yaml up -d --build
docker compose -f docker/browser-mcp/compose.yaml ps
```

The default allows all websites (`allowAllWeb: true`). To restrict websites,
configure the allowlist described below and restart the service. If you rerun
setup, avoid copying the sample over your customized configuration.
Connect your MCP client to `http://127.0.0.1:8080/mcp`; no API key is required.

Create the private configuration outside Git with mode `0600`. The default image
runs as UID/GID `1000:1000`; mounted files and directories must be readable by
that identity. Use deployment secret mounts with the corresponding ownership,
or run Docker with an explicitly selected non-root UID/GID that owns the files.
The secrets directory should be private and must not be a repository directory.

Example configuration (all identities and origins are synthetic):

```json
{
  "listen": "0.0.0.0:8080",
  "node": "node",
  "worker": "/app/browser/container-worker.mjs",
  "allowAllWeb": true,
  "allowMutation": true,
  "operationTimeoutSeconds": 60
}
```

This standalone server requires no OAuth configuration or bearer token.
Compose publishes to host loopback. Anyone who can reach the endpoint can create
sessions, so retain that binding or use a deployment network boundary.
MCP session IDs select isolated tabs; they are not user identities.

`allowAllWeb` defaults to `true`, including when omitted. `allowedOrigins` means
websites Chromium may control, not the MCP server URL. To enforce an allowlist,
explicitly set `allowAllWeb` to `false`:

```json
{
  "allowAllWeb": false,
  "allowedOrigins": ["https://example.org", "https://www.youtube.com"]
}
```

Each origin is the exact scheme, hostname and optional port, without a path.
An empty allowlist with `allowAllWeb: false` permits no websites. The allowlist
does not restrict browsing while `allowAllWeb` is true. `allowMutation` defaults
to false. Configure deployment network egress separately, including which internal
addresses browser navigation and page subresources can reach.

## Quick start: profile browser

The supported profile format is Playwright storage-state JSON, supplied before
startup. It contains cookies and origin storage; it is sensitive login material.
Each session receives an independent copy of that seed state.

Complete the anonymous setup first. Place an existing Playwright storage-state
export at `$MECHANIZE_SECRETS_DIR/storage-state.json` outside Git. This is a
JSON export, not a ZIP, encrypted archive, or Chromium `Default` directory.

```sh
chmod 600 "$MECHANIZE_SECRETS_DIR/storage-state.json"
export MECHANIZE_STORAGE_STATE=/run/browser-secrets/storage-state.json
docker compose -f docker/browser-mcp/compose.yaml up -d --force-recreate
```

The environment value is the path **inside the container**. The host directory
is mounted read-only there. To switch back to anonymous mode:

```sh
unset MECHANIZE_STORAGE_STATE
docker compose -f docker/browser-mcp/compose.yaml up -d --force-recreate
```

For either mode, inspect logs or stop with the same exported configuration:

```sh
docker compose -f docker/browser-mcp/compose.yaml logs --tail 100 browser-mcp
docker compose -f docker/browser-mcp/compose.yaml down
```

Leave this variable unset for clean anonymous contexts. Mount the file read-only
under `MECHANIZE_SECRETS_DIR`. Updating the seed requires restarting the service.
Export storage state from an authorized Playwright context using
`context.storageState({path: destination, indexedDB: true})`; keep the export
outside Git. Restore encrypted artifacts through your deployment secret manager
before launching the service. The server does not accept profile paths in tools.

A full Chromium user-data directory is not a storage-state file. It cannot be
mounted into each isolated context of a shared browser process. Full-profile
migration requires an authorized export in a compatible Chromium environment;
OS-keychain-bound cookies may require signing in again. Service workers, browser
extensions and sessionStorage are not promised by storage-state imports.

Use a deployment dedicated to one authorized login identity when providing a
profile seed. Every admitted session receives that deployment's seed; context
isolation does not make a shared account into separate website identities.

## MCP connection and DSL

Connect to `http://127.0.0.1:8080/mcp` using stateful Streamable HTTP and protocol
`2025-11-25`. Retain the returned `Mcp-Session-Id` for subsequent requests.
No Authorization header is required. Use HTTP DELETE to terminate the session.
Stateless protocol modes do not provide this server's reuse contract.

Tools: `mechanize_capabilities`, `mechanize_script_validate`,
`mechanize_script_run`, and `mechanize_session_close`. The last closes browser
resources and prevents further execution in that session; initialize a new one.

After opening a tab, `mechanize_browser_dom` returns its URL, title, rendered HTML
and visible body text (bounded to 300,000 HTML and 64,000 text characters, with
an explicit truncation flag). `mechanize_browser_screenshot` returns a viewport
PNG as MCP image content. Pass `{}` for full size or `{"scale":0.5}` for half width and height.
`scale` must be greater than zero and at most one; Chromium scales the image
without changing page layout. There are no artifact IDs or scratchpad writes.
Both tools use the owning session's
tab, renew its idle activity and enforce allowed-origin policy before delivery.
Outputs can contain authenticated page data; store them outside public Git.

Pass source as `{"source": "..."}` to the validation or run tool:

```text
web.tab(origin: "https://example.org").openOrigin()
let heading = web.tab(origin: "https://example.org").getByRole("heading").read("text")
```

The canonical Mechanize compiler validates source and typed bindings. This
executor supports browser navigation, activation, strict locators, text/value/
checked/enabled/visible reads, click, fill, check/uncheck, select, focus, keyboard
input and bounded element assertions. Unsupported native and frame capabilities
are rejected. New tabs opened by pages are closed; each session retains one tab.
Concurrent scripts in the same session return busy rather than interleaving.

Execution completion is distinct from a website business outcome. Mutations
are not automatically retried. A lost reply or cancellation may leave the effect
unknown; inspect the site before deciding whether to repeat an action.

## Settings and verification

- `MECHANIZE_IDLE_MS`: browser idle timeout, default `300000`.
- `MECHANIZE_MAX_SESSIONS`: worker session capacity, default `32`.
- `MECHANIZE_STORAGE_STATE`: optional runtime-mounted seed JSON.
- `CHROMIUM_PATH`: optional compatible executable override.
- `MECHANIZE_PORT`: host-loopback published port, default `8080`.
- `MECHANIZE_UID` / `MECHANIZE_GID`: container user/group, default `1000:1000`.
- `operationTimeoutSeconds`: complete script deadline, default `60`, maximum `3600`.

```sh
go test -race ./backend/containerbrowser ./cmd/mechanize-browser-mcp
node --test browser/playwright/test/sessions.test.mjs
node scripts/browser-mcp-smoke.mjs
node scripts/browser-mcp-smoke.mjs --without-profile
```

The smoke test builds synthetic browser state in a temporary directory and
uses the already built image. It verifies real Chromium through MCP, profile
loading, isolation, reuse, accelerated idle expiry and termination.
Live fixture connections prove page closure, including termination during an
active request and cancellation when the HTTP client disconnects. Run both
profile modes. Successful script results include `compileMs`, `browserMs`, and
`elapsedMs` timings; the smoke test prints cold and warm measurements. These
measurements include different workloads and are not a comparative benchmark.
It requires Docker Desktop's `host.docker.internal` routing. It never uses a real
website login. Production network/profile qualification remains specific
to the deployment; local tests do not prove those external conditions.
