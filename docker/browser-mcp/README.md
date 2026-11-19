# Chromium MCP Server

This independent Linux service executes Mechanize browser DSL through MCP. It
does not require the native Mechanize application, a desktop helper, or a Chrome
extension. Each MCP session owns an isolated browser context with one tab.
Requests reuse that tab. Five idle minutes close the context; another request in
the same live MCP session creates a fresh context. Explicit session termination
closes its context. Login state is not written back automatically.

## Quick start: OAuth-authenticated browser

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
# Set keys and identityPolicy in "$MECHANIZE_CONFIG" for your OAuth provider first.
docker compose -f docker/browser-mcp/compose.yaml up -d --build
docker compose -f docker/browser-mcp/compose.yaml ps
```

The default allows all websites (`allowAllWeb: true`). To restrict websites,
configure the allowlist described below and restart the service. If you rerun
setup, avoid copying the sample over your customized configuration.
Before starting, set `keys` and `identityPolicy` in the private config to your
OAuth provider's verification keys/JWKS URL, issuer, algorithms and
required scopes. The sample values are synthetic.
Connect your MCP client to `http://127.0.0.1:8080/mcp` with a provider-issued ID token.

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
  "keys": {"CertURL": "https://issuer.example/.well-known/jwks.json"},
  "identityPolicy": {
    "issuer": "https://issuer.example",
    "algorithms": ["RS256"],
    "requiredScopes": ["browser:use"]
  },
  "operationTimeoutSeconds": 60
}
```

The server requires signed bearer tokens on every MCP request, including
initialization, streaming and termination. It validates signature, issuer,
subject, expiry and scopes against the configured policy.
Missing OAuth configuration fails startup. Shared service tokens and anonymous
access are unsupported. Compose publishes to host loopback; retain that binding
or use a deployment network boundary. MCP session IDs select isolated tabs and
remain bound to the verified user.

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

Complete the OAuth-authenticated setup first. Place an existing Playwright storage-state
export at `$MECHANIZE_SECRETS_DIR/storage-state.json` outside Git. This is a
JSON export, not a ZIP, encrypted archive, or Chromium `Default` directory.

```sh
chmod 600 "$MECHANIZE_SECRETS_DIR/storage-state.json"
export MECHANIZE_STORAGE_STATE=/run/browser-secrets/storage-state.json
docker compose -f docker/browser-mcp/compose.yaml up -d --force-recreate
```

The environment value is the path **inside the container**. The host directory
is mounted read-only there. To remove website login state (MCP still requires OAuth):

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
Every request requires `Authorization: Bearer <provider-issued ID token>`.
Use HTTP DELETE to terminate the session.
Stateless protocol modes do not provide this server's reuse contract.

Tools: `mechanize_capabilities`, `mechanize_script_validate`,
`mechanize_script_run`, `mechanize_browser_dom`, `mechanize_browser_screenshot`,
`mechanize_browser_frames`, `mechanize_browser_network`, and
`mechanize_session_close`. The last closes browser
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
input and bounded element assertions. Exact frame `id`/`name` scope is supported;
native capabilities remain unavailable. New tabs opened by pages are closed;
each session retains one tab. Inspection-only contexts block service workers so
they cannot bypass navigation interception; normal browsing keeps its existing
service-worker behavior.
Concurrent scripts in the same session return busy rather than interleaving.

Execution completion is distinct from a website business outcome. Mutations
are not automatically retried. A lost reply or cancellation may leave the effect
unknown; inspect the site before deciding whether to repeat an action.

## Inspection-only mode and frames

Use [config.inspection.example.json](config.inspection.example.json) as a starting
point, with your approved origins and provider settings. `inspectionOnly`
requires `allowAllWeb:false` and a nonempty explicit origin list. It permits
navigation, activation, reads and assertions. Clicks, input, keyboard actions
and selections are rejected for the entire script before any step executes.
Worker dispatch repeats the operation check. Navigation requests, redirects and
frame documents must also remain on permitted origins.
HTTP redirects are followed as at most 10 separately checked navigations,
preserving the final document URL and context cookies. Request evidence retains
the server's actual response status when a redirect is handled internally.
After a blocked navigation, close the session and initialize a fresh one before
continuing; Chromium may retain an error document from the rejected navigation.

`mechanize_browser_frames({})` returns up to 100 permitted frames with their DOM
iframe IDs, names and origins. Unavailable or blocked frames are not proof that
an implementation is absent. Select an exact frame using existing DSL:

```text
let value = web.tab(origin: "https://shop.example").frame(id: "store-frame").getById("amount").read("text")
```

Both `id` and `name` can narrow the selection. Missing or ambiguous matches fail;
the adapter does not silently choose the first frame. The current frame origin
is checked before returning read evidence. DOM reads also accept
`{"frame":{"id":"store-frame"}}`; omit `frame` for the main document. Screenshots
remain scoped to the main viewport. No arbitrary JavaScript API is added.

Inspection mode blocks explicit input operations. Visiting a website still runs
its normal page code and can generate network traffic. It is not a guarantee
that every GET request has no website side effect.

## Minimized request evidence

`mechanize_browser_network({})` returns a session-local snapshot of naturally
observed requests. Capture starts before page creation and defaults to no
configured endpoints. Deployment `networkRules` match exact origins and paths;
callers cannot widen the capture policy through tool arguments. Rule parameters
choose `value` for safe diagnostic values or `presence` to report only whether
a field is supplied/nonempty. Never configure personal identifiers, credentials
or sensitive records as `value`; use `presence` or omit them.

Evidence includes request method/type, configured parameter projections, frame
origin, response status when observed, elapsed time and failure flags. It does
not include full query strings, request headers, cookies, raw request/response
bodies or unconfigured fields. Queries, URL-encoded forms and flat scalar JSON
payloads up to 16 KiB are supported. Unsupported, oversized or malformed payloads
are explicit, with unknown fields distinguished from confirmed absence.

Each session keeps at most 100 records, five values per configured key and 128
characters per value. Truncation/dropped counts are explicit. Evidence is copied
on read with a 512 KiB serialized-record budget, below the worker response limit,
including multibyte values. Evidence is
discarded with its browser context, including idle recreation.
Requests are observed, never replayed. A successful HTTP response does not prove
application-level receipt, matching or a completed business transaction.

## Hosted authentication and network boundary

Clients present a signed token from the configured provider. Configure `keys` and
`identityPolicy` using the existing Scy verifier contract. For rotating issuer
keys, set `keys.CertURL` to the provider's trusted JWKS endpoint; key caching stays
with Scy. Set an explicit issuer, algorithm list and required scopes. Browser MCP accepts tokens issued to any client when their signature, issuer, subject, expiry and scope satisfy the policy.

Every MCP HTTP request includes `Authorization: Bearer <provider-issued ID token>`.
`X-Mechanize-Owner` is not used. User identity is derived from the
verified token and bind initialize, tool calls, streaming and transport
termination to the same identity. A different user cannot reuse a known
MCP session ID; a refreshed token for the same identity can. Each conversation
uses its own MCP session. Tokens are never forwarded to controlled websites.
The removed `bearerTokenFile` setting is rejected; migrate configuration before
upgrading. Website storage-state imports remain independent of MCP authentication.

Retain loopback/private-network binding and terminate TLS at the approved
gateway. `MECHANIZE_PROXY_SERVER` configures Chromium's outbound proxy, including
loopback destinations. In production, use an approved proxy/firewall that blocks
private, loopback, link-local and metadata destinations, including DNS rebinding
and page subresources. A permitted document origin alone does not enforce that
network boundary. Do not expose the service publicly or claim production egress
qualification from local tests. The client must retain a separate MCP transport
session for each authenticated user/conversation.

## Settings and verification

- `MECHANIZE_IDLE_MS`: browser idle timeout, default `300000`.
- `MECHANIZE_MAX_SESSIONS`: worker session capacity, default `32`.
- `MECHANIZE_STORAGE_STATE`: optional runtime-mounted seed JSON.
- `MECHANIZE_PROXY_SERVER`: optional approved outbound proxy URL.
- `CHROMIUM_PATH`: optional compatible executable override.
- `MECHANIZE_PORT`: host-loopback published port, default `8080`.
- `MECHANIZE_UID` / `MECHANIZE_GID`: container user/group, default `1000:1000`.
- `operationTimeoutSeconds`: complete script deadline, default `60`, maximum `3600`.

```sh
go test -race ./backend/containerbrowser ./cmd/mechanize-browser-mcp
node --test browser/playwright/test/{container-policy,network-evidence,sessions}.test.mjs
node scripts/browser-mcp-smoke.mjs
node scripts/browser-mcp-smoke.mjs --without-profile
node scripts/browser-inspection-smoke.mjs
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

For another Docker runtime, set `MECHANIZE_FIXTURE_HOST` to its host gateway and
`TMPDIR` to a directory shared with that VM. `MECHANIZE_IMAGE` selects a separately
built test image. The inspection smoke test verifies actual HTTP MCP auth/owner
binding, frame discovery/DSL/DOM, GET/POST field minimization, blocked navigation
and input, isolated request buffers and cleanup using only synthetic pages.
