# Codex connection to the running Mechanize broker

`cmd/mechanize-mcp-relay` supplies a stdio MCP connection to an existing loopback
Mechanize HTTP server. It does not launch a broker or claim its native socket.
The relay uses the repository's viant/jsonrpc Streamable HTTP transport and Scy
credential resolver. Codex supports configured stdio MCP commands; see the
[official MCP documentation](https://developers.openai.com/codex/mcp).

Build and register it using an absolute executable path and the private config
used by the running broker:

```sh
go build -o "$HOME/.codex/bin/mechanize-mcp-relay" ./cmd/mechanize-mcp-relay
codex mcp add mechanize -- "$HOME/.codex/bin/mechanize-mcp-relay" \
  --config '/absolute/path/to/private/mechanize/config.json'
```

Only the config path appears in Codex's configuration and process arguments.
The credential remains in the referenced private file. The config and token
must be regular files owned by the current user with no group/other permissions;
symlink files, inline credentials, encrypted references, and fallback credentials
are refused. The token's validated bytes are passed to Scy, avoiding a second
pathname read. The endpoint defaults to `http://127.0.0.1:4987/mcp` and must use a
literal loopback IP. HTTP proxies and redirects are disabled.

The relay negotiates `2025-06-18`, retaining the deployed broker's HTTP session.
It preserves JSON-RPC IDs, results and server errors, forwards notifications and
server-initiated client requests, and supplies the broker's routing headers.
There is no mutation retry or request replay. Transport failures use a redacted
error because a failed connection may leave an operation's outcome uncertain.
Incoming requests are capped at 4 MiB, HTTP response streams at 32 MiB, concurrent
requests at 32, requests at two minutes, and notifications at ten seconds.
Cancellation notifications interrupt the corresponding relay request. EOF and
termination cancel pending work. Payloads, credentials, and internal HTTP errors
are never logged by the executable.

Start a fresh Codex chat/session after registration so it discovers the new MCP
server. The running broker must remain available. If a development installation
moves to a new config path, re-register the relay with that path.

Validation on 2026-10-02:

- `go test -race ./cmd/mechanize-mcp-relay` passed.
- `go build -o ~/.codex/bin/mechanize-mcp-relay ./cmd/mechanize-mcp-relay` passed.
- Live stdio `initialize` negotiated `2025-06-18` with server `mechanize`;
  `notifications/initialized` was forwarded and `tools/list` returned 31 tools.
- Relay exited successfully with empty stderr. No desktop tool was called.
- `codex mcp get mechanize` confirmed the enabled stdio registration with the
  absolute executable and private config paths, and no environment credentials.

The focused tests verify private Scy resolution and file restrictions, endpoint
restrictions, cancellation, routing headers, redacted failures and no replay.
This is connection verification, not a desktop automation or release gate.
