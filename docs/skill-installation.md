# Install the Mechanize skill and connect an MCP host

Mechanize provides one portable skill folder:

```text
skills/mechanize-desktop/
  SKILL.md
  agents/openai.yaml
```

The `SKILL.md` contains the shared runtime guidance. The `agents/openai.yaml`
file supplies optional Codex UI metadata. Other hosts can ignore it.

## Add the skill to a host

If an MCP client supports the MCP skills extension, it may load a server
provided skill through that extension. Support varies by client. Otherwise:

1. Copy the complete `skills/mechanize-desktop/` folder into the skills
   directory supported by the chosen host. Keep the folder name and
   `SKILL.md` filename.
2. Reload the host or its skill catalog, then confirm `mechanize-desktop` is
   available. Each host may use a different directory and discovery process;
   follow that host's current skill documentation.
3. Configure the same host to connect to the Mechanize MCP server as described
   below. Installing a skill does not install or start the server.

No host-specific plugin manifest is required by this portable folder. For
clients without skill support, connect to the MCP server and use its
`mechanize_capabilities`, `mechanize_describe`, and other discovered tools
directly.

## Connect over stdio

Build or install the `cmd/mechanize` executable for the target machine. In the
MCP client's server configuration, use its documented stdio server format with
the executable and a private Mechanize config path. For clients using the
common `mcpServers` shape, the entry is:

```json
{
  "mcpServers": {
    "mechanize": {
      "command": "/absolute/path/to/mechanize",
      "args": [
        "serve",
        "-config",
        "/absolute/path/to/private-mechanize-config.json"
      ]
    }
  }
}
```

This points to the actual `cmd/mechanize serve -config <path>` interface. The
server requires a private JSON host config with absolute Datly source and
storage roots, Scy verifier keys and identity policy, enrolled users, and a
Scy credential-resource reference for stdio. Keep that host config at mode
`0600`; do not put bearer tokens, signing keys, or other credentials in the MCP
client's launch descriptor or shareable skill files. Provide credential
material only through the configured Scy resource mechanism. The server has no
anonymous/default identity.

The stdio process uses the Scy credential to establish a verified principal.
The principal must match an enrolled user and satisfy configured issuer,
audience, algorithm, time, and scope policy. The user's native bundle IDs and
Chrome origins also constrain surface access. Connection success does not
grant a mutation or imply that a requested outcome can be verified.

## Connect over loopback HTTP

For a client that uses HTTP transport, launch:

```sh
/absolute/path/to/mechanize serve \
  -config /absolute/path/to/private-mechanize-config.json \
  -listen 127.0.0.1:8765
```

The server accepts only an explicit loopback IP and serves MCP at `/mcp`. HTTP
requests require a Bearer credential verified by the configured Scy policy.
Supply that credential through the client's protected authentication settings;
do not add it to the command line, shell history, skill file, or shared config
snippet. Use a protected transport if exposing the endpoint beyond loopback.

## First calls and current limits

After connecting, call `mechanize_capabilities` and `mechanize_describe` before
choosing a surface or DSL method. Then use `mechanize_observe` for authorized
current state, `mechanize_script_validate` to parse/type-check a script,
`mechanize_session_open`, and `mechanize_step_run` or
`mechanize_script_run`. Inspect runs with `mechanize_operation_status`; close
the session with `mechanize_session_close` when finished. The server can also
cancel an operation with `mechanize_operation_cancel`.

Capabilities are scoped and conditional. The current host sets mutation policy
to false, so requests to mutate are rejected even if a low-level backend has a
mutation method. Run responses currently report business status as
`unverified`; execution completion is not proof of the business result. Report
these limits accurately and reconcile any effect whose dispatch or outcome is
uncertain.
