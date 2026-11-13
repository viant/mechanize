# Mechanize

**reliable automation infrastructure for people, scripts, and LLM agents.**

Mechanize exposes desktop and browser automation through a typed DSL and
[Model Context Protocol (MCP)](https://modelcontextprotocol.io/) tools.
Choose the runtime that fits your task:

| Runtime | Use it for | Requirements |
| --- | --- | --- |
| [Browser-only MCP server in Docker](#browser-only-mcp-server-in-docker) | Control Chromium, extract DOM, and capture screenshots | Docker; no OAuth, native app, or Chrome extension |
| [Native desktop gateway](#native-desktop-quick-start) | Automate supported macOS apps and an enrolled Chrome browser | macOS helper, private configuration, authentication and permissions |

## Browser-only MCP server in Docker

Run a standalone Chromium MCP server with **no authentication setup**. Each MCP
session gets an isolated tab that is reused between requests and closed on
session termination or after five idle minutes.

From the repository root, start an anonymous browser:

```sh
export MECHANIZE_RUNTIME_DIR="$HOME/.config/mechanize-browser"
mkdir -p "$MECHANIZE_RUNTIME_DIR/secrets"
chmod 700 "$MECHANIZE_RUNTIME_DIR" "$MECHANIZE_RUNTIME_DIR/secrets"
cp docker/browser-mcp/config.example.json "$MECHANIZE_RUNTIME_DIR/config.json"
chmod 600 "$MECHANIZE_RUNTIME_DIR/config.json"
export MECHANIZE_CONFIG="$MECHANIZE_RUNTIME_DIR/config.json"
export MECHANIZE_SECRETS_DIR="$MECHANIZE_RUNTIME_DIR/secrets"
export MECHANIZE_UID="$(id -u)" MECHANIZE_GID="$(id -g)"
unset MECHANIZE_STORAGE_STATE
docker compose -f docker/browser-mcp/compose.yaml up -d --build
```

Connect your MCP client to **`http://127.0.0.1:8080/mcp`** using stateful
Streamable HTTP, protocol `2025-11-25`. No bearer token or API key is required.
All websites are allowed by default (`allowAllWeb: true`). To restrict browsing,
set `allowAllWeb: false` and list website origins in `allowedOrigins`; these are
website addresses, not the MCP endpoint. Preserve a customized config when
rerunning setup. Compose publishes the service to host loopback.

- **Anonymous mode:** leave `MECHANIZE_STORAGE_STATE` unset.
- **Profile mode:** provide a private Playwright storage-state JSON export and
  set `MECHANIZE_STORAGE_STATE=/run/browser-secrets/storage-state.json`.
  See the [profile setup instructions](docker/browser-mcp/README.md#quick-start-profile-browser).
- **Browser control:** call `mechanize_script_run` with Mechanize DSL.
- **DOM extraction:** call `mechanize_browser_dom` with `{}`.
- **Screenshots:** call `mechanize_browser_screenshot` with `{}` for full size
  or `{"scale":0.5}` for half-size PNG image content.

Example arguments for `mechanize_script_run`:

```json
{"source":"web.tab(origin: \"https://example.org\").openOrigin(); let heading = web.tab(origin: \"https://example.org\").getByRole(\"heading\").read(\"text\")"}
```

See the **[browser MCP deployment guide](docker/browser-mcp/README.md)** for
profile export requirements, configuration settings, logs, shutdown, and tests.
Browser profiles and login exports belong outside Git and the Docker image.

## What it provides

- A typed automation DSL and shared intermediate representation for native
  application and browser workflows.
- MCP tools for capability discovery, observation, session and permission
  handling, script validation and execution, operation status, and supported
  evidence and workflow features.
- Short-lived references for observed elements, with durable scripts based on
  application identity and semantic locators.
- Bundled MCP skills that give clients practical, capability-aware guidance.
- Integration points for Endly workflow execution and generated Datly 1.0
  (`v1`) data operations.

Available tools and actions depend on the configured host, authenticated
identity, granted permissions, and advertised backend capabilities. Parsing a
script does not imply that a live adapter can execute it.

## Native desktop quick start

Mechanize is under active development. Dependencies are pinned to published Go
module revisions, including the Datly 1.0 (`v1`) development line; sibling
Viant checkouts are not required. The exact Datly pseudo-version is recorded in
[go.mod](go.mod). Use Go 1.25.8 or
newer. Native automation and the permissions helper require macOS and the
platform build tools described in the installation guide.

```sh
git clone https://github.com/viant/mechanize.git
cd mechanize
go build -o ./mechanize ./cmd/mechanize
```

After installing the native helper and provisioning a private configuration:

```sh
./mechanize doctor -helper /absolute/path/to/native-helper
./mechanize serve -config /absolute/path/to/private/config.json
```

`doctor` performs a nonprompting helper check. `serve` requires a private JSON
configuration file and authenticated credentials; with no `-listen` flag it
serves MCP over stdio. An explicit loopback HTTP listener can be selected with
`-listen 127.0.0.1:4987`. The CLI does not generate configuration or provide an
anonymous default. See [local development installation](docs/local-installation.md)
for the development install workflow and its platform prerequisites.

## Connect a native desktop MCP client

Configure an MCP client to launch the `mechanize` executable with `serve` and
the absolute path to its private configuration file. For a stdio client, the
command shape is:

```text
mechanize serve -config /absolute/path/to/private/config.json
```

Keep credentials in the private configuration and referenced credential
resources; do not put secret values in client arguments. For Codex, a relay can
connect stdio to an already-running loopback broker; see
[the Codex MCP connection guide](docs/codex-mcp-connection.md). Once connected,
discover the tools the host actually advertises. Skill guidance is available
through the protocol methods `skills/list` and `skills/get`, the compatibility
tools `skill_list` and `skill_get`, and `resources/read`. For example,
`skill_get` accepts `{"uri":"skill://mechanize-desktop/SKILL.md"}`.

Each enrolled user may configure `skillDirectories` with absolute paths to
private, dedicated skill folders outside the source repository. Each root
contains named subdirectories with `SKILL.md` entrypoints. Mechanize rejects
symlinks, writable shared roots, oversized content, and duplicate skill URIs.
Local guides join the bundled catalog as immutable snapshots for that user's
MCP connection; reconnect after editing a guide. Skill resources expose guidance
only, never Vault records or arbitrary filesystem paths.

## Browser execution and recovery

Saved access policy is independent of temporary executor cleanup. Mechanize
retains an uncertain action's original receipt and retries only its cleanup;
it does not replay input or ask for renewed permission to recover that state.
Execution holds follow the affected browser tab and frame, so other identified
tabs can continue. A successor document in the same tab remains covered until
the earlier input is retired. Connection loss and input without a trustworthy
target still require broader recovery.

Connection setup keeps one bounded current handoff and retains earlier records
as immutable audit data. Interrupted reconnects do not accumulate nested recovery
state. After a timed-out Chrome setup call settles, one automatic metadata retry
can obtain a fresh connection without replaying browser input.

Native control can also recover after delayed cleanup once the exact old helper
is confirmed stopped and existing input-release checks pass. Completed text
delivery remains recorded even if a later focus observation is unavailable;
partial input and uncertain key release retain their original uncertain outcome.

The local Playwright process is reused across calls, with fresh target and
action authorization for each invocation. Cancellation or a broken transport
discards that process without retrying the action. Browser and native tools
report delivery separately from verification of the requested outcome.

## Typed DSL

The parser accepts a closed typed grammar. For example:

```text
let caseApp = app("com.example.CaseDesk")
let summary = caseApp.getById("case-summary").read("value")
caseApp.getByRole("button", name: "Save", exact: true).click()
expect(caseApp.getById("case-summary")).toHaveValue(summary, timeout: 5s)
```

This illustrates parser-supported syntax, not a promise that a live application
supports those controls or actions. Validate scripts with
`mechanize_script_validate`, inspect the running host's capabilities, and use
fresh observations and references. See [DSL grammar](script/grammar.md) for the
supported syntax and [desktop skill](skills/mechanize-desktop/SKILL.md) for the
interaction flow.

## Development status

The repository contains the MCP gateway, typed DSL, native macOS and Chrome
integration code, and workflow and data-operation integrations. Work remains
to qualify signed packaging, supported application and browser coverage,
permission and restart behavior, end-to-end outcomes, and operational
reliability. Fixture tests and source implementation do not establish a
production release or universal desktop coverage. See
[remaining qualification gates](docs/remaining-gates.md) for current scope.

## Architecture

| Layer | Responsibility |
| --- | --- |
| Mechanize MCP gateway | Capability discovery, authenticated sessions, typed actions and evidence |
| Native helper / Chrome extension | Surface-specific observation and control |
| [Endly](https://github.com/viant/endly) | Workflow orchestration through MCP integration |
| [Datly 1.0 (`v1`)](https://github.com/viant/datly/tree/v1) | Generated, identity-scoped data operations |
| [Scy](https://github.com/viant/scy) | Credential references and authentication integration |

## Contributing

Contributions to app support, browser integration, documentation, and reliable
execution are welcome. Use a matching Viant development workspace and describe
the operating system, application/browser version, advertised capabilities,
and independently verified result when reporting an automation issue.

Focused source checks include:

```sh
go test ./model ./script ./mcp ./skills ./backend/darwin
```

Use disposable documents and isolated fixtures for automation tests. Keep
credentials and personal recordings out of issues and pull requests. A useful
app procedure includes preconditions, observed selectors, expected outcome,
and recovery behavior; passing a parser or mock test alone does not qualify it
for live use.

### Product capabilities and app skills

Mechanize owns reusable observation/control, capability discovery, consent,
secure local credential references, recording, durable effects and recovery.
Endly owns orchestration. App and site skills supply verified interaction knowledge,
parameterized procedures and outcome checks; a skill never grants access or turns
an unsupported API into a qualified capability.

When qualification finds a generally useful missing behavior, implement it in
Mechanize's native/browser adapter or shared closed DSL, test its safety boundary,
and qualify it through MCP and Endly before documenting support in a skill.
App-specific names and workflows stay in app/site guides. Source-only improvements
and historical unknown effects must remain explicit in those guides.

For Microsoft Word, Excel, PowerPoint and Outlook on macOS, use the bundled
[Microsoft Office skill](skills/mechanize-microsoft-office/SKILL.md) and its
[support matrix](skills/mechanize-microsoft-office/references/getting-started.md).
The guide includes recorded document, spreadsheet, presentation and authorized
email workflows, with case-specific limitations. Retrieve it through `skill_get`
with `{"uri":"skill://mechanize-microsoft-office/SKILL.md"}`. Source edits enter
the embedded catalog on rebuild and deployment; a personal Codex skill copy
does not update or connect a running Mechanize broker.

## Credits and Acknowledgements

**Library Authors:**

- Adrian Witas
