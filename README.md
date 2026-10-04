# Mechanize

**reliable automation infrastructure for people, scripts, and LLM agents.**

Mechanize exposes supported desktop and browser automation through a typed
model and an authenticated [Model Context Protocol (MCP)](https://modelcontextprotocol.io/)
gateway. Clients discover capabilities, inspect current state, target semantic
controls, perform authorized actions, and check available postconditions.

## What it provides

- A typed automation DSL and shared intermediate representation for native
  application and browser workflows.
- MCP tools for capability discovery, observation, session and permission
  handling, script validation and execution, operation status, and supported
  evidence and workflow features.
- Short-lived references for observed elements, with durable scripts based on
  application identity and semantic locators.
- Bundled MCP skills that give clients practical, capability-aware guidance.
- Integration points for Endly workflow execution and generated Datly data
  operations.

Available tools and actions depend on the configured host, authenticated
identity, granted permissions, and advertised backend capabilities. Parsing a
script does not imply that a live adapter can execute it.

## Quick start

Mechanize is under active development. The checked-in `go.mod` replaces several
Viant modules with sibling source directories (`../datly`, `../endly`,
`../mcp`, `../mcp-protocol`, `../scy`, and `../sqlx`). A clean clone of this
repository alone therefore does not currently provide a standalone build.
Use the matching Viant source workspace with Go 1.25.8 or newer.

From the `mechanize` module directory in that workspace:

```sh
go build -o ./mechanize ./cmd/mechanize
./mechanize doctor -helper /absolute/path/to/native-helper
./mechanize serve -config /absolute/path/to/private/config.json
```

`doctor` performs a nonprompting helper check. `serve` requires a private JSON
configuration file and authenticated credentials; with no `-listen` flag it
serves MCP over stdio. An explicit loopback HTTP listener can be selected with
`-listen 127.0.0.1:4987`. The CLI does not generate configuration or provide an
anonymous default. See [local development installation](docs/local-installation.md)
for the development install workflow and its platform prerequisites.

## Connect an MCP client

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
through the compatibility tools `skill_list` and `skill_get`, and through
skill resources whose roots use URIs such as
`skill://mechanize-desktop/SKILL.md`.

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
| [Datly](https://github.com/viant/datly) | Generated, identity-scoped data operations |
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
