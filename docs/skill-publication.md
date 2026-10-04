# Skill publication

Mechanize embeds six runtime skills and publishes them through its MCP gateway
using the shared `mcp-protocol` static skill compiler. Canonical roots are
`skill://<skill-name>/SKILL.md`. Discovery uses native `skills/list` and
`skills/get`, resource listing/reading, and the `skill_list` / `skill_get`
compatibility tools. `skill_list` includes top-level `name`, `description` and
`ref` alongside each sealed manifest. Use tool names returned by the host's discovery.

## Datly host integration

For a Datly MCP application, call `skills.Folders()` from
`github.com/viant/mechanize/skills` and assign the result to the Datly MCP
configuration's `Folders` field. Each folder uses the embedded `skills.Files`,
an explicit root and `Skills: []string{"."}`. This is the same folder pattern
used by Datly's developer skill bundle. It does not require a database query.

The current Mechanize gateway continues to use its own static registration.
Providing Datly folder configuration does not expose Mechanize's private data
components, create a second server, or change their exposure policy.

## DQL component alternative

When composing skills into an existing generated Datly component, register the
embedded `skills.Files` under resource namespace `mechanize-skills` in the
transcription resource store. Add these setting fragments to that component's
complete DQL:

```sql
#setting($_ = $mcp_skill_folder('mechanize-skills', 'mechanize-desktop', 'skill://mechanize-desktop/'))
#setting($_ = $mcp_skill_folder('mechanize-skills', 'mechanize-app-discovery', 'skill://mechanize-app-discovery/'))
#setting($_ = $mcp_skill_folder('mechanize-skills', 'mechanize-finder', 'skill://mechanize-finder/'))
#setting($_ = $mcp_skill_folder('mechanize-skills', 'mechanize-openoffice', 'skill://mechanize-openoffice/'))
#setting($_ = $mcp_skill_folder('mechanize-skills', 'mechanize-recording', 'skill://mechanize-recording/'))
#setting($_ = $mcp_skill_folder('mechanize-skills', 'mechanize-scenario', 'skill://mechanize-scenario/'))
```

These are setting fragments, not a standalone query/component. Generate with
Datly v1's appropriate `transcribe` operation for the existing component. Its
resource generator snapshots declared folders into the generated package;
the composed MCP host publishes their immutable inventory and bytes. Keep
`skills/` authoritative; do not edit generated copies. `$mcp_folder` publishes
ordinary resources; `$mcp_skill_folder` additionally declares a skill root.

The source integration is demonstrated in Datly's
`transcribe/mcp_folders_test.go`: generated binary retrieval after source removal,
native skill/resource inventory, and rejection of unpublished traversal paths.
Mechanize's folder test separately checks every published file's digest and size.
Local `work_in_progress/` assets and agent working state are outside the embedded
filesystem and are never published.

## Authorization verification

Datly embeddings must configure `AuthorizeCatalogResource` for discovery and
manifest access, and `AuthorizeResource` for resource bytes. Embedding a folder
does not automatically make public guidance private. Transport authentication
and these callbacks belong to the embedding host's verified identity/policy.

`skills/authorization_test.go` uses the actual Datly service/native handler with
all six embedded Mechanize skills. Anonymous and other-principal contexts see
no skill/resource entries and cannot fetch manifests, entrypoints or references;
an authorized fixture principal can read every manifest file. Compatibility
list/get tools obey the same policy. The fixture guard tests authorization
integration; it does not qualify a live OAuth provider or installed deployment.

Mechanize's current gateway also requires an authenticated principal through its
request-context gate. Its MCP integration test denies anonymous `skill_list`,
`skill_get`, and skill resource reads, and verifies authorized listing descriptions
and exact references. Bundled guidance is shared among authenticated users; it
does not itself authorize application control.

`TestDatlyEmbeddedSkillsHTTPAuthorization` starts a real loopback Streamable HTTP
Datly server for both tested protocol versions (2025-11-25 and 2026-07-28).
It exercises native list/get, every manifest resource, compatibility tools,
missing/invalid credential rejection, and traversal rejection. It owns endpoint
shutdown and uses a random fixture credential kept entirely in process.

Wire verification exposed a compatibility-tool authorization gap in the shared
Viant MCP layer. The local `mcp/server/auth/skills.go` now maps reserved
`tools/call` names `skills/list` and `skills/get` to their native resource policy
checks, including supporting-resource scopes. This dependency fix must ship with
the application; an older dependency cannot be assumed equivalent. Fixture
verification does not qualify the live identity provider.
