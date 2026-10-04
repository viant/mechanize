# Connect and discover

Connect the host to the installed Mechanize binary using its standard MCP
configuration. The current server command is:

```text
/absolute/path/mechanize serve -config /absolute/path/private-config.json
```

The config contains trusted user enrollment, Scy credential references and local
source/storage paths; keep it private. Do not paste tokens into MCP configuration
examples. Installation and credential provisioning are separate from tool use.

After connection, discover the runtime guidance with `skill_list` and
`skill_get`. MCP hosts may display server-qualified tool names; use the exact
names returned by their tool discovery rather than constructing a prefix. Hosts supporting native `skills/list` and `skills/get` can
use those methods. All other MCP hosts can enumerate resources and read the
`skill://mechanize-desktop/SKILL.md` entrypoint and exact supporting
URIs from its inventory. Skill retrieval does not authorize an action.

Some hosts also discover local skill folders. Copy this folder using that host's
supported local-skill installation procedure; do not assume every MCP host
implicitly loads server skills. Server resources and retrieval tools remain the
portable route. Preserve the relative `references/` and `agents/` folders.
