# Mechanize Endly acceptance suite

Run from `e2e/` with PATH-resolved `go`, `python3`, and `endly`:

```sh
./run.sh                                      # full disposable local suite
./run.sh -t=testGateway -d=gateway              # prerequisites + one module
./run.sh -t=testGateway -i=testGateway_discovery -d=discovery
./run.sh -t=testIdentity,testState -d=scoped
```

`run.sh` builds the fixture helper once through `build/build.yaml`, then runs
`run.yaml`. Root module entry points forward `setup,app,<module>` into
`regression/regression.yaml`. The unguarded `test.all` child runs every module
with setup once. Numbered case folders have separate `test.yaml`,
`prepare/request.json` and `expect/result.json` assets, following the structure
inspected in `/Users/awitas/Downloads/platform/e2e`. That external suite was
neither run nor modified.

Use the wrapper for selections: raw Endly accepts unknown `-i=` tags by silently
running a wider module. The wrapper rejects unknown modules, unknown cases, and
cases outside the selected module before starting the fixture. After Endly
finishes it compares emitted TagIDs against the requested set and requires each
case's relevant assertion minimum. Readiness assertions do not count toward a
case. JSON reports in `reports/` retain actual task names, TagIDs, per-case counts
and their total; `-d=<name>` retains detailed Endly events in `logs/<name>/`.
An Endly exit status alone is insufficient evidence.

| Module | Actual acceptance coverage | Assertions |
| --- | --- | ---: |
| gateway | Real MCP HTTP initialization, capabilities, all three skill reads; valid DSL and rejected unsupported DSL without dispatch | 11 |
| identity | Scy rejects invalid, expired and missing-scope credentials before dispatch | 4 |
| durability | One Endly dispatch, idempotent request replay, persisted generated Datly state, state read after Datly builder restart | 6 |
| state | Persisted owned state, foreign run/session denial, state patch fails closed without host guard | 7 |

The full local suite was verified with five emitted case tags and **28 relevant
assertions**, plus two readiness assertions. The focused gateway and durability
runs passed before the whole suite. This is fixture acceptance evidence; it does
not establish native/Chrome desktop reliability or process-death reconciliation.

The helper binds its bridge only to `127.0.0.1:18767`; each request creates a
separate real viant/mcp streamable HTTP server and client, a random ephemeral
HMAC key verified through Scy, an Endly automation runtime, and generated Datly
components with private per-user SQLite infrastructure. Credentials stay in
memory or a mode-0600 temporary file and are never returned in bridge reports.
The fake UI executor performs no employee desktop input and uses no browser,
cloud account or production data. Generated Datly components perform all product
data reads/writes; provisioning owns only narrow connector/schema infrastructure.
Each case removes only its own temporary directory. The wrapper stops its owned
fixture process on exit; after an interrupted shell run, use `.bin/fixture stop`.

The setup intentionally excludes permission-granted native fixtures, enrolled
Chrome profiles, real UI navigation/recovery and process-death scenarios. Those
require separate platform acceptance evidence; lower-level product tests remain
necessary.
