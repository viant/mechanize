# Browser controller tool exposure

The canonical MCP server currently registers 47 tools with all optional services wired. The browser controller exposes 34 through the same handlers and existing policy/session authorization. The remaining 13 require the specific authority or projection work below; absence from the browser catalog does not imply that the canonical tool is unavailable to local clients.

`mcp/controller_tool_policy.go` is the exhaustive policy. `TestControllerCanonicalExposurePolicy` constructs the fully wired canonical catalog and rejects any unclassified registration, stale policy name, or exposure mismatch. Catalogs are bounded to 64 tools and the existing 192 KiB wire limit. This count change requires the updated extension; older receivers capped at 32 refuse the 34-tool catalog rather than partially exposing it.

Manual credential resume reuses the existing Host checks for owned immutable preparation, known child dispatches, current consent and private redactor qualification. It exposes no credential values and does not assert login success. Recording status/pause/stop reuse exact namespace, client and original session ownership; only finite status metadata crosses the bridge. Their input does not authorize starting or exporting a recording.

| Canonical tool | Browser policy | Contract / remaining work |
| --- | --- | --- |
| `mechanize_browser_activate_tab` | Exposed | Authenticated controller identity, canonical authorization and closed typed projection; owned session where required. |
| `mechanize_browser_location_matches` | Exposed | Authenticated controller identity, canonical authorization and closed typed projection; owned session where required. |
| `mechanize_browser_open_origin` | Exposed | Authenticated controller identity, canonical authorization and closed typed projection; owned session where required. |
| `mechanize_browser_status` | Exposed | Authenticated controller identity, canonical authorization and closed typed projection; owned session where required. |
| `mechanize_browser_tab_location_matches` | Exposed | Authenticated controller identity, canonical authorization and closed typed projection; owned session where required. |
| `mechanize_browser_tabs` | Exposed | Authenticated controller identity, canonical authorization and closed typed projection; owned session where required. |
| `mechanize_capabilities` | Exposed | Authenticated controller identity, canonical authorization and closed typed projection; owned session where required. |
| `mechanize_capture` | Exposed | Authenticated controller identity, canonical authorization and closed typed projection; owned session where required. |
| `mechanize_capture_window_frame` | Exposed | Authenticated controller identity, canonical authorization and closed typed projection; owned session where required. |
| `mechanize_capture_windows` | Exposed | Authenticated controller identity, canonical authorization and closed typed projection; owned session where required. |
| `mechanize_credential_apply` | Exposed | Authenticated controller identity, canonical authorization and closed typed projection; owned session where required. |
| `mechanize_credential_prepare` | Exposed | Authenticated controller identity, canonical authorization and closed typed projection; owned session where required. |
| `mechanize_credential_recover` | Exposed | Authenticated controller identity, canonical authorization and closed typed projection; owned session where required. |
| `mechanize_credential_resume_manual` | Exposed | Owned immutable credential preparation, current grant and private redactor qualification; closed credential status only. |
| `mechanize_credential_status` | Exposed | Authenticated controller identity, canonical authorization and closed typed projection; owned session where required. |
| `mechanize_credential_submit` | Exposed | Authenticated controller identity, canonical authorization and closed typed projection; owned session where required. |
| `mechanize_describe` | Exposed | Authenticated controller identity, canonical authorization and closed typed projection; owned session where required. |
| `mechanize_effect_reconcile` | Deferred | Needs exact client-owned durable run and stored-plan authority-target screening. |
| `mechanize_observe` | Exposed | Authenticated controller identity, canonical authorization and closed typed projection; owned session where required. |
| `mechanize_operation_cancel` | Exposed | Authenticated controller identity, canonical authorization and closed typed projection; owned session where required. |
| `mechanize_operation_outputs` | Exposed | Authenticated controller identity, canonical authorization and closed typed projection; owned session where required. |
| `mechanize_operation_status` | Exposed | Authenticated controller identity, canonical authorization and closed typed projection; owned session where required. |
| `mechanize_permission_request` | Exposed | Authenticated controller identity, canonical authorization and closed typed projection; owned session where required. |
| `mechanize_permission_status` | Exposed | Authenticated controller identity, canonical authorization and closed typed projection; owned session where required. |
| `mechanize_record_export` | Deferred | Export includes recorded action values and editable plans; no safe controller projection. |
| `mechanize_record_pause` | Exposed | Exact namespace/client/session recording ownership; bounded finite status only, never events or export. |
| `mechanize_record_start` | Deferred | Capture target needs controller-specific protected-console screening. |
| `mechanize_record_status` | Exposed | Exact namespace/client/session recording ownership; bounded finite status only, never events or export. |
| `mechanize_record_stop` | Exposed | Exact namespace/client/session recording ownership; bounded finite status only, never events or export. |
| `mechanize_recovery_admit` | Deferred | Recovery patches need client-owned run and protected-target screening. |
| `mechanize_recovery_context` | Deferred | Recovery context needs client-owned run and private-value projection. |
| `mechanize_resource_read` | Exposed | Authenticated controller identity, canonical authorization and closed typed projection; owned session where required. |
| `mechanize_scenario_list` | Deferred | Namespace catalogue includes entity values, inputs and surfaces. |
| `mechanize_scenario_publish` | Deferred | Namespace catalogue mutation requires controller ownership and value screening. |
| `mechanize_scenario_select` | Deferred | Selection can return an unscreened stored plan and private values. |
| `mechanize_script_run` | Exposed | Authenticated controller identity, canonical authorization and closed typed projection; owned session where required. |
| `mechanize_script_validate` | Exposed | Authenticated controller identity, canonical authorization and closed typed projection; owned session where required. |
| `mechanize_session_close` | Exposed | Authenticated controller identity, canonical authorization and closed typed projection; owned session where required. |
| `mechanize_session_open` | Exposed | Authenticated controller identity, canonical authorization and closed typed projection; owned session where required. |
| `mechanize_state_get` | Deferred | Namespace-scoped state includes variables, progress and checkpoints. |
| `mechanize_state_patch` | Deferred | Namespace-scoped mutation returns unprojected state; needs exact client-owned run. |
| `mechanize_state_pause` | Deferred | Namespace-scoped mutation returns unprojected state; needs exact client-owned run. |
| `mechanize_state_resume` | Deferred | Stored-plan execution needs exact client-owned run and protected-target screening. |
| `mechanize_state_stop_boundary` | Deferred | Needs exact client-owned durable run and stored-plan authority-target screening. |
| `mechanize_step_run` | Exposed | Authenticated controller identity, canonical authorization and closed typed projection; owned session where required. |
| `skill_get` | Exposed | Authenticated controller identity, canonical authorization and closed typed projection; owned session where required. |
| `skill_list` | Exposed | Authenticated controller identity, canonical authorization and closed typed projection; owned session where required. |

A namespace-only durable run lookup is insufficient for browser-controller ownership. In particular, compact reconcile/stop results do not make those commands eligible: their original run and stored native plan must first be bound to this controller client and screened against protected authority targets. No unknown effect is resolved or replayed by this exposure change. Scenario/state/recording payloads are not forwarded merely because they are available in the canonical catalog.

`mechanize_observe` rejects unknown top-level arguments, including the unsupported `nativeWindow` alias. Use its advertised `windowScope` object for an exact native window, or `nativeRoot: "menuBar"` with `nativeMenu` for a named menu. Invalid arguments never fall back to whole-app observation.

Source contracts reviewed:

- `mcp/controller.go`: authenticated identity, closed argument types, owned session gate and output projection; canonical tools retain their existing handlers.
- `host/credential_manual.go`: `manualCredentialSource` binds preparation and every delivery row to the same namespace/client and immutable source; only known dispatched rows qualify.
- `engine/recording/service.go`: `recordingOwner` checks namespace/client/session in both live and persisted paths. `mcp/controller_recording.go` excludes events, exported plans and arbitrary journal reasons from results.
- `integration/endly/runtime.go` / `reconcile_guard.go`: the current durable mutation guard does not independently prove the browser controller's exact client ownership after restart. `engine/durable/reconcile.go` and `stop_boundary.go` therefore remain deferred.
- `mcp/state.go`, `recovery.go`, `scenario.go`, `recording.go`: state/context/scenario/export responses or plan mutations require additional controller ownership/target/value screening before exposure.
