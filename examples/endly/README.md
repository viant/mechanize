# Mechanize tests through Endly

Build Endly from the sibling checkout containing `service/testing/runner/mcp`.
The verified development binary is installed as `~/.local/bin/endly-mcp-runner`;
use that command instead of `endly` below until your standard Endly binary is rebuilt.
Run from this directory:

```sh
endly -r=smoke endpoint=http://127.0.0.1:4987/mcp \
  bearerTokenSecret=/absolute/private/path/token
```

`smoke.yaml` calls the real MCP server and makes five assertions: schema version,
three supported source formats, and valid Calculator activation DSL. It does not
execute the desktop action. This is an API smoke test, not a Calculator result test.
The endpoint and credential reference are run parameters; never pass a token value.
This initial runner targets streamable HTTP with the stateless 2026-07-28 MCP
protocol. It does not yet support stdio or older stateful MCP servers. Failed tool
calls are not automatically retried; an uncertain external action needs outcome
inspection before any replay.

## Scy credentials for OOB authorization

For new credentials, provision a distinct random key in `MECHANIZE_VAULT_KEY` through your private key-management environment. Never put its value in workflow inputs, command arguments or logs. Create a private JSON input containing `Username` and `Password`, then secure it:

```sh
umask 077
scy secure -s=/private/path/basic-input.json \
  -d=/private/path/oob.sec.json -t=basic -k=blowfish://env/MECHANIZE_VAULT_KEY
```

For a confidential OAuth client, separately secure its OAuth configuration:

```sh
scy secure -s=/private/path/oauth-input.json \
  -d=/private/path/oauth.sec.json -t=oauth2 -k=blowfish://env/MECHANIZE_VAULT_KEY
```

Use the actual Scy Go JSON contract: `ClientID`, `ClientSecret`, `RedirectURL`,
`Scopes`, and `Endpoint` with `AuthURL` and `TokenURL`. Basic and OAuth2 secure
types encrypt the password/client-secret fields; identifiers and endpoint metadata
remain readable. Remove temporary plaintext inputs after successful verification.

Authorize with file references, directing the token into a private file:

```sh
umask 077
scy authorize -a=OOB \
  -c='/private/path/oauth.sec.json|blowfish://env/MECHANIZE_VAULT_KEY' \
  -e='/private/path/oob.sec.json|blowfish://env/MECHANIZE_VAULT_KEY' \
  --tokenType=access > /private/path/access-token
```

Supply provider-required scopes/PKCE settings as appropriate. The provider must
support Scy's OOB flow. Credentials do not create an OAuth provider: the current
local Mechanize deployment uses an existing JWT verifier and token, independently
of these optional OAuth inputs. Scy OOB authorization against idp.viantinc.com was verified separately on 2026-10-02. This does not enroll that provider token as Mechanize authority. Existing enrolled legacy credentials retain their original key references; do not change their cipher reference without explicit re-encryption.

The runner's `oauth` option invokes Scy's authorizer directly. It is mutually
exclusive with `bearerTokenSecret`. Run the separate OAuth smoke workflow with:

```sh
endly -r=oauth-smoke endpoint=https://your-mechanize-host/mcp \
  'oauthConfig=/private/path/oauth.sec.json|blowfish://env/MECHANIZE_VAULT_KEY' \
  'oobCredentials=/private/path/oob.sec.json|blowfish://env/MECHANIZE_VAULT_KEY'
```

This template has not been run against a real OAuth provider. Configure
`oauth.scopes` and `oauth.usePKCE` for that provider when required.

## Calculator execution with generic DSL

Run `calculator.yaml` with the installed runner. It activates Calculator, computes
17 × 23, verifies each entry via native accessibility, then asserts 391. It requires
a user-approved control/observe grant and the enrolled Calculator static-text
reader. An existing permanent grant is resolved automatically.

```sh
endly-mcp-runner -r=calculator endpoint=http://127.0.0.1:4987/mcp \
  credentialResource=/absolute/private/path/token requestId=calculator-demo-001
```

The YAML envelope includes English goal/purpose and typed postconditions around
commands such as `calculator.window(title: "Calculator").getById("Seven", exact:
true).click()`. Directional marks in expected values reflect Calculator's actual
AX strings; they are not extra digits. The verified 2026-10-02 run completed in 8.0s.
`calculator-read.yaml` returns native text via `mechanize_operation_outputs`;
those explicitly requested outputs are ephemeral. Durable checkpoints/state use
the separate state tools. Do not infer durable recovery from live output storage.

## Session keyboard fixture (opt-in)

`session-keyboard.yaml` is a single sequential Mechanize script for the inert
`com.viant.mechanize.keyboardfixture` app. The fixture must already be launched
through Mechanize. Obtain `fixturePID` and `fixtureBirth` together from a fresh
`mechanize_capture_windows` row for that exact app instance; do not mix rows or
reuse a prior process identity. The workflow clicks `choose-folder` once,
verifies the sheet's `CancelButton` identifier and enabled state, explicitly
focuses `ListView` and verifies fresh `focused=true`, then sends `Cmd+Shift+G`
once. Its postcondition requires the `GoToWindow` identifier in the same
narrowed process.

This route requires the semantic native profile with `sessionKeyboard` enabled,
the fixture bundle in the user's native enrollment, and the normal exact observe
and control consent. `session-keyboard` is an explicit opt-in; ordinary
`targetedKeyboard` does not enable it. These prerequisites and a successful
fixture run do not qualify production applications or general Chrome keyboard
delivery. For read reconciliation, host config must separately enroll
`plan.effect.reconcile` for the click/key expected-state predicates and
`native.focus.v1` for focus; these contracts do not prove absence or authorize
input replay.

The first live attempt stopped on `choose-folder`: AXPress returned `-25204`.
A subsequent fresh observation found the folder sheet and reported ListView
settable but not focused; no session key was sent. The source workflow now
contains the explicit focus step. That earlier immutable run was not edited or
replayed, and this updated workflow has not been run yet.

Supply the endpoint, a private secure credential reference, a unique request ID,
and the two values from the fresh discovery row:

```sh
endly-mcp-runner -r=session-keyboard endpoint=http://127.0.0.1:4987/mcp \
  credentialResource=/absolute/private/path/token \
  requestId=session-keyboard-demo-001 \
  fixturePID="$MECHANIZE_FIXTURE_PID" \
  fixtureBirth="$MECHANIZE_FIXTURE_BIRTH"
```

Set `MECHANIZE_FIXTURE_PID` and `MECHANIZE_FIXTURE_BIRTH` from the same fresh
discovery row before running; the sample does not hard-code a process identity.

Only `mechanize_operation_status` is polled after the single script submission;
that polling does not repeat input. If either action, postcondition, or runtime
completion is uncertain, inspect and reconcile the original operation before
any new action. Never blindly replay an unresolved session-keyboard attempt.
