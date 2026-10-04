# Scoped local Vault foundation (disabled)

`Store` owns private encrypted files under an operator-configured root such as
`~/.secret/vault`; this implementation introduces no product database operations.
If searchable metadata is added, it must use generated Datly v1 components.
File names derive from the verified namespace, exact HTTPS origin and opaque
workflow account alias. Username and password are both encrypted. Public JSON is
only `{"resourceURL":"mechanize-vault://credential/<namespace>/<digest>"}`.
The alias resolves locally, through the Vault backend and Scy's KMS/key resource
boundary; it is not a general filesystem or network Scy URL. No caller can select
a key locator, arbitrary file, fallback, another identity or another origin.

`Cipher` implements Scy `kms.Cipher` using AES-256-GCM, a fresh random nonce and
authenticated namespace/origin/account binding. Configure a fresh random 32-byte
master key per Vault outside scripts, database records and logs. Existing
`artifact.NewScyResolver` plus the explicitly enrolled `security/keychain` AFS
provider can resolve a Keychain JSON key resource. `ScyEnvKeys` is an explicit
alternative, using Scy's actual `kms.Key.Key` env support with 32 raw or base64
encoded random bytes. `ChildEnvironment` removes enrolled key variables; every
subprocess launcher must use it before enabling env custody. This slice does not
create a Keychain item, provision a master key, or alter any user's environment.

Scy's inspected `blowfish://default` is a compiled public eight-byte key, not a
salt. Its CBC encryptor uses a zero IV, zero padding and no authentication.
`blowfish://env/NAME` loads the environment value verbatim; `blowfish://mac`
derives an eight-byte FNV hash from active sorted MAC addresses. MAC addresses are
not secret key material and can change. A renamed public default is not a new
secure key. New Vault writes never use these modes. `LegacyResolver` can consume
only explicitly enrolled existing env/MAC Scy basic resources, with an exact
verified user/origin/account mapping and opaque public reference. Legacy CBC is
unauthenticated compatibility input; it is not automatically imported or promoted
to production security. Default-key legacy resources are refused by this Vault
adapter; separately authorized existing developer credential flows are unchanged.
`NewManagerWithLegacy` opts this exact enrollment map into the normal reuse path;
no scan, import or default-key fallback occurs.

`Manager.Ensure` verifies a fresh document binding and reuses an existing
credential. A miss immediately calls the trusted local `Present` adapter and
pauses with `ErrPending`. The native UI shows the exact site/account, uses two
`SecureField`s, and requires an explicit save. `Submit` accepts secret bytes only
from the existing signed native-human authentication boundary. Requests expire,
are single use, are isolated per verified user, and recheck navigation before
save and Endly continuation. Cancel and stale-document outcomes cannot replay the
input. `Consume` rechecks navigation and gives credentials only to a synchronous
local callback; buffers are cleared, formatting is redacted and callback errors
are sanitized. Go/Swift/Scy may retain runtime copies; this is not a promise of
locked secure memory.

## Activation gates

No host, MCP, DSL or native App tab is wired to this foundation. All runtime
features remain disabled. Before enabling: register the exact local alias with
the credential backend; implement a signed native-only secret submission channel
without generic RPC tracing; qualify native AX, screenshots/video, clipboard and
browser recording suppression for the whole secure-entry window; provision the
random master key and signed Keychain ACL; sanitize all subprocess environments;
bind `Fresh` to trustworthy session/profile/frame/document/navigation evidence;
apply credentials only to same-origin forms (reject cross-origin form actions,
frames and uncertain navigation); integrate the pause/resume hooks into Endly
durable intent/reconciliation. None of these gates are satisfied by a UI boolean
or unit tests. Local reveal is deliberately absent until authenticated platform
authorization and pixel suppression are implemented. No real credentials have
been collected, stored or imported by tests.

## Fixture evidence (2026-10-02)

`go test ./vault` and `go test -race ./vault` pass. Tests cover authenticated
native-human input, encrypted files, reference-only output, user/origin isolation,
tamper refusal, single-use resume, stale navigation, symlink roots, serialization
and formatting refusal, explicit Scy env resolution, subprocess env sanitization,
and existing Scy basic env-key decoding. `swift test` in `native/console` passes
56 tests and builds the unwired secure-entry view. No installed live acceptance
or master-key provisioning is implied by these fixtures.
