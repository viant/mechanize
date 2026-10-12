# Local Vault

## Scy typed secrets (source contract)

The native type picker follows Scy's `-t` choices: `raw`, `basic`, `sha1`,
`aws`, `ssh`, `generic`, `jwt`, `oauth2`, `key`, `certificate`, and `x509`.
The private Go adapter resolves actual types with `cred.TargetType`; it does not
import Scy's command package or run its environment/filesystem initialization.
`x509` aliases `cred.Certificate`. `azure` is also accepted by Scy's type API,
but is not a CLI picker choice in the pinned release.

All fields below, including the type marker, remain **inside the existing
encrypted MVLT v2 record**. There is no new envelope, master key, plaintext
getter, or automatic migration.

| Type | Encrypted record fields | Scy primitive |
| --- | --- | --- |
| `raw` | `$scy.type=raw`, `secret` (nonempty raw bytes) | Raw payload |
| `basic` | `$scy.type=basic`, lowercase `username` and `password`; optional lowercase `endpoint`, `email` | `cred.Basic` |
| `key` | `$scy.type=key`, `Key`, `Secret` | `cred.SecretKey` |
| Other supported types | `$scy.type`, `$scy.payload` (JSON object matching the concrete type) | `SHA1`, `Aws`, `SSH`, `Generic`, `JwtConfig`, `Oauth2Config`, `Certificate`, or `Azure` |

Basic deliberately has no duplicate JSON payload. The currently installed
pre-adapter consumer can use its existing lowercase username/password fields;
a console-only UI update can therefore add typed Basic entry without changing
the broker's signing identity or current key custody. Old untyped credential
pairs and generic record inventories remain readable. The new Go typed-write
validation described here is source work, not a claim that it is deployed.

The new adapter rejects unknown types, mixed field representations, malformed
or duplicate JSON keys, wrong field types, and unknown structured fields. Only
`basic` can enter browser credential delivery, under reusable control consent,
exact ciphertext revision, and the exposure barrier. Other types are stored
privately; validation never follows credential paths, makes network requests,
sets environment variables, or calls Scy's cipher/load methods. No Scy target
or secret value is returned through MCP. Errors and receipts remain static or
opaque. Owned byte buffers are wiped after use; Scy's Go string fields are kept
local and cleared, without claiming secure erasure of immutable GC allocations.

## Reusable consent for browser credentials (source contract)

`CredentialPrepare` privately selects exactly one saved typed Basic record whose
encrypted `endpoint` equals the requested canonical HTTPS origin. One optional
trailing slash is accepted; paths, queries, userinfo, alternate ports and other
origins cannot widen the binding. Record names do not select credentials. Missing
or ambiguous matches return the static `needsConfiguration` state.

The authenticated actor needs an existing reusable control grant. The host checks
that real grant before resolution and again whenever the revision-bound private
capability is used. A caller-supplied consent binding alone is never authorization.
There is no per-use record approval or native record-selection step. Native entry
and administration remain required to create, modify or delete secrets.

Resolution decrypts only locally, wipes owned plaintext buffers, and returns no
credential values or record names. Delivery still checks the exact ciphertext
revision, client, namespace, session, browser document, grant revocation, expiry,
MFA/challenge state and durable unknown-effect/privacy barriers. Expired in-memory
preparations may be retired only if no protection, preparation or input attempt
was ever established. Expiry does not permit replay of an unknown effect.
These changes are source-tested; deployment is a separate qualification step.

## Current host follow-up — October 5, 2026

The signed native credential console is installed on the qualification host.
Its local Keychain master-key readiness and encrypted credential inventory checks
pass. Protected-entry and credential CRUD qualification remain open; an enabled
Create button is only readiness evidence. Earlier source-only and unprovisioned
statements below describe historical fixture stages.

Generic secret storage now has a separate source backend: `RecordStore` stores an
arbitrary key and up to 32 named byte fields. Keys, names and values are encrypted;
metadata contains random opaque record IDs and ciphertext revisions. Native-human
CRUD, lookup and inventory reuse the enrolled cipher/version. No plaintext getter,
public consumption API, migration or additional master-key generation is provided.
The race suite covers encryption, namespace isolation, revisions, tampering,
one-shot buffers and filesystem custody. Go and Swift MVLT v2 codecs match the
same fixture. The source native admission service and dedicated signed socket
route check readiness/protection before the first binary read and return opaque
metadata only. The source native form and binary client now support create,
complete replacement and delete. All key/name/value controls mount only after
protected-window confirmation, and detach before cleanup. The console compiles
and passes 120 tests, including independent operation/cleanup barriers. A
readiness or inventory refresh cannot clear an unacknowledged mutation. The
source console now persists protection and mutation flags, with an opaque
generation token, under `~/.secret/console-native-record-guard` before sending
admission or mutation. Matching acknowledgements clear only their own flags;
stale callbacks cannot clear a newer entry. Startup inspection is read-only.
The guard refuses unsafe permissions, symlinks, hardlinks, malformed/partial
artifacts and nonregular locks; writes use atomic rename and fsync. Its marker
contains no record identity or secret data.

This is source evidence only: live capture suppression, installed CRUD, physical
crash qualification and operation-specific reconciliation remain pending. A
storage failure cannot guarantee a newly written marker survives, and a user
with filesystem ownership can delete it. Neither refresh nor protection recovery
resolves an unknown mutation or authorizes its replay.

The installed broker is preserved because its existing Keychain master item
trusts that broker signing identity. Replacing the broker requires a qualified
key-custody/signing migration; neither deleting the key nor broadening its ACL
is an acceptable shortcut. Generic records are unavailable on the old runtime.

Storage identity contains no website or application. Approved usage bindings must
separately restrict delivery to a verified website, application or local consumer;
possession of a record reference does not authorize delivery. Bindings cannot
return values through MCP, workflow outputs, logs or LLM messages.

Host integration must explicitly select a separate private record root under
`~/.secret`, outside Git. The optional source configuration `nativeVault.recordRoot`
accepts only `~/.secret/vault-records`; absence preserves legacy behavior. Both
roots share the exact enrolled cipher and key version, protection gate and
guarded key-setup provider. Missing-key generation holds both custody locks and
refuses existing records. Shutdown joins native transactions before closing
host-owned stores. These additions have source tests, not installed acceptance.
Do not place records inside the existing credential root:
that inventory deliberately rejects unknown directories. Existing credential
files, references, native version-one frames and Keychain custody remain intact.

## Credential storage foundation

`Store` owns private encrypted files under an operator-configured root at
`~/.secret/vault` on this host; this implementation introduces no product database operations.
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

The source-only native input service now connects authenticated native-human
create/update/delete administration to the encrypted store under a trusted
`NativeEntryProtection.WithEntry` callback. No credential bytes are read before
authority, target and protection admission. The adapter must hold qualified
whole-window protection for the entire callback; a caller-provided readiness
boolean cannot supply it. Administration/acknowledgement failures after starting
are reported as unknown and require inspection, not an automatic replay.

Go and Swift share a dedicated binary pair frame: eight bytes `MVLT` followed
by version bytes `00 00 00 01`, then two big-endian uint32 UTF-8 byte lengths,
username bytes and password bytes. The combined payload is bounded to 64 KiB;
empty fields, NUL, invalid UTF-8, invalid versions, overflowing lengths,
truncation and trailing bytes are refused. The native transport must impose
read deadlines and close its write half after one frame. The service never
exports decoded bytes as JSON or printable values; Swift exposes only a
synchronous transport callback and sanitizes its errors. Buffer clearing limits
lifetime but is not a guarantee that Go/Swift/OS copies are erased.

Fixture evidence: the Go vault race suite and all 66 console tests pass,
including matching cross-language golden frames, no reads before admission,
reference-only replies, malformed input and lost-acknowledgement uncertainty.
This is not installed secret-channel or capture-suppression qualification.

Source now has optional HostOptions/native socket wiring and a dedicated Swift
client transaction. No MCP/DSL secret endpoint or entry UI is activated; the
installed runtime has no Vault service configured. Before enabling: register the exact local alias with
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

## Filesystem custody

Keep runtime ciphertext, master-key resources, locks, temporary writes, backups
and exports under the operator-owned private `~/.secret` tree, outside all source
checkouts. The host vault directory is `~/.secret/vault`, mode 0700; no master key
or real entry has been provisioned. The `vault/` repository directory contains
implementation and synthetic tests only.

`NewStore` refuses an ancestor `.git` directory, worktree/submodule `.git` file,
symlink marker or unreadable marker before creating storage. Existing-store reads
and writes recheck this policy. Ignore rules are defense in depth, not authority
to store credentials in a repository. Marker checks do not prevent a user from
concurrently running `git init`, moving directories into Git, exporting private
files or using source archives without `.git`; deployment must explicitly retain
the outside-source location. Native secure entry and live activation remain
disabled pending the gates above.

## Native socket transaction (source only)

The existing private Unix socket first verifies the console's signed audit/code
identity and Scy admin enrollment, then binds a connection session. Vault
create/update/delete methods accept only closed public routing metadata. The
optional trusted NativeInputService is separate from the generic JSON handler;
when absent, Vault requests fail without requesting credential bytes.

For create/update, the service's authority/target/protection admission precedes
its first read. A framed, ID-matched boolean nativeInputReady acknowledgement
then permits the Swift client to send the single binary pair and half-close its
write side. The server checks signed peer/Scy authority at credential reads,
requires EOF after the pair, and emits only a reference or static rejection.
The connection terminates after the transaction. Swift rejects numeric/string
readiness, unexpected keys and ID mismatch before sending secret bytes. A lost
final acknowledgement remains unknown and is not automatically replayed.

Source verification: vault/localrpc race suites, targeted host provider/consent
fixtures and 70 console tests pass. Socket fixtures use synthetic credentials,
explicit fixture peer verification and temporary encrypted stores; they are not
production signing, capture protection or real-user Keychain evidence. The
secure-entry adapter must acquire protection **before mounting fields**, not
merely rely on the submission acknowledgement. Key provisioning, real protection
lease implementation, UI adapter and installed/live qualification remain open.

## Shared exposure admission (source only)

`ExposureGate` now participates in the host's consent admission. Observation,
control, recording and retained capture permits hold exposure leases for their
whole lifetime. Entry cannot start while any such lease exists; approved native
and web operations are refused while entry exists. Failed operation admission
releases its permit. A host refuses an injected native Vault provider that does
not use this exact shared gate.

Entry submission and cleanup bind both the verified namespace and console
client identity. Retirement prevents further submission without releasing the
block. Cleanup must be verified by the trusted lifecycle provider; cancellation,
disconnect and failed cleanup never implicitly re-enable exposure. Tests include
the real Datly-backed consent lease path, native/web targets, all three consent
modes, denied admission, foreign clients and in-flight cleanup.

This gate is not a completed native window lifecycle adapter. Startup/restart
must also detect an existing protected entry window before admitting exposure.
The installed UI remains disabled until that lifecycle, master-key provisioning
and live synthetic-secret isolation checks are complete.

## Native entry lifecycle channel (source only)

`NativeEntryController` admits the shared gate before calling its trusted
`NativeEntryWindows.Prepare` provider. It issues a random opaque entry ID bound
to the verified console client and namespace. `vault.entry.begin`, `.confirm`, `.close` and
`.recover` use the signed/Scy-authenticated native socket, bypass the generic
handler, and accept only closed routing metadata. Credential transactions use a
separate authenticated connection and must name that owned entry ID; refused
requests never receive the binary-input readiness acknowledgement.

The lifecycle connection remains alive throughout native entry. Disconnect
retires submission while retaining exposure protection. A lost Begin response
can be recovered by the same console without knowing the lost ID, but only if
the independent native window provider verifies cleanup. A failed preparation
also retains the block unless that verifier proves cleanup. Neither a caller's
cleanup boolean nor a timeout releases protection. Host construction rejects
missing lifecycle providers and mismatched gates.

Begin authorizes an **empty** marked native window, not credential fields. The
console must create that window and call Confirm; the independent native
provider must see exactly one marked window with the expected opaque ID before
secret input becomes eligible. Only then may fields mount. A broker dying
between Begin and empty-window creation cannot produce a fresh Confirm, and a
broker restarting after Confirm sees the already-present window marker before
exposure. Failed confirmation retires entry and cannot be retried into an active
lease. Cleanup still requires independent closure evidence.

Socket tests exercise protected preparation, separate binary creation, missing
and incorrect IDs, closed-field cleanup refusal, disconnect and authenticated
recovery using synthetic window evidence. The Swift lifecycle client validates
exact entry-ID/boolean replies and treats mismatches or connection loss as
unknown protection; it closes its connection and never requests credentials in
generic JSON. All 73 console tests pass. These fixtures do not implement or
qualify the real macOS window verifier, startup reconciliation, Keychain master
provisioning or the installed secure-entry UI.

## macOS window verifier (source only)

`NewNativeWindowProtection` now creates a macOS implementation shared by entry
preparation, cleanup and every host exposure admission. Its private bounded
probe inspects only window roles and titles for `com.viant.mechanize.consent`.
It checks login UID, process birth before/after and the enrolled strict dynamic
code requirement. Unavailable AX access, failed IPC, wrong types, excessive
process/window counts or changed process identity refuse exposure. Only console
count, protected-window count and exact-marker match count leave the native probe; no window titles,
AXValue, children, clipboard or screenshot are returned.

The console must use `Mechanize Secure Entry ` plus the opaque 64-hex entry ID as
the fixed dedicated window title, never include account data in that title, and
clear/destroy entry fields before closing. This window contract is still awaiting
UI wiring and live qualification. The probe is compiled by the macOS race suite;
fixtures prove surviving-window refusal with no in-memory lease, restart recovery
refusal, unavailable-probe refusal, exact-window confirmation before input and
cleanup retention. They do not prove the
installed native UI or its Keychain custody.

## Key provisioning and readiness (source only)

`NativeKeySetup` composes create-only native broker Keychain provisioning with
the encrypted store's existing private write lock. Missing-key generation is
refused if any ciphertext, directory or unknown file exists; existing keys are
read/validated without replacement. `NativeInputService` checks cipher readiness
before the first credential read, and Begin refuses entry when its enrolled key
cannot be resolved. Fixture tests cover refused replacement, missing-key input
refusal and the private empty-storage case. Key generation and native ACL code
compile on macOS, but no installed Keychain item has been provisioned or tested.
The native-only status/setup endpoint accepts session metadata only and returns
an exact `keyReady` boolean. Host construction requires matching key setup,
input-store custody and entry lifecycle providers. Native Vault requests also
recheck host subject enrollment in addition to signed peer and Scy admin scope;
an unregistered subject cannot create keys or release credential bytes.

Native client tests cover exact boolean status, setup, denied/mismatched replies
and refusing secret-bearing extra keys. All 75 console tests pass. Runtime
provider configuration, UI wiring and actual installed native Keychain readback
remain unfinished; no real key or credential was created by these fixtures.

## Configured runtime construction (source only)

The host now accepts an optional closed `nativeVault` configuration containing
only `root`, `keyVersion`, `keyAlias` and `brokerRequirement`. Production
validation requires the exact `~/.secret/vault` root, the current login UID's
signed native console and a separately enrolled `com.viant.mechanize.vault`
Keychain item. Alias/version syntax, missing enrollment, broker pin disagreement,
inline key/credential fields and mixing configured/injected providers are refused.

After normal configuration validation and read-only Keychain provider
registration, the host constructs Scy's exact alias resource, encrypted store,
macOS guarded exposure gate, entry controller, input service and key setup. They
share the same gate and store. Construction generates no key and reads no
credential; native setup remains an explicit authenticated operation. The host
owns this configured store and closes it only after listener/runtime quiescence;
failed construction closes the opened store.

Validation and an isolated macOS constructor fixture pass under the race suite.
The fixture uses a private temporary root, never registers its Keychain alias,
and never calls readiness/setup. This does not prove installed provisioning or
the secure-entry UI. The managed runtime has not yet been updated with this
configuration, and native Create/Modify/Delete UI wiring remains unfinished.

## Native window controller (source only)

The console now has a dedicated `VaultEntryWindow` controller that uses an
authenticated lifecycle connection and separate one-shot binary transactions.
It checks key readiness, begins protection, creates an empty fixed-marker
window, obtains exact-window confirmation and only then mounts secure fields.
RPC executes off the main thread so the console can answer the independent AX
probe. The marker title contains only the opaque ID and is hidden visually.
Window sharing suppression is additional defense; the host exposure gate is
mandatory and is not replaced by `.sharingType = .none`.

Cancellation/close detaches fields before requesting independently verified
cleanup. Window close is refused during an active save. Failed/unknown save
removes fields and reports uncertainty, without offering a secret-input replay.
Save and cleanup outcomes remain distinct, including retaining a confirmed
opaque saved reference when cleanup is unconfirmed. Product text no longer
claims automatic workflow resume where no resume adapter is connected.

This controller builds and the 75 core console tests pass, but the tests do not
exercise its actual native window lifecycle. It is not connected to the Vault
tab yet. Credential inventory, target selection, Create/Modify/Delete tab wiring,
managed runtime installation and live synthetic-secret qualification remain.

### Retiring uncertain credential exposure

An unknown credential delivery remains unknown permanently; it is never interpreted as a successful login or automatically replayed. The host can retire its exposure protection only after loading an immutable, verified normal Chrome quit plan, independently checking that the original kernel process birth is gone, and obtaining current reusable control consent. Every child delivery must match that process birth. The generated CAS changes only protection to `retired`, preserves dispatch state and appends an audit revision. Ordinary cleanup and ordinary delivery producers cannot perform this transition. Live processes, changed plans, missing consent, mixed births and stale snapshots remain blocked. Schema 014 preserves existing rows and audits; migrating alone never retires a delivery. A new login requires a new process, preparation and attempt ID.
