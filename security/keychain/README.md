# Enrolled Keychain resources

## Coordinated installer integration follow-up

The private native authority adapter authenticates an actual signed consent
console Unix peer and verifies its bounded binary Scy credential independently
of bootstrap JSON. Namespace, client and deadline are pinned and checked again
for every worker operation. No requester boolean supplies native-human authority.

Concrete private file staging now uses descriptor-based custody checks, exact
artifact modes, durable no-overwrite backups and native atomic exchange. The
actual displaced file is retained even if it changes at publication. Partial or
raced placement stays unknown; there is no deletion, rollback or plain-rename
fallback. Fixture tests exercise real temporary-file swaps without touching an
installation or a Keychain item.

`migrationInstaller` joins old-policy preparation, the separate staging journal,
canonical placement, bound approval and one ACL attempt, then both independent
verification phases. A verified ACL alone cannot complete an unknown file/readiness
transition. Reconciliation reads verified custody again and never places files,
approves or replays the ACL call. Different administrator clients cannot adopt
the prepared installation, and stage factories cannot substitute its item identity.

This is not an enabled upgrade command. Remaining integration includes the
packaged worker and verified console-to-helper credential sender, concrete bound
local approval, exclusion held across the whole file/ACL/readiness interval,
coordinated helper/console/native-host placement, migration-aware runtime startup,
and installed same-item/key-readiness qualification. The normal updater's
provisioned-master guard remains in force; no employee key or ACL was changed.

This project's `mechanize-keychain` scheme is implemented by a read-only AFS
`storage.Manager` registered explicitly through `keychain.Register`. Scy's
public `scy.New().Load` implementation uses AFS and therefore resolves this
provider without any Scy or AFS changes.

Trusted operator configuration supplies `Options.Items`, an alias map to exact
generic-password `Service` and `Account` pairs. `keychain.Reference("console")`
returns `mechanize-keychain://generic-password/console`. The URL selects only an
enrolled alias; service/account overrides, credentials, query parameters,
fragments, percent escapes, traversal, and resource storage options are denied.
Register before constructing consumers. Re-registration is denied. No global
automatic registration or general-purpose Keychain URL is provided.

Example enrollment uses service `com.viant.mechanize.console.enrollment` and the
operator's configured account. The item must already exist and authorize the
signed broker. This provider performs only `SecItemCopyMatching`, with
`LAContext.interactionNotAllowed = true`, no synchronization, and one exact
generic-password match. Missing, locked, or unauthorized items fail closed;
there are no permission prompts, Keychain writes, ACL changes, or secret logs.
macOS with cgo is required. Other builds return `ErrUnsupported`.

Tests inject a fixture lookup to prove Scy's actual provider dispatch and input
denials. They never read or write the employee's Keychain. Actual signed broker
Keychain access remains a separate enrollment integration gate.

## Native Vault master provisioning (source only)

The AFS provider remains read only. A separate `MasterKeyProvisioner` accepts
only trusted setup options and authenticated native-human authority. It verifies
the running broker's enrolled strict code requirement before inspecting or
creating its local generic-password item. A fresh 32-byte key is generated in
the broker and stored as Scy's local key payload; results contain only the
enrolled resource reference. Temporary Go payload/key buffers are cleared.
No caller-supplied key, file export, generic RPC body, update, delete, ACL rewrite
or automatic replacement is supported. Native framework/Go memory copies are
not claimed to provide secure-memory erasure.

Existing unreadable/invalid items and duplicate creation are preserved. A
failed final readiness check preserves a newly created key for later inspection.
The trusted Vault adapter holds the ciphertext write lock throughout setup and
refuses missing-key creation if encrypted or unknown files already exist.
Credential input now checks enrolled cipher key readiness before its first read.

The macOS implementation uses the SDK's legacy application ACL APIs to restrict
the item to its signed broker creator, with both explicit noninteractive policy
and failed authentication UI. Those APIs emit deprecation warnings on the current
SDK. Source compilation and synthetic race tests do not prove actual signed
broker partition/ACL access: installed creation and Scy readback remain a live
qualification gate. No real master key has been created by these tests.

### Verified master-item custody

Master provisioning and each later Scy/AFS read of the enrolled master item now
use the same custody verifier. The native query requests all service/account
matches and refuses ambiguity. It pins the single item's persistent reference,
checks the complete owner and permission ACL subjects against a newly constructed
policy trusting only the running broker, and reads that exact item. Added or
broadened permission entries, different signing subjects, unknown policies and
failed inspections are rejected. Only separate system partition/integrity
metadata entries are excluded from policy equality; an entry that also grants
ordinary permissions is never excluded. No ACL is rewritten.

The comparator uses the SDK's public, deprecated `SecAccessGetOwnerAndACL` API
because it exposes the actual signing-subject bytes. It deliberately does not
use `SecTrustedApplicationCopyData` as identity evidence: [Apple's implementation](https://github.com/apple-oss-distributions/Security/blob/main/OSX/libsecurity_keychain/lib/SecTrustedApplication.cpp)
returns its path/comment rather than the signing requirement. Temporary copied
ACL structures are released after inspection.

Creation returns the actual created item's persistent identity. Readback must
retain that identity and custody, and its decoded key must match the generated
key using a constant-time comparison. A mismatch preserves the item and returns
an uncertain failure; no key replacement, deletion or automatic retry occurs.
The provider's thread-safe master-reader registry supports provider registration
before Vault construction, refuses conflicting enrollment, and never falls back
to generic lookup after master custody is enrolled. Other enrolled items retain
their original read behavior.

This proves current policy equality and exact-item readback, not historical
creator provenance. Keychain item labels/creator attributes cannot prove who
originally generated an existing key. A user-authorized owner can still change
Keychain policy; this code does not claim to defeat that platform authority.
The strict policy comparison may reject a legitimate older item or an OS version
that transforms the policy differently. Such items remain untouched and require
explicit diagnosis. Persisted ACL round-trip behavior, installed broker access,
and Scy readback still require installed qualification. Unit tests use fixtures
and in-memory Security.framework policy objects only; none access the employee's
Keychain or create a real encryption key.


## Broker identity migration design gate

The qualification host has an existing usable master item and an ad-hoc,
exact-build broker identity. Its installed broker is preserved. The ordinary
provider and runtime updater still refuse a replacement identity; no migration
API or upgrade exception is enabled by this investigation.

The private `master_prepare_single_acl` helper prepares a copied access object
in memory. It refuses aliased expected-policy objects, verifies the complete old
policy, changes precisely one singleton decrypt-bearing ACL, and checks the
complete proposed target policy. It neither queries nor changes a Keychain item
and is not wired to a migration backend.

`TestNativeSingleACLMigrationPolicyWithoutKeychain` exercises in-memory
Security.framework access objects only. It establishes that replacing the
singleton trusted application in the existing decrypt-bearing ACL can match
the complete target policy while preserving the owner and other ACL entries.
It also establishes that identical signed executable bytes at a different
path do not satisfy the same complete policy. Together with the existing
comparator test, the targeted native policy tests pass on this host. They do
not search, read, create or change any Keychain item, or prove platform
human authorization.

A migration must preserve the same item, key and ciphertexts. A narrowly scoped
local utility would need the following sequence before any updater exception
is considered:

1. Verify frozen old/new build identities and the canonical installation path.
   Before replacing the old canonical executable, pin the unique item's
   persistent reference and verify its complete old policy using metadata only.
2. Quiesce the owned broker and all native transactions with existing checked
   deployment controls. Persist a private, public-status-only migration journal;
   do not store a key or credential payload. Installing candidate bytes is not
   evidence that Keychain migration completed.
3. At the final canonical path, verify the exact new signed bytes. Prepare a
   copied existing access object changing exactly the known singleton limited
   ACL via `SecACLSetContents`. Preserve its authorization tags, prompt selector,
   description, owner and remaining policy. Verify the complete proposed policy
   against the exact new identity before writing. A fresh `SecAccess` replacement
   or a staging-path policy is insufficient.
4. Obtain explicit local-human approval for that exact transition. Any platform
   authentication must remain in Security.framework's native UI; Mechanize must
   never collect a Keychain password. An interaction-enabled API call is not
   itself evidence of human approval.
5. Call `SecKeychainItemSetAccess` once. Independently reopen metadata and verify
   the same persistent item reference and complete new policy. Only then may the
   new broker perform its existing local readiness/readback checks. Do not return
   key bytes or credentials through the migration result.

Apple's implementation applies ACL entries individually; this is not an atomic
whole-policy transaction. A timeout, cancellation, crash, lost acknowledgement
or failed post-write check must preserve an unknown transition and block replay.
File rollback does not roll back a Keychain ACL. Reverse migration would be a
separate verified and human-authorized transition. Do not weaken the ordinary
custody comparator, trust both builds, delete/recreate the item, or modify Vault
ciphertexts to unblock deployment.

The public APIs are deprecated but present in the local SDK. Implementation and
live qualification remain open, including SecurityAgent authorization,
cancellation, exact-build subject restrictions, canonical-path sequencing,
partition metadata behavior and interruption recovery. See Apple's
[Access implementation](https://github.com/apple-oss-distributions/Security/blob/main/OSX/libsecurity_keychain/lib/Access.cpp)
and [signing subject implementation](https://github.com/apple-oss-distributions/Security/blob/main/OSX/libsecurity_cdsa_utilities/lib/acl_codesigning.cpp).


The source-only portable `migrationCoordinator` now separates preparation,
later candidate-verification checks, explicit bound local approval, single dispatch and
metadata-only reconciliation. It requires authenticated native-human authority
and a deadline. A private journal interface must persist the unknown transition
before dispatch and retain verified receipts; write or verification failures keep
uncertainty. Reconciliation requires the exact new policy and same persistent
item, and never replays or reverses a change. Results contain closed public status
only; backend errors and prepared policy handles are withheld.

There is no exported migration constructor or enabled item-write backend,
local approval transport or updater exception. The installer also needs a durable
file-staging journal before replacing canonical bytes; the coordinator's ACL
write-ahead barrier alone does not cover that earlier phase. These remain required
implementation and qualification work, not reasons to enable a bypass.

Validation: `go test -race ./security/keychain` passed after the coordinator and
in-memory policy preparation changes. The migration suite includes 15 test
functions plus table cases; fake backends cover ordered approval/write-ahead,
cancellation, identity substitution, competing coordinators, restart and unknown
reconciliation. This does not qualify real Keychain migration or installation.


### Durable journal and native metadata preparation follow-up

A private file-backed journal now implements the coordinator's persistence
interface at the trusted installer's enrolled
`~/.secret/mechanize-custody-migration` location. Its constructor and missing-root
reads create nothing. Private directories/files, descriptor-based ancestor and
entry checks, nonblocking process locking, canonical bounded metadata and atomic
synced writes protect the record. Matching unknown-to-verified transitions retain
a terminal receipt; unknown or partial artifacts refuse further use. A failed
write leaves a best-effort poison artifact and blocks the current instance. This
cannot guarantee persistence when storage refuses every write, nor prevent a
filesystem owner from deleting the journal. One retained transition per enrolled
root is supported; later migration history/reset is not implemented.

The private Darwin metadata adapter verifies canonical executable code pins,
uniqueness, persistent item identity and full policy. It holds an independently
copied old policy before canonical replacement, and can compare it to fresh item
metadata after candidate placement. Inspection checks the exact new policy at
that final path. It requests only item references and access metadata, never
key/credential data, enables no authentication UI and changes no Keychain item.
It deliberately has no commit method and cannot stand in for a write backend.
Security.framework IPC still requires a separately bounded native execution
process before live integration; a Go deadline cannot forcibly interrupt C IPC.

The combined `go test -race ./security/keychain` suite passes after these changes.
Sixteen journal test functions exercise private temporary fixtures, and the
native adapter tests reject missing code/untrusted context/foreign handles before
Keychain lookup. No tests inspect employee Keychain items or create a real
`~/.secret` journal. Actual metadata round-trip, isolated writing, local human
approval, installer file-staging persistence and live recovery remain open.


### Isolated writer source follow-up

The source now contains a native single-ACL write primitive. It first requires
its own running code to match an exact `com.viant.mechanize.custody-migration`
identifier/hash pin; the ordinary broker cannot satisfy that role. Candidate
pins are checked at the canonical path, and the candidate's designated
requirement must itself restrict access to the exact supplied rule or the same
ad-hoc singleton code hash. A broader designated requirement is refused even
when the file satisfies an external exact-build check.

The routine checks unique item identity and complete old policy twice, prepares
a fresh independent access copy, modifies one limited ACL, and verifies the
complete proposed policy before one `SecKeychainItemSetAccess` call. An atomic
attempt latch forbids a second dispatch. Platform interaction is restored to
noninteractive mode in `@finally`; any attempted failure or failed independent
new-policy/item check returns unknown. It reads no key or credential material,
creates/deletes no item, and performs no reversal.

The Go wrapper is private and intentionally is not a complete migration backend.
An isolated child protocol, authenticated parent, immutable bound human approval,
deadline watchdog and installer staging journal are still required before it can
be wired. Public Keychain APIs provide no transaction spanning external policy
changes, filesystem pins and the ACL write; cooperating runtime/installer activity
must remain excluded, and uncertainty must survive interruptions.

Writer identity tests use disposable ad-hoc-signed code. Every Keychain item and
interaction function in the positive-role fixture is replaced by an aborting
stub; the writer receives a nil snapshot. These tests establish exact helper-role
acceptance, ordinary-process refusal, narrow candidate acceptance and broad
candidate-DR refusal without Keychain lookup or native authorization UI. Combined
`go test -race ./security/keychain` passes. The real platform write path, local
approval and recovery remain unqualified; the installed runtime and key are
unchanged.


### Worker protocol and owned-process watchdog follow-up

The private worker protocol now uses bounded 32 KiB canonical frames and closed
prepare/verify/commit/inspect/close commands. Request bodies contain no options,
authority claims, approval tokens, passwords or policy handles. Only the private
prepare response carries a bounded opaque item reference. Trusted bootstrap binds
the options, session and executor pin. Authority is checked before the first read
and every action, and its initial namespace/client identity cannot change during
the session. A separate trusted callback must attest the exact human approval
and synced uncertainty record before commit. Nothing derives NativeHuman
privileges from request JSON.

The source owned-child transport requires trusted file and running-process
verifiers, bounds total lifetime and each exchange, sanitizes inherited
environment, discards stderr, validates reply/session IDs and refuses replay.
A stalled call terminates only its spawned child and retains uncertain commit
status. The installer can explicitly wait for that child's exit; process exit
alone never establishes the Keychain result. Private pipes are parent-owned so
waiting for child exit does not prematurely close unread response bytes.

Worker and process tests use fake executors and owned protocol fixtures, not
Keychain operations or Office automation. No production command/bootstrap,
concrete peer-signature verifier, bound local approval interface or installer
integration is enabled. A verified isolated helper launch, actual native
cancellation/UI behavior and migration recovery still require live qualification.


### Concrete verifiers and coordinator proxy follow-up

Concrete private Darwin callbacks now bracket static code verification with
NOFOLLOW directory/file descriptors and custody checks. They require an owned
private artifact directory and exact migration-helper signature. Running-process
checks pin the owned process object, PID, UID, canonical executable and birth
token before and after dynamic code verification; a failure cannot adopt a new
process. Construction alone inspects or launches nothing. Public code-only
fixtures exercise matching signatures and rejection of altered code, wrong
paths/roles, exited processes and changed birth tokens without Keychain calls.

The private process backend now links the coordinator to framed prepare,
verification, one commit attempt and fresh metadata inspection. Its trusted
launcher must bind options, expected item identity, session and helper pin through
a verified bootstrap. The coordinator proxy tests use owned protocol fixtures:
they demonstrate ordered write-ahead/verification, retained unknown state after
stall, and refusal of replay or foreign handles; they do not establish a real
Keychain migration. Combined race tests pass.

Verified parent bootstrap, actual bound approval transport, packaged worker entry
and installer file-staging integration remain absent. The proxy and signature
callbacks do not enable a production launch or bypass the existing upgrade
refusal. Original Vault/Office files and installed runtime are preserved.


### Authenticated bootstrap and file-staging barrier follow-up

The private bootstrap loader now requires independently supplied frozen options,
config digest, parent pin, session and worker pin. Authority is authenticated
before reading and after decoding; namespace/client continuity and the shorter
trusted deadline are retained. Every decoded metadata field must match that
reviewed enrollment. Credential payloads, scope/role claims and approval tokens
are rejected. The loader returns copied trusted configuration, never authority
promoted from JSON. Actual peer/admin authentication transport still requires
integration; these loader tests use fake authority only.

A separate private staging controller now writes uncertainty before canonical
file placement through checked installer hooks. It uses
`~/.secret/mechanize-runtime-staging`, separate from the ACL journal, with the
same private-file/process-lock/fsync protections. Its metadata binds the old/new
binary and config hashes, immutable migration options, transition ID and original
item identity. Successful placement alone leaves the transition unknown. Restart
cannot replay placement; full fresh file/config, same-item/new-policy and local
readiness verification is required before the terminal receipt is retained.
Backend hooks receive copied metadata so they cannot mutate the controller's
saved item identity. No actual file moves or runtime startup are wired here.

Combined race tests pass after synchronizing channel-state observations in the
bootstrap/worker test fixtures. Bootstrap and staging fixture tests inspect no
employee Keychain items and modify no installed files. Packaged entrypoint,
concrete authenticated parent bootstrap, local approval UI, checked file placement
and live migration/recovery qualification remain open.

### Concrete private native authority adapter

`migration_authority.go` now supplies `newMigrationNativeAuthority` for a dedicated
Unix connection whose actual peer is the exactly pinned native consent console.
The production factory compiles `nativepeer.NewVerifier`; it does not accept a
caller-supplied peer verifier. Trusted enrollment pins UID, code requirement,
namespace, client ID and a deadline of at most four minutes. Before any bootstrap
metadata reads, `authority.authenticate` verifies the socket peer, receives one
bounded binary `MMAUTH` credential frame on this separate channel, then rechecks
peer identity and the existing Scy verifier's `consent:admin` principal. Only that
sequence establishes NativeHuman. Credentials never enter bootstrap/worker JSON,
public results, formatting or logs. Each worker authority call revalidates peer
and credential, and any mismatch closes the connection and clears retained bytes.

Private wiring is explicit: construct the adapter with the actual console socket,
trusted enrollment and existing `*auth.Verifier`; pass `adapter.authenticate` to
`newMigrationBootstrapLoader` and `adapter.workerAuthority` to `newMigrationWorker`;
close the adapter when its bounded operation ends. Keep metadata/worker frames on
the existing private channel. Native console code must verify the migration
helper before sending the separate credential frame, as it does for existing
broker transports. An inherited pipe, arbitrary signed installer or wire-provided
role is not a substitute for this direct signed-console socket. A broker acting
on the console's behalf would need separately authenticated delegation and is not
admitted by this adapter.

Synthetic Unix-socket fixtures exercise pre-read refusals, repeated peer/admin
checks, namespace/client/scope/credential changes, bounded deadlines, cancellation,
JSON rejection, private formatting and bootstrap-to-worker continuity. These tests
perform no real Keychain access. The native console sender/listener integration,
exact operation-bound local approval transport and production migration entrypoint
still need wiring; this adapter alone enables no ACL write or updater exception.
