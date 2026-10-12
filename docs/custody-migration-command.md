# Packaged custody migration command

The source entry is `cmd/mechanize-custody-migration`. It accepts no arguments,
loads no environment-selected enrollment, and writes no diagnostic text to
stdout/stderr. Stdin/stdout must be inherited pipes carrying only the existing
closed bootstrap/operation protocol. Descriptor 3 must be the connected Unix
stream to the signed native console. Descriptor 4 is a separate readiness pipe:
one non-consuming fd-3 receive must return EAGAIN before the worker writes the
fixed `MMREADY1` marker and closes fd 4. This establishes the inherited socket
endpoint's current kernel peer/audit identity without consuming credentials.
The launcher requires marker plus EOF, then exact child PID and signed peer
verification before sending any credential bytes. The worker independently verifies that
socket's exact console signature and UID before loading verifier resources,
then verifies the existing Scy admin credential through the dedicated binary
channel. No argv/JSON native-human claim creates authority.

`RunPackagedCustodyMigration` consumes the linker-embedded enrollment, checks the
current executable's validated Security.framework identity, and requires the
exact `com.viant.mechanize.custody-migration` writer role. Its own cdhash is
obtained from public validated signing metadata. Embedding its own hash before
signing would create a circular dependency; the launcher instead independently
pins the resulting signed artifact's exact requirement.

The signed enrollment contains version 1, fixed session, config path/digest,
resource path/digest list, console requirement, expected UID, namespace/client,
canonical broker executable, old/new requirements, alias/service/account,
private journal root, and optional original item reference for reconciliation.
It contains no credentials or keys. The encoding is canonical JSON in the field
order of `migrationPackagedEnrollment`, wrapped in strict standard base64.

The existing broker configuration is read through owned private descriptors
and matched to its signed SHA256. Its `keys` and `identityPolicy` are retained.
Every referenced verifier key must be an enrolled canonical local file with its
own signed digest. All path components reject symlinks; the immediate directory
must be owned 0700 and each file owned 0600, regular and single-linked. Identity,
metadata and digest are checked around the read. Scy receives those pinned bytes
through `Resource.Data`, avoiding a second path-based read. Errors remain static;
resource/config/key bytes never enter protocol replies or logs.

Current support covers existing unencrypted local HMAC/RSA resource files,
including verifier rules. Remote, environment-selected, encrypted, fallback,
inline and certificate-URL resources fail closed. This does not authorize a
credential or policy replacement to work around an unsupported resource.

After authenticated bootstrap, the entry constructs the console approval
transport against the trusted journal root. It attests the already approved exact
transition; it does not request another approval or infer approval from admin
identity. Reconciliation mode cannot prepare or commit. The command and parent
both enforce a 240-second process lifetime; uncertain writes stay unknown.

## Packaging without execution

`scripts/build-custody-migration.py --enrollment REVIEWED_METADATA.json
--output-directory NEW_PRIVATE_DIRECTORY [--signing-identity EXISTING_SHA1]`
compiles the frozen metadata into the worker, signs and verifies it, and writes
its exact requirement and binary/enrollment digests to a private manifest. It
never launches the worker, reads referenced verifier resources, or modifies a
Keychain item. No packaging or installation was performed during source tests.

## Remaining integration and qualification

### Authenticated package selection

The console now has `MigrationSignedPackageSource`, enrolled through the signed
Info.plist fields `MechanizeUpgradeReviewPublicKey` (canonical base64 Ed25519
public key) and `MechanizeUpgradePackagePath` (external absolute package path).
`build-app.sh` accepts the corresponding `MECHANIZE_UPGRADE_REVIEW_PUBLIC_KEY`
and `MECHANIZE_UPGRADE_PACKAGE_PATH` variables before signing. Both must be
present together. The package cannot live inside the console bundle.

The external JSON envelope has exactly `version: 1`, `payloadBase64` and
`signatureBase64`. The signature covers the UTF-8 bytes
`viant.mechanize.runtime-upgrade-package.v1`, a NUL byte, then the exact decoded
payload bytes. The payload is the closed reviewed upgrade package, including
worker pins, frozen plan and observer enrollment. Credential values and the
private signing key must never be included. Signing authority is enrolled by
the existing trusted installation/review channel, never by a website or package.

This separates the dependency order: sign the approval console with its public
review key, bind workers to that console, then sign the completed package.
Selection re-reads and re-verifies the signature on Upgrade; changing the
selected payload cannot reuse its approval. Missing enrollment keeps selection
unavailable. Reading is bounded and rejects symlinks, nonregular files,
nonprivate ownership/modes, hard links and replacement during the read.

These are source changes, not a deployed custody migration. The installation
still needs review-key enrollment, a signed package, observed live provenance,
and process shutdown after capture before installer execution. The unchanged
observer freshness bound is thirty seconds. Neither package authenticity nor
unit tests prove a successful real Keychain transition.

`scripts/sign-runtime-upgrade-package.py --payload REVIEWED_JSON --private-key
PRIVATE_ED25519_PEM --output NEW_EXTERNAL_ENVELOPE` produces that signed envelope
with local OpenSSL. The key and output are rejected inside Git sources; files
must be private owned regular files and the output parent must be private.
The signer reads no Vault key or website credentials, performs no installation,
does not create approval, refuses to overwrite an existing package, suppresses
private signing diagnostics, and never requests a key password interactively.
The independently enrolled review public key must match the signing key.

The installed console/coordinator must still construct reviewed enrollment from
the existing authenticated installation, bind the current exact approved
transition, pin/launch this artifact with fd 3, serve credential and approval
frames, and drive the existing bootstrap/prepare/verify/unknown-journal/commit
protocol. Placement locking, binary/config staging and reconciliation remain
owned by the existing coordinator. The new command does not create an upgrade
bypass. Signed end-to-end execution and a real custody transition remain
unqualified by these source tests.


## Native-console launcher source

`MigrationWorkerLauncher.launch(manifest:credentials:authorization:)` is the
main-window-owned Swift entry. The reviewed typed manifest binds a private owned
0700 executable and directory, exact SHA256 and exact custody-writer code
requirement. Descriptor/ancestor checks surround signature verification and
`posix_spawn`. The launch has no arguments or inherited environment; only private
stdin/stdout, suppressed stderr, fd 3 socketpair and fd 4 readiness pipe survive.
Readiness is bounded to ten seconds and never substitutes for `SignedBrokerPeer`.

The returned `MigrationWorkerSession` exposes typed `bootstrap` and `exchange`
operations with bounded canonical Go-compatible frames, request/session binding,
a finite request count and a phase machine. Unknown commits allow inspection,
not another commit. `commitMayHaveDispatched` is a conservative dispatch latch;
a terminal reply remains the source of result classification. Cancellation
shuts down credential IO, stops the one owned child and reaps it without signaling
a recycled PID. The original authorization deadline caps lifetime at 240 seconds.

Invoke launcher/protocol work off the main UI thread and retain the session
through its terminal reply. No new window or approval prompt is created. Hooking
this typed launcher into the main-window coordinator remains integration work;
synthetic process tests do not qualify a live Keychain transition. The extension
rollout separately needs the actual Chrome-loaded unpacked directory; copying an
assumed canonical folder does not prove the loaded path or preserve its ID.

## Signed transport fixture, 2026-10-06

A disposable signed console and packaged signed worker completed the real
Security.framework peer checks, private synthetic Scy credential verification,
canonical bootstrap and a `close` receipt. The credential provider was read
once. The fixture used independent private resources and performed no prepare,
commit, Vault key read, ACL change or installed-runtime replacement. It proves
the signed transport path; it does not qualify custody migration or native
authorization-record creation in the main window.

The fixture also exposed two integration details. On macOS the child must make
the single non-consuming no-data receive before emitting fd 4 readiness so the
parent's audit-token check identifies the child. Existing physical `/private/tmp`
artifact paths must be validated lexically before descriptor-based custody:
Foundation may standardize them into the `/tmp` symlink alias. Neither fix removes
the exact signature, peer, digest or `O_NOFOLLOW` checks.

## Assemble a reviewed runtime upgrade package

`scripts/package-runtime-upgrade.py` produces the installer, read-only preparation
worker, frozen Go install plan, reviewed package payload and signed Ed25519
envelope. It consumes already staged signed broker/helper/native-host and
candidate-console artifacts from the digest-pinned development build manifest.
It does not launch those artifacts, inspect installed runtime files, load config
or credential resources, grant approval, or install the package.

The current producer supports `preserve-extension-v1`. Its closed reviewed input
has exactly `version: 1`, `title`, `stagedManifest: {path, sha256}`, `enrollment`,
`installPlan` and `observer`:

- `enrollment` has the existing custody builder's required public metadata fields:
  `version`, `session`, `config`, `resources`, `consoleRequirement`, `expectedUID`,
  `namespace`, `clientID`, `canonicalExecutable`, `oldRequirement`, `newRequirement`,
  `alias`, `service`, `account`, `journalRoot`. Config/resources are only path/hash
  references. The console requirement pins the independently enrolled approval
  console, not a package-generated approval.
- `installPlan` uses the Go plan fields shown in the shared synthetic
  `testdata/runtime-upgrade-plan-v1.json`, except `brokerCandidate` is omitted.
  In `runtime`, omit `NewBrokerRequirement`; each artifact row contains only
  `role`, `target`, `Old`, `OldDigest`, `OldRequirement`. Supply exactly helper,
  native-host and console. `readiness` contains only `launchd: {path, sha256}` and
  `listen`. All NEW inventories, candidate paths, digests and requirements are
  computed from verified staged artifacts; caller NEW claims are rejected.
- Preserved-extension metadata includes its unchanged path, extension ID and
  digest-covered public resource inventory. There is no storage digest and no
  profile/storage read. The installer independently checks that the reviewed
  metadata still matches the live installation after native approval.
- `observer` has exactly `port`, `brokerPID`, `brokerStart`, `brokerRequirement`,
  `credentialURL`, `credentialSHA256`, `windowTitle`, `chromePID`, `chromeStart`.
  These are reviewed references, never claims of current process readiness.

Use a new output directory under a private 0700 directory outside Git:

```sh
python3 scripts/package-runtime-upgrade.py \
  --review /private/review/upgrade-metadata.json \
  --output-directory /private/review/package-001 \
  --private-key /private/review/review-key.pem
```

The optional `--signing-identity` selects the existing code-signing certificate
for both workers. Child build/sign diagnostics are withheld. The producer first
verifies artifact digests, exact role signatures and the candidate console's
reverse broker pin. It freezes the canonical Go plan, builds the installer bound
to that exact plan, then builds the preparation worker bound to the resulting
installer executable/hash/requirement. It rechecks staged artifacts before
calling the existing envelope signer. Workers are built, signed and verified;
a manifest-only placeholder cannot complete assembly.

The approval console must already carry the independent review public key and
package path in its signed enrollment. That independent key pin breaks the
console/package hash cycle. Copying a package or its own digest does not enroll a
review authority. `signed-package.json` is selectable metadata, and the native
Upgrade action still performs preparation, human approval, live identity checks,
credential admission, placement and recovery. Failed assembly leaves its private
output directory for inspection; it never retries installation or overwrites an
existing package.

The Python producer tests and Go `TestRuntimePackageProducerCanonicalGolden`
share the fixture to check exact struct order, sorted inventory keys, omitted
preservation fields and inventory digests. Fixture build/sign seams do not claim
that a real signed package or runtime upgrade was performed.
