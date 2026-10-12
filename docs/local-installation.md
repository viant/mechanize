# Local development installation

Run `python3 scripts/install-development.py` from this checkout on macOS after
`scripts/build-development.py` has produced a signed development manifest
(ad-hoc by default, or an explicitly selected existing certificate).
This is a local development installation, not a production-qualified release.
The installer verifies broker/helper SHA256 values and the exact code requirements
of all three artifacts before and after copying. It rejects symlink paths and
bundle entries, installs into a new private per-user directory, and leaves existing
production and development files intact. No broker or console is launched.

Files live under `~/Library/Application Support/Mechanize/development/<unique-id>`.
The output report names the installed broker, helper, console, and `config.json`.
Directories are mode 0700; config, reports, and credential resources are mode 0600.
The shared console endpoint is fixed by the app at
`~/Library/Application Support/Mechanize/runtime/consent.sock`; an existing unsafe
parent directory causes setup to fail rather than changing its permissions.

The config uses the checkout as Datly source root and an isolated storage root.
It enrolls the local UID as a single user, with separate development-agent and
permissions-console client identities. New developer installs select a desktop-wide ceiling; per-app restrictions remain optional. Actual backend support and native session consent are still checked. The installer itself changes no macOS privacy permission or employee input.

The installer generates a fresh 256-bit HMAC verifier key, a fresh 256-bit artifact
key, and separate signed HS256 JWTs expiring after 24 hours. Scy resources point to
absolute private files: the HMAC file is base64 text, the artifact file is JSON
with a base64 `key`, and the stdio credential file contains only the JWT. Credentials
never appear in command arguments, output, or inline config. No existing personal
secret store is read. Protect the entire private installation: its owner can mint
new development credentials using the verifier key.

The console JWT has `desktop:observe consent:admin`; the agent JWT has
`desktop:observe desktop:control`. The native enrollment helper receives console
credential bytes on stdin, verifies the installed console's exact signature, and
adds generic-password service `com.viant.mechanize.console.enrollment`, account
`com.viant.mechanize.consent:<uid>:<build-id>` from the signed console metadata (legacy builds used the unsuffixed account). Public Security APIs constrain secret access
to the installed console through an explicit trusted-application ACL. Keychain
interaction is disabled. Existing items, including expired or production enrollment,
are preserved and cause a reported refusal; the installer never updates or deletes
an item or broadens its access. Locked or inaccessible Keychain state is reported
truthfully. A second install therefore may copy files while console enrollment
remains unavailable; consult `setup-report.json` before using the console.

`native/enrollment/audit.swift` inspects ACL metadata without requesting password
data. Successful enrollment records `enrollment-acl-audit.json` and checks that
secret-reading ACLs name only the installed console. macOS also creates metadata
and encryption ACLs; those do not authorize credential decryption. This audit does
not prove that a later explicit Connect action can read the item or that macOS
permissions are granted. The report distinguishes item creation and ACL verification.

Use the reported config when explicitly starting the installed broker. Use the
installed helper with the broker's nonprompting `doctor -helper <path>` command.
Do not rebuild in place and assume trust remains valid: exact ad-hoc hashes pin
this enrollment to these copies. Expired or replaced console enrollment requires an
explicit reviewed removal/rotation workflow, which this installer does not perform.


## Actual installation and permissions, 2026-10-01

The developer installation is at `/Users/awitas/Library/Application Support/Mechanize/development/20261002T034524Z-89d66cc8`. Its broker was started on `http://127.0.0.1:4987/mcp` and read-only authenticated discovery passed (26 tools); unauthenticated requests returned401. The permission app was opened; its Connect action and signed broker authentication remain to verify. Credentials expire after24hours and are never included in this document.

Applied setup: per-user private files, exact ad-hoc signature pins, and a new native Keychain item whose secret-read ACL names only the installed permission console. No root action, macOS privacy grant, Gatekeeper bypass or desktop input was applied.

The installed helper reports capture access available, Accessibility and event posting unavailable, and input monitoring unavailable. Control remains disabled and production identity/active graphical session qualification are false. These are actual nonprompting doctor results, not claims that capture or input has been qualified live. macOS privacy approvals must be made by the human in System Settings; root does not substitute for them.

Recheck authenticated discovery without exposing credentials:

```sh
python3 scripts/smoke-development.py --credential '/Users/awitas/Library/Application Support/Mechanize/development/20261002T034524Z-89d66cc8/credentials/stdio.jwt'
```

The broker currently runs as an owned development tool process rather than an installed login service. Reboot/login persistence and coordinated signed upgrade remain packaging gates.


## Current state after live permission setup

The user authenticated the macOS Privacy & Security prompt and the installed helper was added through the normal Accessibility picker. The live doctor now confirms Accessibility, event posting, Input Monitoring and capture access available. No TCC database was edited. The desktop-wide semantic development profile uses AX actions and keeps raw keyboard/pointer input disabled. These permissions do not imply production qualification or a completed Calculator/Finder demonstration.

A rebuilt panel uses a separate signed per-build Keychain account; the previous item is preserved. Current enrollment is waiting in the standard macOS Keychain authorization process for `enroll-console-interactive`. The computer-use tool refuses access to SecurityAgent, so the human must handle that protected dialog. Secure Input is currently enabled while the prompt is open; semantic action admission therefore remains inhibited.

The stopped first helper generation was reconciled using an exact namespace/generation query through a generated Datly read-only component and independent public process-stop inspection. The existing ledger proved no dispatch intents; the fence was released without input or replay. A missing/corrupt database or any intent cannot justify this reconciliation.

### Reviewed Chrome recovery metadata

`python3 scripts/prepare-runtime-upgrade-review.py --input PRIVATE_INPUT --output-directory NEW_PRIVATE_DIRECTORY`
produces private `review.json`, `candidate-config.json`, and `readiness.json` for
`package-runtime-upgrade.py`. Both input and output must be outside Git. This
only prepares metadata; it does not install, approve, open Keychain, or establish
browser readiness. The helper derives old artifact inventories and actual
verifier resource digests rather than accepting caller inventory claims.

The closed input contains `version:1`, `title`, `installationRoot`,
`stagedManifest:{path,sha256}`, `approvalConsole:{path,requirement}`,
`processes:{broker:{pid,start},console:{pid,start},chrome:{pid,start}}`,
`extension:{path,extensionID,windowTitle}`, `observerCredential:{path,sha256}`,
`consentBinding:{sessionID,purpose,grantID?}`, `keychain:{alias,service,account}`,
`identity:{subject,tenant,clientID}`, and `launchdPath`. The observer resource must
already authenticate as the client owning that session and its approved read
consent. The signed package carries this binding and the reader sends ordinary
`sessionId`, `purpose`, and optional `grantId`; the live Host checks them again.
No native-human identity is synthesized by the observer.

Optional `chromeRecovery:{path,sha256}` references the retained full original
configuration. The current configuration must equal it exactly except for an
absent `chrome` field. The signed runtime plan binds both files and a canonical
Chrome-subtree digest. The candidate restores that subtree with only the reviewed
Chrome requirement and new native-host pin changed. The installer independently
checks the same relationship. Chrome recovery requires Apple's signing anchor,
Google team `EQHXZ8M8AV`, identifier `com.google.Chrome`, and an exact union of
all signed architecture CDHashes. A single architecture's hash is insufficient
for a universal binary. Old browser connection or permission claims are not
borrowed from the retained configuration.

Optional `enableRecordStore:true` adds `~/.secret/vault-records` only when the
original `nativeVault.recordRoot` is absent or empty and its existing root is
`~/.secret/vault`. All other Vault identity, key metadata, users, resources, and
grants remain unchanged. No existing plaintext/origin records are imported.

The Chrome image verifier alone permits macOS's OS-resolved `admin` group write
bit, with independent Google signature verification, exact enrolled pin,
stable physical-image metadata, and dynamic process identity checks. It rejects
world write, other writable groups, copied replacement images, and symlinks.
Broker, helper, and native-host executable permissions remain strict. The
preserved extension is inventoried read-only; profile/storage are never read or
written by this producer. Deployment still requires the signed native review,
live observer consent, custody checks, shutdown proof, and post-install checks.

The signed console's `--check-runtime-upgrade` diagnostic selects only its
independently signed, bundle-enrolled package and captures a fresh preservation
observer receipt. It accepts no additional arguments. Its JSON contains exactly
`qualified`, `stage`, and `errorCode`; failures never print paths or underlying
errors. This path runs before normal console configuration, performs no Keychain
or Vault lookup, and never constructs an approval/provider, starts workers,
shuts down processes, or installs files. The read-only observer still consumes
its separately enrolled file credential and the live Host requires its owned
session and consent. A successful result proves this observation only; Upgrade
must perform its own fresh checks and explicit native approval afterward.

For an unpacked source directory containing unrelated development files, the
reviewed input may set `extension.runtimeResourcesOnly:true`. This explicit
signed flag is copied into `PreservedExtension.runtimeResourcesOnly`. Only the
current fourteen fixed runtime names and the root directory metadata are
snapshotted and reverified; sibling files and directories are neither listed
nor traversed. Every runtime file must remain an owned, non-shared-writable,
single-link regular file with its exact signed inventory hash. Missing runtime
files, symlinks, changed bytes, and incomplete legacy sets fail this variant.
The independent native Loaded-from path and extension-ID proof remains required.
This grants no extension write and no trust to sibling files. Without the flag,
the existing exact-directory inventory contract still rejects extra entries.

After a separately authorized console-only upgrade, a recovery baseline must
bind the current disabled configuration plus the independently retained original
Chrome subtree. The installer still requires exact equality after removing
`chrome`; it does not excuse historical console-pin differences.

### Unified application staging

`python3 scripts/build-unified-app.py --manifest SIGNED_DEVELOPMENT_MANIFEST --output-directory NEW_EXTERNAL_DIRECTORY`
stages `Mechanize.app` without changing an installation. Its main console keeps
`com.viant.mechanize.consent` and the existing enrollment account. Broker, helper,
and native-host retain their exact signed bytes and internal identities under
`Contents/Helpers`; the outer console is signed only after nesting. The output
`unified-manifest.json` uses `layout:unified-app-v1` and cannot be passed off as
the old sibling-artifact installation manifest. Optional `--signing-identity`
is an exact existing certificate fingerprint; default remains ad-hoc.

The stage does not consolidate existing TCC records or migrate Keychain custody.
The relocation transaction must explicitly bind the old private broker path and
new `~/Applications/Mechanize.app/Contents/Helpers/mechanize` path while retaining
the private configuration and encrypted stores. Old applications and grants must
remain until the replacement's same-item/key-version readiness is verified.

The closed initial-relocation review adds `unifiedManifest:{path,sha256}` and
`unifiedLaunchdPath` to the metadata helper input. Both are required together.
The unified stage must derive from the same reviewed development manifest. The
helper retains the original private config/stores and changes only reviewed
pins and the helper/native-host executable paths. It checks the original
launchd metadata separately from the relocated job, with an unchanged listener.
The relocated job must already be loaded and stopped for the existing readiness
checker; packaging does not register jobs or native-host manifests.

Relocation uses enrollment/plan version 2 and `unified-app-v2`: one absent-target
application at `~/Applications/Mechanize.app`, plus three read-only legacy
artifact records. The complete app is copied into a checked sibling and published
with an exclusive atomic rename. The old broker/app stay in place, and the private
config receives a retained backup before exchange. The durable unknown barrier
binds both executable paths and the full new app inventory before placement.
Keychain preparation checks the old path/policy; commit and fresh readiness check
the new path/policy against the same captured encrypted item identity. Version 1
bytes and journal interpretation remain unchanged. An uncertain transition is
never replayed or automatically rolled back; retained artifacts and journals
require explicit reconciliation. Cleanup is a separate action only after actual
replacement readiness succeeds.

Journal references use the Go constructor's exact layout under the private
runtime: `.secret/mechanize-custody-migration`,
`.secret/mechanize-runtime-staging`, and `.secret/mechanize-runtime-artifacts`.
Existing records are never replaced to make a new attempt appear fresh. A prior
unknown or incompatible journal blocks a new transaction until reviewed recovery.

If the exact reviewed unified app was preinstalled so the user could grant its
final identity permissions, the review input may explicitly set
`preinstalledUnifiedApp:true`. The signed runtime plan carries the same flag.
The producer and worker require exact full-inventory and signature equality with
the reviewed candidate. The worker verifies the target before/after custody
work and performs no app staging, rename, overwrite, or removal in this mode.
Only private configuration/custody transition remains. The durable journal binds
this choice; false or an unflagged existing target cannot authorize adoption.
This metadata/worker change requires no re-signing of the preinstalled app.

When the preinstalled app itself approves activation while the original private
configuration still pins the old console, the review must additionally set
`preinstalledApprovalConsole:true`. This requires `preinstalledUnifiedApp:true`.
The helper verifies the actual approving process against the installed bundle's
reviewed pin and birth. The plan carries `ApprovalConsole` (installedPath,
requirement, birth) and a separate `OriginalConsoleArtifact` (path, requirement,
inventory, inventorySHA256). The worker checks the original artifact and original
configuration pin independently before and after the transition, and authenticates
the new approving socket peer's kernel PID, executable path, birth and signature.
No original console or configuration is overwritten to establish approval.

For compatibility with the frozen console observer, `LegacyArtifacts.console`
in this explicit mode describes the separately signed approving candidate image:
its target equals its candidate, and its old/new inventories and requirements
both describe those actual candidate bytes. `OldConsoleBirth` is the genuine
approving process birth. These fields are approval compatibility evidence, not a
claim that the historical console had that identity; the historical evidence is
retained in `OriginalConsoleArtifact`. This narrow read-only alias is permitted
only in this explicit mode. The original and final bundles remain disjoint.
The installed app bytes need not change; fresh signed workers enforce the expanded
metadata contract and preserve the original Vault item identity.

### App-owned native helper launch

The unified bundle enrolls `MechanizeHelperLaunchTransport:console-v1` together
with its exact broker and helper pins. On normal GUI launch, before connecting
to the broker, the app starts the private `consent.sock.helper` service in the
existing owned runtime directory. Host configuration must explicitly select
`nativeLaunch.transport:"console-v1"`; Vault protection in that mode uses
`nativeVault.windowProtection:"helper-v1"`. There is no direct-launch fallback.
Permissions drag the verified app bundle in this mode; legacy mode retains its
existing recipient. Startup failure appears as a fixed message in Permissions.

Only the enrolled signed broker can request the fixed bundled helper. The private
protocol accepts five descriptor capabilities and a bounded closed launch
profile; it accepts no executable path, arbitrary environment, or desktop request.
All descriptors are duplicated above the child target numbers before mapping.
The helper independently verifies the broker and actual console parent before
initializing native services. The app retains and reaps its own child; lost or
invalid termination evidence remains unknown. This preserves existing frame,
watchdog, fence, grant, and durable-operation checks. Inherited macOS application
responsibility still requires actual live AX/TCC qualification; packaging does
not set `singleTCCEntryQualified` or claim permission was granted.

### Stable local development signing

For development on one Mac, run `python3 scripts/setup-local-signing.py --create`
once. It creates a code-signing certificate in the user's default Keychain,
imports its private key as non-extractable with `/usr/bin/codesign` access, and
limits certificate trust to the user-domain code-signing policy. Passwords stay
in macOS dialogs. Public certificate metadata is stored under
`~/.secret/mechanize-signing`; no signing material belongs in the repository.
An unknown import/trust outcome requires inspection; setup does not replay it.

Later development builds reuse that configured identity automatically, and the
unified app builder retains the staged manifest's signer. A missing or unusable
configured identity fails the build instead of silently reverting to ad-hoc
signing. `--signing-identity` can select an explicit valid certificate.
Certificate-backed artifacts
carry a stable designated requirement bound to their exact bundle identifier
and certificate leaf. Broker/helper/host/console transport checks still use
the separately reviewed per-build code hashes. The custody writer accepts that
narrow certificate policy only for the exact reviewed broker image and with
valid OS code-signing trust. A different certificate or identifier does not
inherit the grant.

The initial transition from an ad-hoc identity can require macOS permission and
Keychain approval. Keeping the certificate and bundle identifiers stable lets
later builds retain their OS identity. This local certificate is not a Developer
ID distribution identity; Viant's release process must supply its own Developer
ID signing and notarization before public distribution.

### Local Scy Vault custody

Set `nativeVault.keyProvider` to `scy-local-v1` to keep Vault encryption independent of macOS Keychain and application signing changes. Keep an opaque `keyAlias` and `keyVersion`; the broker derives the local key location under `~/.secret/vault-keys`. Native setup generates a 256-bit key in an owner-only file, and Vault records use authenticated AES-GCM through the Scy KMS boundary. The key file is protected by filesystem permissions; it is not itself encrypted with another local key. This mode does not provide Keychain's isolation from other processes running as the same user.

Provisioning remains native-only. Existing ciphertext prevents replacement of a missing key; malformed keys, symlinks, hard links, unsafe permissions and repository locations are refused. No MCP tool reads or returns master keys, credential values or clipboard contents. Keep keys and encrypted records outside source control and back them up together using an appropriate private backup.

`NativeKeyProvisioner` separates native setup/readiness from the internal cipher key resolver. A future Secret Manager adapter can implement these seams without changing the MCP credential contract or exposing secret values to the model. The legacy default remains `keychain-v1` for existing installations; switching providers requires an explicit local migration or retained-backup reset, never an automatic fallback.
