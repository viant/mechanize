# Native read-only custody preparation bridge

`NativeMigrationPreparationReader(preparationWorker:credentials:).prepare(intent)`
is the concrete console-side metadata reader. It launches the exact reviewed
signed worker through the existing descriptor/signature-checked launcher. Its
credential-only channel authenticates the helper before credential lookup and
sends only MMAUTH. It has no authorization record, approval challenge reader, or
approval response method. The already-approved frozen upgrade intent determines
all bootstrap fields; no new permission window is created.

The existing custody-worker command selects this server branch only when its
signed, linker-embedded enrollment contains `preparation` with these fields:

- `mutationExecutable`: exact later mutation-worker path.
- `mutationRequirement`: exact later mutation-worker signature requirement.
- `mutationSHA256`: exact later mutation-worker file digest.
- `runtimeManifestSHA256`: frozen whole-runtime artifact manifest digest.

This section is not a request argument or environment flag. Preparation mode
cannot be combined with restart reconciliation. It routes before normal worker
construction to `serveMigrationPreparationEntry`, which accepts only prepare and
close. Verify, commit and inspect are rejected before metadata access. The new
branch cannot reach the approval transport, write executor, staging controller,
or journal mutation methods.

Under the existing installation placement lock, the server checks the frozen
broker configuration, console identity, old broker pin, alias and item mapping.
It calls the existing native metadata-only preparation twice; each call checks
the actual complete old access policy against the exact old signed broker. Both
must identify the same persistent item. It rechecks configuration, lease and
native-console authority before returning private identity and transition
metadata. It never asks Security.framework for the Vault master key bytes.

The response binds the original approved intent, config digest, options digest,
whole-runtime manifest, mutation-helper pin, exact item reference digest and
existing Go transition format. The Swift decoder requires canonical closed
frames and verifies every binding before constructing `MigrationNativePreparation`.
The reader requires the terminal close receipt and retains its credential socket
until then. Closing releases the preparation lease; it does not claim the later
mutation process already owns an uninterrupted lease.

## Adoption by the existing Go installer

`bindMigrationPreparation` is a private native-composition integration function,
not a wire approval API. Given the independently verified preparation evidence,
trusted current manifest plan and frozen-config verifier, it binds one original
transition ID and returns a context clamped to the prepared deadline. The caller
must use that returned context for the existing composition execute call.

The narrow coordinator hook re-prepares actual metadata under the installer's
held lease, checks the original item/options/intent and unchanged frozen config,
and adopts the original ID only once. Any existing journal blocks fresh
adoption. Commit checks the same held lease, actor, item/transition and shortened
deadline. An unclamped context is refused; deadlines cannot be extended. No
journal record, stage engine or placement sequence is replaced by this hook.

## Exact remaining production wiring

1. Package the same command with the reviewed preparation enrollment and record
   its exact resulting signature/hash as a separate read-only image manifest.
2. Invoke the native reader from the existing approved main-window upgrade
   action, preserving its typed evidence privately.
3. The authenticated native bridge must feed that evidence and original
   prepared deadline into the existing signed composition/adoption path. It must
   construct the actual full-artifact adapter and fresh loaded-extension,
   quiescence, console-readiness and final-verification evidence.
4. Drive one Go installer execute operation and its typed terminal/recovery
   protocol. Do not wire the raw Swift prepare/verify/commit fixture sequence as
   production: native verification requires the candidate already staged at its
   canonical path, which the Go installer owns.

Source tests use synthetic metadata, credentials, pipes and temporary artifacts.
They do not qualify a real item read, Keychain custody change or deployment.

## Main-window package composition root

`MigrationUpgradeSelection` now connects selection metadata to `MigrationUpgradeIntent`, `NativeMigrationUpgradeProvider`, and the existing coordinator. The main window has explicit Select upgrade, Upgrade, and Cancel actions. Launch and selection never read the enrollment credential, prepare custody, or start a worker. The Upgrade click consumes its selection before awaiting package revalidation; substitution, duplicate clicks, cancellation, or an unavailable provider cannot reach preparation. Existing unknown/recovery states remain owned by the coordinator.

`MigrationReviewedUpgradePackage` has no public JSON initializer or approval field. Its internal native-source decoder requires an independently reviewed whole-package SHA256, closed fields, distinct preparation/installer manifests, matching bootstrap worker pin, exact frozen-plan digest, and the existing console-manifest checks. Worker files are still independently signature/hash/descriptor checked at launch, and the Go installer remains responsible for the complete install-plan/artifact policy. The envelope fields are `version`, `title`, `preparationWorker`, `installerWorker`, `bootstrap`, `installPlanBase64`, and `installPlanSHA256`; bootstrap contains the existing nine immutable identity/options fields without an approval claim.

The installed-entry wiring deliberately supplies no `MigrationUpgradePackageSource`: both selection and Upgrade are inactive. A production implementation must obtain the expected digest and package from the authenticated installation/review channel inside the native console, then revalidate that same selection before execution. A hash carried by the selected package, an arbitrary file picker, command-line input, or a worker challenge cannot enroll itself. The main window retains the existing credential-provider object without looking up credential bytes.

Remaining rollout gates are the authenticated package source and reviewed artifacts/enrollments, the signed Go runtime-observer factory, and signed end-to-end qualification. This source slice adds no runtime enrollment, pin override, custody bypass, or deployment action.

## macOS app launch context for AX diagnostics

Run `--check-runtime-upgrade` through LaunchServices against the exact signed app
bundle when assessing the console's Accessibility grant. Direct execution of
`Contents/MacOS/MechanizeConsent` from a shell can have a different macOS TCC
responsible-process context and report `accessibilityRequired` despite the app's
existing grant. That result alone is not evidence that another grant is needed.
The normal main-window Upgrade action already runs in the app process.

For a bounded read-only diagnostic, use `/usr/bin/open -n -g -W --stdout <private
report file> --stderr <private diagnostic file> -a <exact signed app bundle> --args
--check-runtime-upgrade`. Use operator-owned private destinations; expose only
the closed report fields `qualified`, `stage`, and `errorCode`. A
`managementDocument` failure after an app launch means the exact frozen
PID/birth/window/internal-document proof did not qualify; refresh and review that
binding before retrying. Do not interpret it as an Accessibility denial or loosen
the document proof. This diagnostic neither approves nor performs an upgrade.

The future `nativeVault.windowProtection: "helper-v1"` opt-in routes the Vault's
independent scalar window check through the authenticated native helper. Missing
configuration preserves the legacy route; a helper error never switches routes.
The helper's private administration profile rejects ordinary automation, and its
metadata route is absent from MCP. Consolidating those routes still requires
signed end-to-end qualification; a nested executable alone does not prove one
macOS permission owner.

## App-owned helper transport

For a unified installation, `nativeLaunch.transport: "console-v1"` selects the
signed app's private `consent.sock.helper` launcher. When Vault is configured,
this transport requires `nativeVault.windowProtection: "helper-v1"`. Both keys
are reviewed host configuration, never tool arguments. The helper path must be
`~/Applications/Mechanize.app/Contents/Helpers/mechanize-native`; the console
socket remains the fixed private runtime endpoint. Legacy installations retain
their existing launch route only when the transport field is absent. Connection,
identity, permission, or protocol failures never select another route.

The app starts its launcher before broker connection, under its normal
LaunchServices app context. The broker authenticates the signed console and
passes only a closed helper profile plus inherited stdin/stdout, artifact,
watchdog, and fence descriptors. The console authenticates the enrolled broker,
verifies its own and the fixed helper's signatures, and launches/reaps that exact
child. The helper independently authenticates the broker rendezvous and its
actual signed console parent. Public MCP requests, consent, desktop fencing,
and durable effect semantics stay unchanged. Reads, controls, recordings, and
private Vault window probes all use this launch route. The console's narrow
management-page reader already runs in the same app context.

Losing the console channel immediately retires broker-owned input and heartbeat
pipes. Missing exit evidence keeps cleanup unknown; it never enables a replay.
A verified nonzero child status remains an execution failure, distinct from the
independent fact that the child was reaped. The Vault's existing exposure lock,
exact secure-entry checks, and encrypted custody remain mandatory.

Activation requires one consistently signed app/broker/helper package with the
new helper pin and `MechanizeHelperLaunchTransport: "console-v1"` sealed into its
Info.plist, the two reviewed host fields above, and matching enrolled code pins.
Start the app through LaunchServices before starting the broker. Do not reset or
recreate the existing Vault/key. Source tests qualify transport/protocol/guard
behavior; only a live normal-window observation and protected-window rejection
under the activated app can qualify its actual macOS permission attribution.

The Darwin Unix-socket peer token must be checked while the peer still holds its
endpoint. The one-use identity rendezvous authenticates the broker before nonce
emission; after its final ACK, the helper revalidates its exact signed parent,
not an already-closed socket. The app-owned control channel stays open after the
`exited` receipt until the broker authenticates that receipt and sends the exact
`reaped` acknowledgement. An EOF without the qualified terminal receipt remains
unknown. Disposable socket regressions cover both the peer-token expiry and the
acknowledged terminal lifetime.

Helper-owned guard failures retain closed stage codes (launch, profile,
exchange, cleanup, AX trust, process/signature, or window shape). They never
include native error messages, window titles, paths, or credential data. In
particular, `nativeProbeUnavailable` from an older build did not distinguish an
AX denial from a transport failure and must not trigger an automatic TCC change.
