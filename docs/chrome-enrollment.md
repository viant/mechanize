# Disposable Chrome development enrollment

`scripts/enroll-chrome.py` prepares one exact disposable Chrome channel. It defaults
to preflight and never starts/restarts Chrome, the broker or native host, posts
input, edits a database, or grants consent. Enrollment is not production
qualification. Existing credentials and configuration are preserved until an
explicit apply under a stopped-runtime maintenance boundary.

## Required evidence

Load the unpacked extension through the authorized disposable Chrome session and
read the actual Chrome-reported 32-character `[a-p]` extension ID. The script
requires that ID; it cannot derive or guess it from a path. A syntactically valid
ID alone does not establish its provenance: the operator must supply the ID read
from this exact disposable profile.

The qualification plan supplies the canonical user-data root, its `Default`
profile, channel/browser identifiers, signed Chrome executable and exact origin.
The current bounded recipe uses `http://127.0.0.1:18771`; arbitrary origin
expansion is rejected. Profile/channel proof remains a separate runtime gate from
Chrome code-signature proof.

Choose the frozen development build manifest corresponding to the installed
broker/native host. The script verifies installed binary SHA256 and exact
codesign requirements, plus the native host's embedded reverse broker pin. It
rejects a manifest whose source differs from the installed configuration. Pins
in earlier `enrollment-recipe.json` files are advisory placeholders and are not
copied as trust. The signed Chrome code-directory hash is observed and verified
at preflight; an updated Chrome image requires renewed enrollment.

Chrome publisher provenance is checked before its image hash is enrolled: the
requirement includes Apple's generic signing anchor, Google's Team ID
`EQHXZ8M8AV`, the exact Chrome identifier, and the observed CDHash. An ad-hoc
lookalike with the same identifier is rejected. General executable ownership,
non-group/world-writable mode, symlink and hard-link checks remain unchanged.

If the installed Chrome executable is group-writable, enrollment rejects it.
An operator can remove only its group-write bit, preserving the bytes and
signature. macOS may deny this modification even to the file owner; do not bypass
that denial or change the trust checks to force enrollment. Check the installing
tool's App Management permission under System Settings → Privacy & Security, or
perform the change through an OS-authorized administrator workflow. App Management
is separate from Accessibility. An `EPERM` alone does not establish which OS
restriction caused the denial. Record the original/new modes and verify the
signature again after an authorized change.

The principal is obtained by a local Go helper using the application's actual
`auth.Verifier` and Scy service to verify the existing installed stdio token.
It is never accepted as caller-authored principal JSON or decoded unsigned
claims. Issuer, audience, algorithms, expiration, enrolled client, scopes and
user origin ceiling are checked. This bounded helper supports the existing local
HS256/plain-file credential references; it refuses remote key discovery,
fallback resources, encrypted existing verifier inputs, and other provider
shapes rather than making new external connections. An expired token must be
renewed through the existing broker credential enrollment process.

For read-only preflight, existing local resource bytes are read from private
files with `O_NOFOLLOW`, checked ownership/mode and bounded size, then passed as
Scy `Resource.Data` in process memory. This avoids AFS changing existing resource
parent directory modes. No credential bytes are printed, passed as process
arguments, or placed in the environment. The helper returns only the verified
principal through a captured private subprocess pipe.

## Preflight and apply

```text
python3 scripts/enroll-chrome.py \
  --installation /absolute/private/installed/development/root \
  --manifest /absolute/frozen/source/dist/development/manifest.json \
  --qualification-plan /absolute/private/disposable/qualification-plan.json \
  --extension-id ACTUAL_CHROME_REPORTED_ID
```

Default preflight validates the selected inputs, signatures and principal. It
creates only an ephemeral private helper build directory, removed afterward;
it generates no enrollment key/credential and writes no configuration.
`--dry-run` explicitly selects the same behavior.

After reviewing that concrete result, inhibit owned automation, stop the exact
broker/helper/native-host executables and keep that maintenance boundary held.
Only then add `--apply --broker-stopped-verified`. Apply independently checks
that none of those exact owned executable paths is running; it does not replace
the operator's runtime/unknown-effect cleanup proof. The script performs no stop,
restart, socket deletion, or effect resolution itself.

The three targets are:

- Installed broker `config.json`, preserving every existing field except adding
  the new `chrome` enrollment. An existing non-null Chrome enrollment is refused
  for explicit migration review.
- Fixed private `~/Library/Application Support/Mechanize/native-host.json`.
- `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/com.viant.mechanize.json`.

The native-host configuration and broker grant share the same exact extension
origin, channel/browser/profile, credential resource, signed process policy and
private socket. The native messaging manifest enables
`supports_native_initiated_connections`, contains that actual extension's sole
allowed origin, and points to the verified installed native host. The native
host validates the signed immediate Chrome parent, kernel broker peer, exact
reconnect profile arguments and reverse broker pin before loading the credential.
`fixtureEnrollment` remains false.

## Explicit local Scy credential

Only apply generates a new independent 32-byte random file encryption key and a
separate 32-byte random enrollment credential encoded as 64 hex characters. Scy
stores the credential as an encrypted resource and loads it back for an exact
roundtrip check. The raw key is a new private file; no default, MAC-derived,
inline, shared artifact key or environment key is selected.

The real local Scy `kms.NewKey` parser was verified to interpret
`blowfish://file/absolute/key` as scheme `blowfish`, kind `file`, and the canonical
absolute path. The provision helper validates that same parser contract before
writing any key. Broker and native host use identical resource references; they
load the secret independently with no inline payload or fallback.

Fresh layout under the private Mechanize support directory:

```text
chrome-enrollments/<fresh-enrollment>/             0700
  backup/                                        0700, files 0600
  secrets/                                       0700
    key/                                         initially 0700
      enrollment.key                             0600
    ciphertext/                                  initially 0700
      enrollment.sec                             0600
```

The socket uses a separate fresh `/private/tmp/mce-<UID>-<random>/transport`
0700 directory, with a 0600 runtime socket. This keeps the complete socket path
within Darwin's 103-byte bound; placing it inside the long Application Support
path would exceed that limit. The script does not delete that socket root.

AFS may change a directly accessed leaf directory to 0755. Key and ciphertext
leaves are therefore separate from the socket parent and remain behind unchanged
0700 outer enrollment/secrets directories. Provision restores leaf directories
to 0700 and validates the outer private boundaries. Runtime access must not rely
on the leaf mode alone. Never put the credential/key directly beside the socket.

The installed Scy Blowfish provider uses CBC without authenticated encryption.
This explicit random-key, private-file development enrollment does not qualify
production credential integrity or custody. The current local registry exposes
Blowfish and GCP; using an authenticated external provider requires a separately
authorized, enrolled provider route. This script makes no such connection.

## Preservation and failure boundaries

Apply creates a fresh private backup with original target bytes, presence markers
and SHA256 before generating the new credential. It re-verifies signatures,
checks stopped executables, and compares all target bytes before replacement.
Each target is replaced atomically with a 0600 file and directory fsync; broker
configuration is replaced last. This is three atomic files, not a cross-file
transaction. A failure can leave a partial configuration set, so keep the broker
stopped and restore the retained exact backup under review before any restart.
The script never automatically replays an apply, overwrites a backup, or deletes
an orphaned credential after uncertain replacement.

The extension's Options page must also contain the same `profileChannel`,
`browserInstance` and exact origins from the qualification plan. Configure these
through the authorized disposable UI; the script never edits Chrome preferences
or storage. No enrollment credential belongs in extension options/storage. Chrome
must have been launched with the planned `--enable-features=OnConnectNative`,
`--user-data-dir` and `--profile-directory=Default` flags for signed reconnect
profile evidence; the script does not launch or retrofit that browser.

After apply, root must explicitly start the reviewed runtime and prove signed
peer authentication, exact profile/channel enrollment, visible extension badge
and executor readiness, scoped semantic observation, consent-enforced mutation,
unknown-command inhibition/reconciliation, and cleanup. Successful configuration
provisioning alone establishes none of those runtime qualification gates.

Verification command: `python3 scripts/enroll-chrome.py --self-test`. Synthetic fixtures exercise configuration preservation, private path/atomic CAS protections, and the actual Scy/auth verifier accepting a signed local token while rejecting expired/invalid tokens. They generate no live enrollment credential and touch no live configuration.
