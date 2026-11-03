# Local developer installation

Local development can run without a Developer ID certificate. Use an ad-hoc
signature and exact executable hash pins so the local consent channel can still
verify its peer. Apple describes ad-hoc signing as sealing code without a signing
identity, using `codesign --sign -`:
[ad-hoc code-signature contract](https://developer.apple.com/documentation/security/seccodesignatureflags/adhoc).

From the repository root:

```sh
python3 scripts/build-development.py
```

For repeated development updates, an existing valid code-signing certificate
can be selected by its exact SHA-1 fingerprint:

```sh
security find-identity -v -p codesigning
python3 scripts/build-development.py --signing-identity CERTIFICATE_SHA1
```

The fingerprint identifies a public certificate, not a credential. The builder
rejects names, missing identities and invalid fingerprints before building. It
signs every packaged artifact with the selected identity and verifies each
artifact's actual leaf certificate. It preserves exact artifact hash pins for
the broker/helper/console trust channels. No key or certificate is created,
imported or trusted by this option; Keychain controls access to the existing
private key. An unavailable signing identity fails without falling back to
ad-hoc signing.

Certificate signing lets macOS use the signer's designated requirement to
recognize updates; see [Apple's code-signing guidance](https://developer.apple.com/library/archive/technotes/tn2206/).
Permission preservation must still be tested across an actual signed upgrade.
The manifest records the signing mode and public certificate fingerprint.
Certificate signing alone does not qualify release distribution or Office input.

This builds the MCP broker, native helper, and permission app under
`dist/development/`, signs each locally, verifies signatures, and writes a
private `manifest.json`. The app contains the exact broker requirement. Copy the
manifest's `nativeConsoleConfig` into your explicitly configured host file; its
console code hash and OS UID are verified before Scy consent-admin credentials
are accepted. The app shows a development label.

The build does not install or start anything, create credentials, write Keychain
items, grant macOS permissions or enable mutations. Configure your own Scy
resources, enrolled clients/user ceilings and encrypted artifact key resources.
Use separate development storage and a development issuer/audience. The current
console uses the fixed local socket and Keychain service, so run one enrolled
broker installation at a time; isolated parallel development profiles remain a
packaging task.

A rebuild changes hash pins. Rebuild the app and update the broker's console
requirement together; an old enrollment never authorizes arbitrary replacement
code. Completely unsigned peers fail the existing signed-peer verifier. Ad-hoc
signing needs no paid signing certificate and does not turn off peer checking.

You still approve tool access in the native panel and grant the helper's actual
Accessibility, Screen Recording or Input Monitoring permissions in macOS.
macOS may require an explicit Privacy & Security **Open Anyway** action for a
local unnotarized app; see
[Apple's app-opening guidance](https://support.apple.com/102445).
This build does not change Gatekeeper settings.

Ad-hoc identities are tied to a particular build; privacy choices may need
renewal after rebuilding. See
[Apple's code-requirement guidance](https://developer.apple.com/documentation/technotes/tn3127-inside-code-signing-requirements).
Development packaging is not release qualification. Distributed production builds
still require appropriate Developer ID signing/notarization and installed/live
acceptance; see
[Apple's notarization requirements](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution).

## Local profiling

Diagnostics are disabled by default. For an operator-requested development
profile, set `MECHANIZE_GOPS_DIR` to a private, owned physical directory or pass
`-gops-dir /absolute/private/directory` to `mechanize serve`. The broker starts
[gops](https://github.com/google/gops) on an ephemeral `127.0.0.1` port and removes
its port registration on normal shutdown. This endpoint has gops' local-process
access model; do not enable it on a shared host. It is never an MCP capability.

Install the pinned client with `go install github.com/google/gops@v0.3.23`.
Set `GOPS_CONFIG_DIR` to the same directory for `gops stack PID`, `gops stats PID`
and `gops pprof-cpu PID`. The CPU command records 30 seconds and starts Go pprof
when available. Keep raw stack/profile artifacts private and outside the repo.
Use a diagnostic workload separately from timed comparisons, then repeat the
same verified workflow without profiling before claiming a speed improvement.

Durable step timing includes `processVerification.checks` and
`processVerification.milliseconds` for completed full signed-peer probes.
These counts are step-scoped metadata, not authorization or cached trust.
Continuity-only checks do not contribute. The total may include overlapping
checks and should not be subtracted mechanically from wall time.
