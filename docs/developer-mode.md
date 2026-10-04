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
