# Local development installation

Run `python3 scripts/install-development.py` from this checkout on macOS after
`scripts/build-development.py` has produced an ad-hoc signed development manifest.
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
