# Explicit all-websites Chrome enrollment

`chrome.grants[].allWebsites: true` enrolls ordinary HTTP and HTTPS website
origins in that authenticated Chrome channel. `origins` must be empty. Omission
or `false` preserves the existing exact-origin policy and its scope hash. The
host requires the user's existing `desktopAccess` operator ceiling for this
broader website enrollment, including when channel trust is profile-scoped.
This flag does not replace process, profile, document, executor, or consent proof.

Privileged browser/extension/file schemes, URL credentials, origin wildcards,
and non-origin strings remain outside website admission. HTTPS credential
submission and exact destination binding are separate controls; all-websites
enrollment does not widen credential delivery or remove DOM quarantine.

The human consent scope is `{ "kind": "browser", "bundleID": "com.google.Chrome" }`.
It is distinct from native Chrome application/window control and from desktop
control. The host maps web operations into this scope only when trusted local
enrollment enables all websites and the current operator ceiling permits it.
The normal verified-client, purpose, mode, lifetime and revocation checks apply.
An existing explicit desktop grant covers this scope. An agent requesting browser
consent cannot enable all-websites enrollment.

The broker returns `allWebsites` in enrolled/processQualified messages and browser
status. Lifecycle inventory retains it; read, control and lifecycle guards reject
scope changes. Broad enrollment adds `allWebsites:http+https:v1` to the existing
scope-hash input array. Retirement origin-policy evidence uses that distinct
marker instead of an origin list. Exact-origin hashes/digests remain compatible.
Switching scope still requires the existing retirement/reconciliation workflow;
unknown effects are never cleared or replayed by changing enrollment.

Capability discovery uses currently observed admitted origins as candidates,
then performs normal document qualification. It never invents a representative
site or treats broad permission as proof that a document executor is ready.

These are source contracts verified with fixtures. Rollout requires coordinated
broker, extension, local enrollment and human-consent UI support. An older broker
cannot be made all-websites-capable by an extension permission alone. A broker
whose exact identity owns Keychain custody must not be replaced without the
qualified custody transition. No runtime installation is part of these tests.

The extension connection page offers **All websites** as the new default choice;
existing selected-site preferences remain selected until changed. Chrome is
asked once for `https://*/*` and `http://*/*`, without file or browser-internal
access. Global setup links use `access=all` instead of an origin list. The worker
requires the broker's explicit `allWebsites: true` acknowledgement before
qualifying that scope; an old/narrow broker produces a static scope-mismatch
message rather than apparent success.

The native console decodes and displays the distinct browser consent scope and
shows website access separately from transport readiness. Legacy status replies
without `allWebsites` remain selected-site replies. Credential storage/delivery
bindings and login-document quarantine are unchanged.

After a custody-safe coordinated runtime upgrade, preview enrollment with
`scripts/extend-chrome-origins.py --all-websites` and the installed frozen build
manifest. Only a manifest advertising `websiteAccessModes: ["selected", "all"]`
permits this mode; old runtimes are rejected before writes. Explicit apply uses
the same stopped-runtime/private-backup boundary as selected-origin changes.

Mutating runtime, console, helper, Chrome enrollment and website-scope updates
hold the installation's permanent `.migration-placement.lock` for their entire
operation. The custody installer uses that same lock through placement, ACL
migration and readiness checks. A competing update fails before reading or
changing configuration. Preview does not acquire or create the lock. The lock
excludes cooperating installers; exact artifact and configuration checks still
protect against independent changes. These source tests do not establish live
Vault migration or browser readiness.
