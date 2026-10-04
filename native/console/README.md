# Native permissions console

A macOS 14+ SwiftUI/AppKit permissions app. Build and package without starting it:

```sh
swift test --package-path native/console
native/console/build-app.sh
```

The default unsigned preview bundle is `native/console/dist/Mechanize Permissions.app`. No installation, launch, desktop input, or TCC prompts occur during build/tests. The app contains a conditional production adapter: when trusted bundle identity and a provisioned broker signing requirement are present, it creates `SocketConsentBroker` with the fixed Unix endpoint and Keychain enrollment provider. The host exposes the matching signed-peer-verified local RPC listener and Datly consent broker. An unprovisioned preview has no credential and stays disconnected. The [local developer builder](../../docs/developer-mode.md) creates an ad-hoc signed copy with exact broker/console code-hash pins; credential enrollment and OS permissions remain separate. Signing, notarization, enrollment provisioning, and installed end-to-end qualification remain release gates.

The app starts **disconnected and read-only**. It does not manufacture requests or grants. A dropped/selected application bundle, or a broker inventory target, selects scope only; it cannot grant permission. Every actual request displays the broker-verified client identity, exact application/window/origin, modes, purpose, duration, and expiry. The broker must enforce `allow_once` as one operation and `allow_session` as bounded to the authenticated session and maximum duration. The UI validates returned grant scope, modes, purpose, identity, and duration against the reviewed request before showing success.

Stop/Revoke displays the broker's `requested`, `stopping`, `revoked`, or `cleanupUnknown` status. Pending/unknown cleanup is never described as completed revocation. Confirmed grants remain visible until the broker reconciles state. The grants panel shows grant scope, once/session mode, expiry and remaining time; it does not invent action progress.

## Host integration contract

Implement `ConsentHostAdapter` and inject it via `ConsentView(broker:)`. `LocalConsentBroker` is the consent boundary:

- `snapshot() -> {requests, grants}`
- `decide(requestID, decision: allow_once | allow_session | deny) -> grant | null`
- `revoke(grantID) -> requested | stopping | revoked | cleanupUnknown`
- `inventory() -> [{id, scope}]` and `helperPermissionDoctor() -> [{helperBundleID, permission, state, detail}]`
- `openSystemPermissionSettings(permission)` is called only on a user click.

The host adapter authenticates a local private Unix socket broker, resolves Scy enrollment credentials through Keychain, and associates every operation with verified broker identity. Peer verification uses socket UID plus kernel audit-token identity and a strict code requirement; it has no PID-only fallback. A peer display name alone is not authentication. This app does not accept arbitrary remote URLs, authentication tokens in arguments, or plaintext credentials/configuration. Socket framing, peer verification, Keychain lookup, and host listener/broker composition are implemented. `MechanizeConsent/App.swift` constructs the socket adapter only when the signed app's trusted broker requirement is provisioned; otherwise it uses the disconnected adapter. An unprovisioned bundle has no enrolled credential, so it stays disconnected and cannot issue grants. Release enrollment and signing setup must provision both ends.

Wire DTOs are Codable with ISO-8601 dates (`ConsentWire`). Requests:

```json
{"id":"request-id","verifiedClient":{"id":"client-id","displayName":"Agent name","verification":"verified"},"scope":{"kind":"window","bundleID":"com.example.Editor","windowID":"42","displayName":"Draft"},"modes":["observe","control"],"purpose":"Edit the selected draft","durationSeconds":300,"createdAt":"2026-10-01T14:00:00Z","expiresAt":"2026-10-01T14:02:00Z"}
```

Grants:

```json
{"id":"grant-id","requestID":"request-id","clientID":"client-id","scope":{"kind":"window","bundleID":"com.example.Editor","windowID":"42","displayName":"Draft"},"modes":["observe","control"],"purpose":"Edit the selected draft","durationSeconds":300,"decision":"allow_once","createdAt":"2026-10-01T14:01:00Z","expiresAt":"2026-10-01T14:06:00Z","state":"active"}
```

`verification` is `verified | unverified | unknown` and originates at the authenticated broker. Grant `state` is `active | revoked | expired | consumed`. `scope.kind` is `application | window | origin`; application needs a bundle identifier, window also needs a window identifier, origin needs an exact HTTP(S) origin without credentials/path/query/fragment. The broker validates these values authoritatively and rejects widening/races/replay.

macOS TCC is separate from app consent. The doctor must report the **automation helper's** Accessibility, Screen Recording, and Input Monitoring permission status, identified by helper bundle ID. The console must not probe its own TCC and present that as the helper's status. Status refresh cannot prompt, open System Settings, or perform automation. App consent never bypasses macOS controls.

## Validation

Seventeen state/transport fixtures cover once/session acceptance, denied requests, unverified identities, exact scope/purpose/modes/duration JSON roundtrip, rejected mismatched responses, revoked versus unknown cleanup, expired grants, and disconnected preview. `swift test` passes. Transport fixtures cover framing bounds/truncation, mismatched RPC IDs, unknown revoke status, credentials sent only after peer authentication, sanitized remote errors, and unchanged active grants after a claimed revoke. The tests are injected fixtures and do not prove production broker authentication, persistence, action enforcement, signing or live helper TCC behavior.

## Socket transport v1

`UnixBrokerTransport` only uses `~/Library/Application Support/Mechanize/runtime/consent.sock`. It rejects symlink path components, mismatched UID, writable-by-others ancestors, non-private runtime/socket modes, and non-socket endpoints. Before credential exchange, `SignedBrokerPeer` requires the expected peer UID and validates the socket peer process against a host-provisioned Security.framework designated signing requirement. The host's `auth/nativepeer` verifier checks the accepted connection's audit identity against its configured UID and signing requirement before reading credentials. Both policies must come from trusted signed provisioning; neither has a development UID-only trust fallback. Signed policy and credential provisioning, plus acceptance using the installed binaries, remain integration/release gates.

Each UTF-8 JSON-RPC 2.0 message has a 4-byte big-endian length (1–262144 bytes). Requests use a fresh UUID string ID; replies must echo it exactly and contain exactly one of result/error. Errors are sanitized to fixed messages; server details and credentials never reach UI logs/errors. A failed/malformed RPC disconnects and closes the socket. Reads and writes have five-second socket timeouts.

First message:

```json
{"jsonrpc":"2.0","id":"uuid","method":"hello","params":{"protocolVersion":1,"credential":"Keychain enrollment secret","clientBundleID":"com.viant.mechanize.consent"}}
```

Hello result is `{ "protocolVersion": 1, "sessionID": "opaque", "brokerName": "display name" }`. Display name is informational; local native peer proof establishes trust. Subsequent requests include `sessionID` in params. Methods are `snapshot`, `decide` (requestID, decision), `revoke` (grantID, result `{ "status": "revoked" }` or other typed status), `inventory`, and `helperPermissionDoctor`. Decide result is a grant or JSON null. Credentials are not resent after hello.

`KeychainEnrollment` reads only generic-password service `com.viant.mechanize.console.enrollment`, account `<trustedBundleID>:<uid>`. Lookup is called only by explicit Connect user action, with authentication interaction disabled; missing/locked credentials leave the app disconnected. This client does not enroll credentials or accept secrets in argv/plain config. Enrollment must be provided by the signed host's Scy/Keychain provisioning flow. Settings buttons use fixed native System Settings destinations after a click; no TCC prompt or console-permission probe occurs automatically.
