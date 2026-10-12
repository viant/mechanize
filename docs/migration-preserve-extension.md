# Preserve-extension runtime repair

The reviewed `preserve-extension-v1` plan is an infrastructure-only variant. It replaces the signed broker/config through the existing custody composition and exactly three auxiliary artifacts: `helper`, `native-host`, and `console`. The extension directory is a separate read-only preservation record. No extension exchange/copy/rename, Chrome profile operation, storage read, or storage write is implemented by this variant.

The frozen Go runtime plan adds these fields after `Artifacts`:

- `Mode`: exactly `preserve-extension-v1`.
- `PreservedExtension`: exactly `path`, `extensionID`, `inventory`, `inventorySHA256`.
- `ChromeRequirement`: equal to the original frozen configuration's `chrome.processTrust.chromeRequirement`; the canonical `ChromeExecutable` must also match.

`ExtensionID` remains required and equals the preserved record. `ExtensionStorageSHA256` is omitted in preservation mode. It is never replaced with a synthetic hash. Each inventory entry has `kind`, `mode`, `size`, and `sha256`, including zero/empty directory values. The inventory digest uses Go's sorted map-key encoding and that entry-field order. Only the existing historical public extension-resource sets are accepted; private profile or enrollment files cannot become preservation inventory entries.

The installer verifies the preserved directory inventory before and after runtime placement and at its existing observation gates. Every writable target, backup and journal is restricted to the canonical Mechanize runtime directory and cannot overlap the preserved extension. Artifact/broker/config candidates also cannot overlap it. `NewSourceRoot` remains a read-only configuration reference, not a write operation. Existing full-extension plans retain their four-artifact, storage-hash and authenticated connection requirements.

The digest-covered native `observer` section has exactly `port`, `brokerPID`, `brokerStart`, `brokerRequirement`, `credentialURL`, `credentialSHA256`, `windowTitle`, `chromePID`, and `chromeStart`. It does not accept `profileChannel`, `browserInstance`, credentials, connected flags or success claims. The read-only resource reference is independently pinned and read only after peer verification. The package's external review signature remains independent of its contents.

Preservation capture never calls `browserSetupMetadata`. It proves the exact signed Chrome process and canonical main executable, accepting an actual Chromium hardlink image only through stable device/inode metadata, canonical static signature and actual dynamic signature checks. It retains the actual kernel path. A complete exact-window Mechanize native receipt and independent top AXWebArea `chrome://extensions/?id=...` proof bind the enrolled extension ID and loaded directory. Nested roots, missing ownership/document/detail fields, multiple paths, stale evidence, and lookalikes fail closed. No connected/executor trust or storage equality is inferred.

After capture and native preparation, the approving console performs a single identity-qualified managed broker SIGTERM using the legacy installed signal lifecycle. It validates the pinned launchd definition and loaded job, requires KeepAlive false, waits for broker/owned helper disappearance, then requests Chrome's normal quit once and independently verifies absence. No force quit, uncertain retry or approving-console termination is used. The original 30-second evidence bound remains unchanged. Legacy `cmd/mechanize` discards `Host.Close` errors, so disappearance proves only physical shutdown; durable unknown effects remain unresolved.

A verified preservation-mode installer receipt covers the selected runtime repair, preserved public code inventory, and existing custody/readiness checks. It does not establish Chrome connection or automation success. Full Chrome verification and any remaining plugin rollout follow after the repaired runtime is deployed. Source fixture tests do not replace signed end-to-end qualification.
