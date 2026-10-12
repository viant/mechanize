# Browser setup metadata without a website executor

The extension now has a read-only setup producer in `setup-metadata.js`. Its
Options page exposes **Read setup metadata**, available even when the native
broker or website executor is disconnected. Only an exact top-level message from
this extension's own Options page can invoke that local projection. It displays
extension ID, a stable digest of extension-local storage, and bounded worker
state counters. It never displays storage values or key names, reads websites,
opens a tab, changes permissions, writes storage, or resets retirement state.

The native setup-channel version is advertised explicitly in the extension
hello. A compatible authenticated broker can issue a one-shot request bound to
a fresh nonce, request ID, broker epoch, channel epoch, scope hash and deadline.
The reply remains usable when website inventory/executor qualification is false.
`Gateway.SetupMetadata` verifies the existing native-host/Chrome process channel
before and after the request and returns an opaque proof with a detached metadata
receipt. `VerifySetupMetadata` rejects changed actors, channels, epochs, process
births and stale receipts. Unknown mutations and lifecycle inhibition are not
changed by this read.

The native-console RPC is `browserSetupMetadata`, with only owned logical
`profileChannel` and `browserInstance` selectors. Caller-supplied directory,
storage hash, process or quiescence claims are not accepted. The old installed
broker need not support this RPC for the local Options projection to work; that
projection can be qualified through the existing scoped Mechanize native UI
workflow.

## Digest and observation boundaries

The storage scope is exactly `extension-local-v1`: SHA256 of recursively sorted
canonical JSON from `chrome.storage.local`. The producer makes two bounded reads
and rejects a changed digest or storage-change revision. Ephemeral session data
is not part of the preservation digest, but retained unknown intent and lifecycle
markers contribute to the reported counters. The digest describes this sample;
it is not a storage lock or a claim that later state stayed unchanged.

The extension does not infer a physical loaded directory. Chrome's documented
[management ExtensionInfo](https://developer.chrome.com/docs/extensions/reference/api/management#type-ExtensionInfo)
provides ID and installation metadata, not an authoritative filesystem directory.
The [runtime API](https://developer.chrome.com/docs/extensions/reference/api/runtime)
provides extension resource URLs; those are not evidence of the physical source
folder. `loadedDirectoryAvailable` is always false in this projection, and a
native broker rejects a reply claiming otherwise.

## Required receipt fusion before artifact placement

A complete runtime-artifact observation still needs:

- A fresh scoped native Chrome Extensions-details receipt identifying the actual
  loaded directory and the same extension ID. Never substitute an assumed
  installation folder or inspect profile databases.
- Exact broker/console process birth and signature provenance from the native
  workflow. The setup channel currently supplies its verified native-host and
  Chrome-parent identities and enrolled signing requirements only.
- Independent stopped-process and renderer-quiescence receipts. Zero sampled
  command counters are not proof that Chrome or other executables stopped.
- The original channel/storage receipt provenance retained by the authenticated
  native workflow. A caller-computed receipt hash alone grants no authority.

The receipt explicitly lists these missing evidence classes. It must not be
passed off as a complete artifact observer or install success. Public browser
setup data does not authorize a reload, move the unpacked directory, replace a
source tree, change an extension ID, or discard storage/retirement records.

Tests use synthetic extension storage and private channel fixtures. No live
browser/profile content was read while implementing this producer.
