# Signed native socket peers and helper launch identity

Trust policy comes from operator enrollment: an expected UID and the exact
Security.framework code requirement for the enrolled binary. Helper messages,
requested bundle names, executable paths, and PIDs do not supply that policy.
A broad requirement such as `true` provides no identity boundary and must never
be used as enrollment configuration.

## Connected socket verification

`NewVerifier(Options{ExpectedUID, DesignatedRequirement})` parses the trusted
requirement at startup. Its returned function verifies each connected Unix
socket before the transport reads a credential or handles a request.

Both `getpeereid` and the socket's `LOCAL_PEERTOKEN` effective UID must match the
configured UID. `SecCodeCopyGuestWithAttributes` receives
`kSecGuestAttributeAudit`, including the audit token's PID version, and
`SecCodeCheckValidity` applies the exact configured requirement with strict
validation. PID alone and UID alone never authorize a peer. Missing audit-token
support or a Security error denies access; there is no PID fallback.

`AuditPID(conn)` extracts the connected peer's PID from that kernel audit token.
It does not verify a code requirement. Call the verifier on the same connection
before using `AuditPID` to match the peer to a process the broker launched.

These APIs require macOS with cgo. `NewVerifier` returns `ErrUnsupported` on
other builds; `AuditPID` and platform executable verification are also
unsupported there.

## Executable verification before launch

`VerifyExecutable(path, Options{ExpectedUID, DesignatedRequirement})` requires
an absolute, clean path without symlinks, a nonempty trusted requirement, and a
regular executable with one hard link. The file must belong to the expected UID
or root and must not be writable by group or others. Security.framework checks
the static code against that exact requirement using strict validation and
validation of all architectures.

Static validation establishes the enrolled file's signature policy. It does
not authenticate a running process. Launch admission must also verify the
connected kernel audit-token peer and match it to the actual launched helper.
See Apple's [static code validation API](https://developer.apple.com/documentation/security/secstaticcodecheckvalidity(_:_:_:)),
[guest code lookup API](https://developer.apple.com/documentation/security/seccodecopyguestwithattributes(_:_:_:_:)),
and [audit-token guest attribute](https://developer.apple.com/documentation/security/ksecguestattributeaudit).

## Chrome launch-image hardlinks

`VerifyChromeExecutable` is limited to the enrolled canonical Chrome main image.
Chromium's [CodeSignCloneManager](https://chromium.googlesource.com/chromium/src/+/refs/tags/135.0.7049.7/chrome/browser/mac/code_sign_clone_manager.mm)
hardlinks that executable into its launch clone. Chrome verification permits that
link count while retaining the exact canonical static code requirement, ownership,
mode and no-symlink checks. A different running path normally qualifies when canonical
and actual main executable have identical device/inode and stable file metadata.
Both paths are rechecked across canonical static verification, exact dynamic PID
signature verification, and PID/birth/UID/ancestry reinspection. Clone resource
metadata does not replace canonical bundle validation. Process evidence preserves
the kernel-reported path; neither a clone-name substring nor copied file bytes
qualifies. If a Chrome update replaces the canonical executable while the old
process remains running, the kernel-selected running image can instead qualify
under the original enrolled requirement and the independent Google signer.
Both static image signatures and dynamic process signatures are checked, with
stable file metadata and PID/birth/UID/parent ancestry across the checks. The
new on-disk image does not supply a replacement pin. Verifier construction
alone grants no authority; full peer and running-process verification precede
credential loading and request admission. Native-host and broker executable
verification still requires one link.

## Native helper rendezvous

`backend/darwin.Options` accepts `Requirement` and `ExpectedUID` as trusted
enrollment configuration. Both must be configured together. A mutation launch
also requires a supervisor-owned inherited `Fence`; omitting trust configuration
rejects mutation opt-in. Observation-only fixture launches may omit both trust
options, and do not thereby acquire verified launch identity.

Configured `NewClient` first verifies the executable, then creates a private
0700 temporary directory, a 0600 Unix socket, and a random 32-byte nonce. It
strips inherited `MECHANIZE_IDENTITY_SOCKET` and `MECHANIZE_IDENTITY_NONCE`
variables and supplies fresh values to this launch. The helper sends a bounded,
length-prefixed nonce frame on that socket. The broker verifies the peer's code
requirement and UID, matches `AuditPID` to the launched child, and checks the
nonce in constant time. The socket and nonce are rendezvous evidence; the
kernel audit-token verification remains mandatory.

Within a two-second deadline, further shortened by the caller's deadline, the
broker compares libproc PID/start identity before and after the handshake,
checks the expected executable and UID, and confirms that the executable file
still has the same identity. Only then does it acknowledge the helper, allowing
its protocol and watchdog to begin. Handshake failure closes and reaps the
helper; if teardown fails, `NewClient` returns the client alongside the error so
the lifecycle owner can retain its fence. Later `Client.Identity()` checks that
the current process identity still matches the authenticated launch identity.

Code identity grants no action consent, app enrollment, Accessibility,
Screen Recording, or event-posting permission. TCC and operation authorization
remain separate gates. These latest source trust options are not yet included
in the previously installed development build; that build's read-only smoke
results do not establish coverage of this handshake or control admission.

## Verification scope

Default native-peer tests verify requirement parsing and platform behavior.
`MECHANIZE_SIGNED_PEER_FIXTURE=1 go test ./auth/nativepeer` additionally builds
and ad hoc signs a disposable C Unix client, pins its exact CDHash, verifies its
audit-token identity, and rejects different UIDs and code identities.
`backend/darwin` also contains inert signed helper fixtures for the launched
process handshake, wrong requirement, wrong nonce, and a differently launched
peer carrying the same signature. They do not initialize AX/TCC or dispatch
desktop input. These fixtures do not prove Developer ID signing, product
enrollment, Keychain authorization, or a release build's console integration.
