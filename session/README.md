# Desktop supervisor

This package owns one physical input fence, independent of app and user database.
`NewSupervisor(Options{LockPath, HelperExecutable, Inspect?, StopOrphan?})` requires
an absolute, explicitly enrolled helper path and lock file inside a private 0700
same-user directory. Production enrollment must choose **one shared LockPath for
the login desktop**, not one path per authenticated user. No signing/audit policy
is inferred from a file lock or PID.

Lifecycle:

1. `Acquire(ctx, principal, Scope{AllowedBundles})`: validates trusted identity and
   desktop:control, obtains nonblocking OS flock and fsyncs a new lease generation.
2. `FenceFile(ctx, principal)`: pass this descriptor to `darwin.Options.Fence`.
3. Launch the helper, obtain `Client.Identity()` (public libproc PID, start-time,
   UID and executable), then `AttachHelper(ctx,p,identity,client.Stop)`.
4. Construct a Gateway. Its Lease callback calls Supervisor.Lease and translates
   the neutral ID/Generation into darwin.Lease or chrome.Lease. The helper itself
   reads bundle scope and enrolled helper PID from the inherited fence file.
5. `Close(ctx)` inhibits/reaps the helper with a two-second callback bound,
   independently proves its old PID/start identity stopped, persists cleanup,
   then unlocks/closes. Failed stop proof retains the fence. Unknown held-input
   cleanup persists a reconciliation barrier; the next Acquire returns
   ErrCleanupUnknown. There is deliberately no automatic uncertainty bypass.

The native helper inherits the same open-file description at FD5, so broker
crash cannot release the OS lock while that helper lives. Watchdog FD4 receives
250ms host heartbeats; native EOF or two-second silence inhibits input, dispatches
held releases and exits independently of a blocked AX request. Every restart
invalidates native epoch/refs. A persisted old helper that remains alive blocks
epoch transfer even if an earlier build did not inherit the lock. StopOrphan is
an optional **trusted enrollment recovery hook**, never a blind kill from a disk
PID. The default refuses transfer and reports ErrOldHelperAlive.

Acquire rejects symlinks, nonprivate files/directories, foreign UID, hardlinked
lock files, corrupt/oversized records and changed held scope. Scope slices are
copied. Metadata writes are fsynced under the OS lock; an interrupted write may
leave a corrupt record, which fails closed and needs operator recovery rather
than inventing an epoch. State-file atomic replacement is intentionally avoided
because it would replace the inode protected by flock.

Tests cover OS contention, cross-user/scope isolation, epoch progression,
old-helper liveness, unsafe records/paths, bounded teardown, unknown cleanup, and
a real non-input process fixture proving inherited-lock retention and public
PID/start identity. Native watchdog tests only inspect nonprompting doctor.

Remaining production gates: stable signed helper bundle/TCC upgrades, audit-token
verification, active/locked/disconnected graphical session qualification,
independent permission-granted input fixture outcomes, platform rollout matrix,
broker circuit breaker and a qualified held-input reconciliation mechanism.
Non-macOS or non-cgo default process inspection explicitly fails; fixtures may
inject an inspector without pretending to qualify the platform.
