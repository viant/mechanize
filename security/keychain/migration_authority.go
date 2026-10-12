package keychain

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/auth/nativepeer"
)

// Enrolled outside the wire decoder. The peer must be the actual signed native
// console holding the Scy admin credential, not an installer asserting its role.
// A separate broker/installer parent requires its own independently authenticated
// console delegation integration; this adapter does not manufacture delegation.
type migrationNativeEnrollment struct {
	parentRequirement   string
	approvalConsole     *migrationApprovalConsole
	expectedUID         uint32
	namespace, clientID string
	deadline            time.Time
}
type migrationCredentialVerifier interface {
	Verify(context.Context, string) (auth.Principal, error)
}
type migrationNativeAuthority struct {
	mu                  sync.Mutex
	channel             *net.UnixConn
	enrollment          migrationNativeEnrollment
	peer                func(*net.UnixConn) error
	verifier            migrationCredentialVerifier
	credential          []byte
	initialized, closed bool
	expiry              *time.Timer
}

// The factory compiles the exact trusted socket-peer pin. Caller-supplied peer
// callbacks are not accepted here. The private dependency seam below is for tests.
func newMigrationNativeAuthority(channel *net.UnixConn, enrollment migrationNativeEnrollment, verifier *auth.Verifier) (*migrationNativeAuthority, error) {
	if verifier == nil {
		return nil, errMigrationUnavailable
	}
	peer, err := nativepeer.NewVerifier(nativepeer.Options{ExpectedUID: enrollment.expectedUID, DesignatedRequirement: enrollment.parentRequirement})
	if err != nil {
		return nil, errMigrationUnavailable
	}
	return migrationNativeAuthorityWith(channel, enrollment, verifier, migrationApprovalConsolePeer(peer, enrollment.approvalConsole))
}
func migrationNativeAuthorityWith(channel *net.UnixConn, enrollment migrationNativeEnrollment, verifier migrationCredentialVerifier, peer func(*net.UnixConn) error) (*migrationNativeAuthority, error) {
	if channel == nil || verifier == nil || peer == nil || !migrationBootstrapParentPin.MatchString(enrollment.parentRequirement) ||
		!validMigrationID(enrollment.namespace) || enrollment.clientID == "" || len(enrollment.clientID) > 256 ||
		!time.Now().Before(enrollment.deadline) || enrollment.deadline.After(time.Now().Add(240*time.Second)) {
		return nil, errMigrationUnavailable
	}
	// NativeHuman is defined by the enrolled native console, not by an arbitrary
	// signed executable with an admin token. Keep its role exact as well as its hash.
	const prefix = `identifier "com.viant.mechanize.consent" and cdhash H"`
	if len(enrollment.parentRequirement) < len(prefix) || enrollment.parentRequirement[:len(prefix)] != prefix {
		return nil, errMigrationUnavailable
	}
	authority := &migrationNativeAuthority{channel: channel, enrollment: enrollment, peer: peer, verifier: verifier}
	authority.mu.Lock()
	authority.expiry = time.AfterFunc(time.Until(enrollment.deadline), func() {
		_ = channel.Close() // unblock a read before waiting for the authority mutex
		authority.close()
	})
	authority.mu.Unlock()
	return authority, nil
}
func (*migrationNativeAuthority) String() string   { return "Keychain migration native authority" }
func (*migrationNativeAuthority) GoString() string { return "Keychain migration native authority" }
func (*migrationNativeAuthority) MarshalJSON() ([]byte, error) {
	return []byte(`{"state":"private"}`), nil
}

// Dedicated credential frame: eight-byte marker, four-byte big-endian length,
// then credential bytes. Never place it in bootstrap JSON or worker requests.
// This writer is for the native console transport, not a tool/API endpoint.
func writeMigrationNativeCredential(writer io.Writer, credential []byte) error {
	if writer == nil || len(credential) == 0 || len(credential) > 32768 {
		return errMigrationUnavailable
	}
	header := [12]byte{'M', 'M', 'A', 'U', 'T', 'H', 0, 1}
	binary.BigEndian.PutUint32(header[8:], uint32(len(credential)))
	if err := migrationWriteAll(writer, header[:]); err != nil {
		return err
	}
	return migrationWriteAll(writer, credential)
}
func migrationWriteAll(writer io.Writer, value []byte) error {
	for len(value) > 0 {
		n, err := writer.Write(value)
		if err != nil || n <= 0 || n > len(value) {
			return errMigrationUnavailable
		}
		value = value[n:]
	}
	return nil
}
func (a *migrationNativeAuthority) closeLocked() {
	if a.closed {
		return
	}
	a.closed = true
	if a.expiry != nil {
		a.expiry.Stop()
	}
	for i := range a.credential {
		a.credential[i] = 0
	}
	a.credential = nil
	_ = a.channel.Close()
}
func (a *migrationNativeAuthority) close() {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.closeLocked()
}

// Authenticate before bootstrap reads, then again for every worker operation.
// The dedicated socket remains live for revalidation; failure is terminal and
// closes it. The returned context never outlives the trusted enrollment deadline.
func (a *migrationNativeAuthority) authenticate(parent context.Context, requirement string) (context.Context, error) {
	if a == nil || parent == nil || parent.Err() != nil {
		return nil, errMigrationUnavailable
	}
	if _, ok := parent.Deadline(); !ok {
		return nil, errMigrationUnavailable
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return nil, errMigrationUnavailable
	}
	ctx, cancel := context.WithDeadline(parent, a.enrollment.deadline)
	accepted := false
	defer func() {
		if !accepted {
			cancel()
			a.closeLocked()
		}
	}()
	if requirement != a.enrollment.parentRequirement || ctx.Err() != nil || a.peer(a.channel) != nil {
		return nil, errMigrationUnavailable
	}
	deadline, _ := ctx.Deadline()
	if a.channel.SetReadDeadline(deadline) != nil {
		return nil, errMigrationUnavailable
	}
	// Close unblocks a credential read when the caller cancels before its deadline.
	stop := context.AfterFunc(ctx, func() { _ = a.channel.Close() })
	defer stop()
	if !a.initialized {
		a.initialized = true
		var header [12]byte
		if _, err := io.ReadFull(a.channel, header[:]); err != nil {
			return nil, errMigrationUnavailable
		}
		if string(header[:8]) != "MMAUTH\x00\x01" {
			return nil, errMigrationUnavailable
		}
		count := binary.BigEndian.Uint32(header[8:])
		if count == 0 || count > 32768 {
			return nil, errMigrationUnavailable
		}
		a.credential = make([]byte, count)
		if _, err := io.ReadFull(a.channel, a.credential); err != nil {
			return nil, errMigrationUnavailable
		}
	}
	if ctx.Err() != nil || a.peer(a.channel) != nil {
		return nil, errMigrationUnavailable
	}
	principal, err := a.verifier.Verify(ctx, string(a.credential))
	if err != nil || principal.Validate() != nil || !principal.HasScope("consent:admin") || principal.Namespace != a.enrollment.namespace || principal.ClientID != a.enrollment.clientID || ctx.Err() != nil || a.peer(a.channel) != nil {
		return nil, errMigrationUnavailable
	}
	human, err := auth.WithNativeHuman(auth.WithPrincipal(ctx, principal))
	if err != nil || migrationContext(human) != nil {
		return nil, errMigrationUnavailable
	}
	// The deadline owns this timer. Cancellation also follows the caller context.
	accepted = true
	return human, nil
}
func (a *migrationNativeAuthority) workerAuthority(parent context.Context) (context.Context, error) {
	if a == nil {
		return nil, errMigrationUnavailable
	}
	return a.authenticate(parent, a.enrollment.parentRequirement)
}
