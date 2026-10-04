package darwin

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/viant/mechanize/auth/nativepeer"
	"github.com/viant/mechanize/session"
)

const identitySocketEnv = "MECHANIZE_IDENTITY_SOCKET"
const identityNonceEnv = "MECHANIZE_IDENTITY_NONCE"
const identityTimeout = 2 * time.Second
const identityNonceBytes = 32

// identityHandshake is a private, single-use rendezvous. Neither the nonce nor
// the socket is a substitute for Security.framework's kernel audit-token proof.
type identityHandshake struct {
	listener       *net.UnixListener
	directory      string
	nonce          string
	executable     string
	executableInfo os.FileInfo
	expectedUID    uint32
	verify         func(*net.UnixConn) error
}

func prepareIdentity(options Options) (*identityHandshake, error) {
	configured := options.Requirement != "" || options.ExpectedUID != nil
	if !configured {
		if options.AllowMutations || options.AllowLaunch || options.AllowSemantic || options.AllowRecording {
			return nil, errors.New("native action opt-in requires enrolled native helper code requirement and expected UID")
		}
		return nil, nil
	}
	if strings.TrimSpace(options.Requirement) == "" || options.ExpectedUID == nil {
		return nil, errors.New("native helper trust requires both code requirement and expected UID")
	}
	policy := nativepeer.Options{ExpectedUID: *options.ExpectedUID, DesignatedRequirement: options.Requirement}
	verify, err := nativepeer.NewVerifier(policy)
	if err != nil {
		return nil, err
	}
	executable, err := filepath.Abs(options.HelperPath)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(executable)
	if err != nil {
		return nil, err
	}
	if err = nativepeer.VerifyExecutable(executable, policy); err != nil {
		return nil, fmt.Errorf("native helper executable rejected: %w", err)
	}
	verifiedInfo, err := os.Stat(executable)
	if err != nil || !sameExecutable(info, verifiedInfo) {
		return nil, errors.New("native helper executable changed during static verification")
	}
	directory, err := os.MkdirTemp("/tmp", "mechanize-identity-")
	if err != nil {
		return nil, err
	}
	h := &identityHandshake{directory: directory, executable: executable, executableInfo: info, expectedUID: *options.ExpectedUID, verify: verify}
	if err = os.Chmod(directory, 0700); err != nil {
		h.close()
		return nil, err
	}
	nonce := make([]byte, identityNonceBytes)
	if _, err = rand.Read(nonce); err != nil {
		h.close()
		return nil, err
	}
	h.nonce = hex.EncodeToString(nonce)
	h.listener, err = net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(directory, "peer.sock"), Net: "unix"})
	if err != nil {
		h.close()
		return nil, err
	}
	if err = os.Chmod(h.listener.Addr().String(), 0600); err != nil {
		h.close()
		return nil, err
	}
	return h, nil
}

// Strip inherited rendezvous variables even for unconfigured fixture launches.
func (h *identityHandshake) environment() []string {
	result := make([]string, 0, len(os.Environ())+2)
	for _, entry := range os.Environ() {
		if strings.HasPrefix(entry, identitySocketEnv+"=") || strings.HasPrefix(entry, identityNonceEnv+"=") {
			continue
		}
		result = append(result, entry)
	}
	if h != nil {
		result = append(result, identitySocketEnv+"="+h.listener.Addr().String(), identityNonceEnv+"="+h.nonce)
	}
	return result
}
func (h *identityHandshake) close() {
	if h == nil {
		return
	}
	if h.listener != nil {
		_ = h.listener.Close()
	}
	if h.directory != "" {
		_ = os.RemoveAll(h.directory)
	}
}

func (h *identityHandshake) authenticate(ctx context.Context, pid int) (session.ProcessIdentity, error) {
	deadline := time.Now().Add(identityTimeout)
	if end, ok := ctx.Deadline(); ok && end.Before(deadline) {
		deadline = end
	}
	if err := h.listener.SetDeadline(deadline); err != nil {
		return session.ProcessIdentity{}, err
	}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = h.listener.Close()
		case <-done:
		}
	}()
	before, err := h.inspect(pid)
	if err != nil {
		return before, err
	}
	conn, err := h.listener.AcceptUnix()
	if err != nil {
		return before, errors.New("native helper identity rendezvous failed")
	}
	defer conn.Close()
	if err = conn.SetDeadline(deadline); err != nil {
		return before, err
	}
	if err = h.verify(conn); err != nil {
		return before, err
	}
	auditPID, err := nativepeer.AuditPID(conn)
	if err != nil {
		return before, err
	}
	if auditPID != pid {
		return before, errors.New("verified native peer is not the launched helper")
	}
	if err = readIdentityNonce(conn, h.nonce); err != nil {
		return before, err
	}
	after, err := h.inspect(pid)
	if err != nil {
		return before, err
	}
	if before != after {
		return before, errors.New("native helper process identity changed during authentication")
	}
	info, err := os.Stat(h.executable)
	if err != nil || !sameExecutable(h.executableInfo, info) {
		return before, errors.New("native helper executable changed during launch")
	}
	// Acknowledge only after every check: the helper starts its protocol and
	// watchdog only after receiving this byte.
	if err = ctx.Err(); err != nil {
		return before, err
	}
	if err = writeAll(conn, []byte{1}); err != nil {
		return before, err
	}
	return after, nil
}
func (h *identityHandshake) inspect(pid int) (session.ProcessIdentity, error) {
	identity, alive, err := session.InspectProcess(pid)
	if err != nil {
		return identity, err
	}
	if !alive || identity.StartToken == "" || identity.UID != h.expectedUID || identity.Executable != h.executable {
		return identity, errors.New("native helper libproc identity does not match enrolled executable and UID")
	}
	return identity, nil
}
func readIdentityNonce(reader io.Reader, expected string) error {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return errors.New("native helper identity challenge missing")
	}
	if binary.BigEndian.Uint32(header[:]) != uint32(identityNonceBytes*2) {
		return errors.New("invalid native helper identity frame size")
	}
	body := make([]byte, identityNonceBytes*2)
	if _, err := io.ReadFull(reader, body); err != nil {
		return errors.New("native helper identity challenge truncated")
	}
	if subtle.ConstantTimeCompare(body, []byte(expected)) != 1 {
		return errors.New("native helper identity challenge mismatch")
	}
	return nil
}

func sameExecutable(before, after os.FileInfo) bool {
	return before != nil && after != nil && os.SameFile(before, after) && before.Size() == after.Size() && before.Mode() == after.Mode() && before.ModTime().Equal(after.ModTime())
}
