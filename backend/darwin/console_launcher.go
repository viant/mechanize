package darwin

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/viant/mechanize/auth/nativepeer"
	"github.com/viant/mechanize/session"
	"golang.org/x/sys/unix"
)

// ConsoleLaunchOptions is immutable operator enrollment, not a tool argument.
// The fixed signed app owns the process launch and its macOS responsibility.
type ConsoleLaunchOptions struct{ SocketPath, Requirement string }
type consoleChild struct {
	conn     *net.UnixConn
	nonce    string
	pid      int
	verify   func() error
	stopOnce sync.Once
	reaped   atomic.Bool
}
type consoleLaunchReply struct {
	Version int    `json:"version"`
	Nonce   string `json:"nonce"`
	State   string `json:"state"`
	PID     int    `json:"pid"`
	Status  *int   `json:"status,omitempty"`
}

func launchConsoleHelper(ctx context.Context, options Options, handshake *identityHandshake, args []string, files []*os.File) (*consoleChild, error) {
	return launchConsoleHelperWith(ctx, options, handshake, args, files, nativepeer.NewVerifier, nativepeer.AuditPID, session.InspectProcess)
}

// Internal transport test seam; production has no caller-supplied trust hooks.
func launchConsoleHelperWith(ctx context.Context, options Options, handshake *identityHandshake, args []string, files []*os.File,
	factory func(nativepeer.Options) (func(*net.UnixConn) error, error), audit func(*net.UnixConn) (int, error), inspect func(int) (session.ProcessIdentity, bool, error)) (*consoleChild, error) {
	if options.Console == nil || handshake == nil || len(files) != 5 || options.ExpectedUID == nil {
		return nil, ErrPrivateProof
	}
	policy := *options.Console
	if !filepath.IsAbs(policy.SocketPath) || filepath.Clean(policy.SocketPath) != policy.SocketPath || len(policy.SocketPath) > 103 || policy.Requirement == "" {
		return nil, ErrPrivateProof
	}
	for _, path := range []string{filepath.Dir(policy.SocketPath), policy.SocketPath} {
		resolved, e := filepath.EvalSymlinks(path)
		if e != nil || resolved != path {
			return nil, ErrPrivateProof
		}
		info, e := os.Lstat(path)
		if e != nil || info.Mode().Perm()&0077 != 0 {
			return nil, ErrPrivateProof
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != *options.ExpectedUID {
			return nil, ErrPrivateProof
		}
		if path == policy.SocketPath && info.Mode()&os.ModeSocket == 0 {
			return nil, ErrPrivateProof
		}
	}
	verifier, e := factory(nativepeer.Options{ExpectedUID: *options.ExpectedUID, DesignatedRequirement: policy.Requirement})
	if e != nil {
		return nil, ErrPrivateProof
	}
	d := net.Dialer{Timeout: 2 * time.Second}
	connection, e := d.DialContext(ctx, "unix", policy.SocketPath)
	if e != nil {
		return nil, ErrPrivateProof
	}
	conn, ok := connection.(*net.UnixConn)
	if !ok {
		connection.Close()
		return nil, ErrPrivateProof
	}
	success := false
	defer func() {
		if !success {
			conn.Close()
		}
	}()
	deadline := time.Now().Add(5 * time.Second)
	if end, ok := ctx.Deadline(); ok && end.Before(deadline) {
		deadline = end
	}
	conn.SetDeadline(deadline)
	if verifier(conn) != nil {
		return nil, ErrPrivateProof
	}
	pid, e := audit(conn)
	if e != nil {
		return nil, ErrPrivateProof
	}
	identity, alive, e := inspect(pid)
	if e != nil || !alive {
		return nil, ErrPrivateProof
	}
	verify := func() error {
		if verifier(conn) != nil {
			return ErrPrivateProof
		}
		current, alive, e := inspect(pid)
		if e != nil || !alive || current != identity {
			return ErrPrivateProof
		}
		return nil
	}
	if verify() != nil {
		return nil, ErrPrivateProof
	}
	descriptors := make([]int, len(files))
	for i, f := range files {
		if f == nil {
			return nil, ErrPrivateProof
		}
		descriptors[i] = int(f.Fd())
	}
	n, oob, e := conn.WriteMsgUnix([]byte{1}, unix.UnixRights(descriptors...), nil)
	if e != nil || n != 1 || oob != len(unix.UnixRights(descriptors...)) {
		return nil, ErrPrivateProof
	}
	request := struct {
		Version            int      `json:"version"`
		Operation          string   `json:"op"`
		Nonce              string   `json:"nonce"`
		Arguments          []string `json:"arguments"`
		IdentitySocket     string   `json:"identitySocket"`
		IdentityNonce      string   `json:"identityNonce"`
		HelperRequirement  string   `json:"helperRequirement"`
		ConsoleRequirement string   `json:"consoleRequirement"`
	}{1, "launch", handshake.nonce, args, filepath.Join(handshake.directory, "peer.sock"), handshake.nonce, options.Requirement, policy.Requirement}
	raw, e := json.Marshal(request)
	if e != nil || verify() != nil || consoleWriteFrame(conn, raw) != nil {
		return nil, ErrPrivateProof
	}
	reply, e := readConsoleReply(conn, handshake.nonce, "launched", 0)
	if e != nil || verify() != nil {
		return nil, ErrPrivateProof
	}
	conn.SetDeadline(time.Time{})
	success = true
	return &consoleChild{conn: conn, nonce: handshake.nonce, pid: reply.PID, verify: verify}, nil
}
func consoleWriteFrame(conn *net.UnixConn, raw []byte) error {
	if len(raw) == 0 || len(raw) > 32768 {
		return ErrPrivateProof
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(raw)))
	if e := writeAll(conn, header[:]); e != nil {
		return e
	}
	return writeAll(conn, raw)
}
func readConsoleReply(conn *net.UnixConn, nonce, state string, pid int) (consoleLaunchReply, error) {
	var result consoleLaunchReply
	raw, e := readFrameBounded(conn, 8192)
	if e != nil || closedPrivateReply(raw, &result) != nil {
		return result, ErrPrivateProof
	}
	var fields map[string]any
	json.Unmarshal(raw, &fields)
	count := 4
	if state == "exited" {
		count = 5
	}
	if len(fields) != count || result.Version != 1 || result.Nonce != nonce || result.State != state || result.PID <= 0 || pid != 0 && result.PID != pid || state == "launched" && result.Status != nil || state == "exited" && (result.Status == nil || *result.Status < 0 || *result.Status > 65535) {
		return result, ErrPrivateProof
	}
	return result, nil
}

var ErrConsoleHelperExit = errors.New("console-owned helper exited unsuccessfully")

func (c *consoleChild) wait() error {
	defer c.conn.Close()
	reply, e := readConsoleReply(c.conn, c.nonce, "exited", c.pid)
	if e != nil {
		return ErrPrivateProof
	}
	if c.verify() != nil {
		return ErrPrivateProof
	}
	c.reaped.Store(true)
	// The console holds this socket open until this acknowledgement. Darwin
	// cannot re-query peer audit credentials after the peer closes its endpoint.
	ack, _ := json.Marshal(map[string]any{"version": 1, "op": "reaped", "nonce": c.nonce, "pid": c.pid})
	c.conn.SetWriteDeadline(time.Now().Add(time.Second))
	if consoleWriteFrame(c.conn, ack) != nil {
		return ErrPrivateProof
	}
	if *reply.Status != 0 {
		return ErrConsoleHelperExit
	}
	return nil
}
func (c *consoleChild) stop() {
	c.stopOnce.Do(func() {
		if c.verify() != nil {
			c.conn.Close()
			return
		}
		raw, _ := json.Marshal(map[string]any{"version": 1, "op": "stop", "nonce": c.nonce, "pid": c.pid})
		c.conn.SetWriteDeadline(time.Now().Add(time.Second))
		c.conn.SetReadDeadline(time.Now().Add(time.Second))
		if consoleWriteFrame(c.conn, raw) != nil {
			c.conn.Close()
		}
	})
}
