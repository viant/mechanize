//go:build darwin || linux

package keychain

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/viant/mechanize/auth"
	"golang.org/x/sys/unix"
)

// Verifiers are trusted installer dependencies, never wire input. The running
// verifier must check this exact spawned process's identity/birth and signature.
type migrationProcessSpec struct {
	executable  string
	requirement string
	session     string
	arguments   []string
	// Dedicated connected Unix stream to the enrolled native console. It is
	// inherited as fd 3, never copied into stdin, argv, environment or output.
	// The worker independently authenticates its actual socket peer.
	console       *os.File
	verifyFile    func(context.Context, string, string) error
	verifyRunning func(context.Context, *os.Process, string) error
}
type migrationChildProcess struct {
	mu        sync.Mutex
	stopOnce  sync.Once
	command   *exec.Cmd
	input     *os.File
	output    *os.File
	ready     *os.File
	null      *os.File
	cancel    context.CancelFunc
	done      chan struct{}
	session   string
	namespace string
	clientID  string
	used      map[string]bool
	failed    bool
	unknown   bool
}

func (*migrationChildProcess) String() string   { return "Keychain migration child" }
func (*migrationChildProcess) GoString() string { return "Keychain migration child" }
func (*migrationChildProcess) MarshalJSON() ([]byte, error) {
	return []byte(`{"state":"private"}`), nil
}
func migrationProcessFile(path string) (unix.Stat_t, error) {
	var info unix.Stat_t
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return info, errMigrationUnavailable
	}
	defer unix.Close(fd)
	if unix.Fstat(fd, &info) != nil || info.Mode&unix.S_IFMT != unix.S_IFREG || info.Uid != uint32(os.Getuid()) || info.Mode&0o022 != 0 || info.Mode&0o100 == 0 || info.Nlink != 1 {
		return info, errMigrationUnavailable
	}
	return info, nil
}
func startMigrationChild(ctx context.Context, spec migrationProcessSpec) (*migrationChildProcess, error) {
	if migrationContext(ctx) != nil || !filepath.IsAbs(spec.executable) || filepath.Clean(spec.executable) != spec.executable || !migrationWorkerExecutorPin.MatchString(spec.requirement) || !validMigrationID(spec.session) || spec.verifyFile == nil || spec.verifyRunning == nil {
		return nil, errMigrationUnavailable
	}
	before, err := migrationProcessFile(spec.executable)
	if err != nil || spec.verifyFile(ctx, spec.executable, spec.requirement) != nil || migrationContext(ctx) != nil {
		return nil, errMigrationUnavailable
	}
	principal, err := auth.FromContext(ctx)
	if err != nil {
		return nil, errMigrationUnavailable
	}
	lifetime, cancel := context.WithTimeout(ctx, 240*time.Second)
	p := &migrationChildProcess{cancel: cancel, done: make(chan struct{}), session: spec.session, namespace: principal.Namespace, clientID: principal.ClientID, used: map[string]bool{}}
	childInput, parentInput, err := os.Pipe()
	if err != nil {
		cancel()
		return nil, errMigrationUnavailable
	}
	parentOutput, childOutput, err := os.Pipe()
	if err != nil {
		childInput.Close()
		parentInput.Close()
		cancel()
		return nil, errMigrationUnavailable
	}
	null, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		childInput.Close()
		parentInput.Close()
		parentOutput.Close()
		childOutput.Close()
		cancel()
		return nil, errMigrationUnavailable
	}
	command := exec.Command(spec.executable, spec.arguments...)
	command.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"}
	if home, err := migrationUserHomeDir(); err == nil {
		command.Env = append(command.Env, "HOME="+home)
	}
	command.Stdin = childInput
	command.Stdout = childOutput
	command.Stderr = null
	p.command = command
	p.input = parentInput
	p.output = parentOutput
	p.null = null
	var childReady *os.File
	if spec.console != nil {
		if !migrationConsoleDescriptor(spec.console) {
			childInput.Close()
			childOutput.Close()
			p.closePipes()
			cancel()
			return nil, errMigrationUnavailable
		}
		p.ready, childReady, err = os.Pipe()
		if err != nil {
			childInput.Close()
			childOutput.Close()
			p.closePipes()
			cancel()
			return nil, errMigrationUnavailable
		}
		command.ExtraFiles = []*os.File{spec.console, childReady}
	}
	if command.Start() != nil {
		childInput.Close()
		childOutput.Close()
		if childReady != nil {
			childReady.Close()
		}
		p.closePipes()
		cancel()
		return nil, errMigrationUnavailable
	}
	childInput.Close()
	childOutput.Close()
	if childReady != nil {
		childReady.Close()
	}
	go func() { _ = command.Wait(); close(p.done) }()
	go func() {
		select {
		case <-lifetime.Done():
			p.stop()
		case <-p.done:
		}
	}()
	if p.ready != nil && p.waitReady(lifetime) != nil {
		p.stop()
		return nil, errMigrationUnavailable
	}
	after, fileErr := migrationProcessFile(spec.executable)
	if fileErr != nil || before.Dev != after.Dev || before.Ino != after.Ino || spec.verifyRunning(lifetime, command.Process, spec.requirement) != nil || spec.verifyFile(lifetime, spec.executable, spec.requirement) != nil || migrationContext(lifetime) != nil {
		p.stop()
		return nil, errMigrationUnavailable
	}
	return p, nil
}

// Readiness only synchronizes startup. Running code and the actual socket peer
// are independently verified before any private credential exchange.
func (p *migrationChildProcess) waitReady(parent context.Context) error {
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	result := make(chan bool, 1)
	go func() {
		data, err := io.ReadAll(io.LimitReader(p.ready, 9))
		result <- err == nil && string(data) == "MMREADY1"
	}()
	select {
	case <-ctx.Done():
		return errMigrationUnavailable
	case valid := <-result:
		if !valid || ctx.Err() != nil {
			return errMigrationUnavailable
		}
		_ = p.ready.Close()
		return nil
	}
}

func migrationConsoleDescriptor(file *os.File) bool {
	if file == nil {
		return false
	}
	fd := int(file.Fd())
	var info unix.Stat_t
	if unix.Fstat(fd, &info) != nil || info.Mode&unix.S_IFMT != unix.S_IFSOCK {
		return false
	}
	kind, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE)
	if err != nil || kind != unix.SOCK_STREAM {
		return false
	}
	local, err := unix.Getsockname(fd)
	if err != nil {
		return false
	}
	remote, err := unix.Getpeername(fd)
	if err != nil {
		return false
	}
	_, localUnix := local.(*unix.SockaddrUnix)
	_, remoteUnix := remote.(*unix.SockaddrUnix)
	return localUnix && remoteUnix
}
func (p *migrationChildProcess) closePipes() {
	if p.ready != nil {
		_ = p.ready.Close()
	}
	if p.input != nil {
		_ = p.input.Close()
	}
	if p.output != nil {
		_ = p.output.Close()
	}
	if p.null != nil {
		_ = p.null.Close()
	}
}

// Only the process spawned and held by this object is terminated. This is not
// a shared broker/helper restart. Process exit never proves ACL outcome.
func (p *migrationChildProcess) stop() {
	if p == nil {
		return
	}
	p.stopOnce.Do(func() {
		p.cancel()
		if p.command != nil && p.command.Process != nil {
			_ = p.command.Process.Kill()
		}
		p.closePipes()
	})
}
func (p *migrationChildProcess) close() { p.stop() }
func migrationProcessResponseMatches(op, status string) bool {
	if status == "unavailable" || status == "unknown" {
		return true
	}
	switch op {
	case "prepare":
		return status == "prepared"
	case "verify":
		return status == "checked"
	case "commit", "inspect":
		return status == "verified"
	case "close":
		return status == "closed"
	}
	return false
}
func (p *migrationChildProcess) exchange(ctx context.Context, request migrationWorkerRequest) (migrationWorkerResponse, error) {
	if p == nil || migrationContext(ctx) != nil {
		return migrationWorkerResponse{}, errMigrationUnavailable
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	principal, err := auth.FromContext(ctx)
	if migrationContext(ctx) != nil || err != nil || len(p.used) >= migrationWorkerMessageLimit || principal.Namespace != p.namespace || principal.ClientID != p.clientID || p.failed || !validMigrationWorkerRequest(request) || request.Session != p.session || p.used[request.ID] || (p.unknown && request.Operation != "inspect" && request.Operation != "close") {
		return migrationWorkerResponse{}, errMigrationUnavailable
	}
	p.used[request.ID] = true
	// Latch before writing any commit bytes. Partial delivery/lost acknowledgement
	// must not permit replay; only coordinator/journal reconciliation proves result.
	if request.Operation == "commit" {
		p.unknown = true
	}
	type result struct {
		response migrationWorkerResponse
		err      error
	}
	complete := make(chan result, 1)
	go func() {
		if writeMigrationWorkerRequest(p.input, request) != nil {
			complete <- result{err: errMigrationUnavailable}
			return
		}
		response, err := readMigrationWorkerResponse(p.output)
		complete <- result{response, err}
	}()
	select {
	case <-ctx.Done():
		p.failed = true
		p.stop()
		if p.unknown {
			return migrationWorkerResponse{}, errMigrationUnknown
		}
		return migrationWorkerResponse{}, errMigrationUnavailable
	case received := <-complete:
		if received.err != nil || received.response.ID != request.ID || received.response.Session != p.session || !migrationProcessResponseMatches(request.Operation, received.response.Status) || migrationContext(ctx) != nil {
			p.failed = true
			p.stop()
			if p.unknown {
				return migrationWorkerResponse{}, errMigrationUnknown
			}
			return migrationWorkerResponse{}, errMigrationUnavailable
		}
		if received.response.Status == "unknown" {
			p.unknown = true
		}
		if request.Operation == "close" {
			p.stop()
		}
		return received.response, nil
	}
}

// File staging must wait for this exact child to exit. Exit is process evidence
// only; it never clears an unknown Keychain outcome.
func (p *migrationChildProcess) waitStopped(ctx context.Context) error {
	if p == nil || ctx == nil {
		return errMigrationUnavailable
	}
	if _, bounded := ctx.Deadline(); !bounded {
		return errMigrationUnavailable
	}
	select {
	case <-p.done:
		return nil
	case <-ctx.Done():
		return errMigrationUnavailable
	}
}
