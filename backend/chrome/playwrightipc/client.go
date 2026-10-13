// Package playwrightipc owns the private local Node child transport. It exposes
// no MCP/browser endpoint and never logs command, callback or provider contents.
package playwrightipc

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const Limit = 512 * 1024

var ErrUnavailable = errors.New("local Playwright transport unavailable")

// FailureReason is a closed local transport phase. It never contains paths,
// provider output, callback parameters or browser data.
type failureReason string

func (r failureReason) Error() string        { return "local Playwright transport unavailable" }
func (r failureReason) Is(target error) bool { return target == ErrUnavailable }
func FailureCode(err error) string {
	var reason failureReason
	if !errors.As(err, &reason) {
		return "playwrightUnavailable"
	}
	switch string(reason) {
	case "playwrightRuntimeQualification", "playwrightChildLaunch", "playwrightDeadline", "playwrightIPCFrame", "playwrightIPCProtocol", "playwrightIPCWrite", "playwrightChildExited":
		return string(reason)
	}
	return "playwrightUnavailable"
}
func failure(ctx context.Context, code string) error {
	if ctx.Err() != nil {
		return failureReason("playwrightDeadline")
	}
	return failureReason(code)
}

type Config struct {
	NodePath      string `json:"nodePath"`
	NodeSHA256    string `json:"nodeSHA256"`
	RuntimeRoot   string `json:"runtimeRoot"`
	RuntimeSHA256 string `json:"runtimeSHA256"`
}

// Client retains only the qualified local runtime. Authority, handlers, events
// and command results belong to one Execute call and are never cached here.
type Client struct {
	config Config
	lane   chan struct{}
	closed chan struct{}
	mu     sync.Mutex
	child  *process
	serial uint64 // owned by lane; distinguishes even repeated caller IDs
}

func New(c Config) (*Client, error) {
	if validate(c) != nil {
		return nil, ErrUnavailable
	}
	return &Client{config: c, lane: make(chan struct{}, 1), closed: make(chan struct{})}, nil
}
func safeFile(path string) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrUnavailable
	}
	real, e := filepath.EvalSymlinks(path)
	if e != nil || real != path {
		return nil, ErrUnavailable
	}
	f, e := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if e != nil {
		return nil, ErrUnavailable
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil {
		return nil, ErrUnavailable
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if e != nil || !ok || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || owner.Uid != uint32(os.Getuid()) && owner.Uid != 0 || info.Size() > 256*1024*1024 {
		return nil, ErrUnavailable
	}
	return io.ReadAll(io.LimitReader(f, 256*1024*1024+1))
}
func digest(value []byte) string { s := sha256.Sum256(value); return hex.EncodeToString(s[:]) }

// RuntimeDigest binds the complete reviewed runtime, including playwright-core
// dependencies, against locally writable substitutions. Symlinks are refused.
func RuntimeDigest(root string) (string, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return "", ErrUnavailable
	}
	real, e := filepath.EvalSymlinks(root)
	if e != nil || real != root {
		return "", ErrUnavailable
	}
	var paths []string
	e = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.Type()&os.ModeSymlink != 0 {
			return ErrUnavailable
		}
		info, err := entry.Info()
		if err != nil {
			return ErrUnavailable
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok || info.Mode().Perm()&0022 != 0 || owner.Uid != uint32(os.Getuid()) && owner.Uid != 0 {
			return ErrUnavailable
		}
		if entry.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() {
			return ErrUnavailable
		}
		paths = append(paths, path)
		if len(paths) > 10000 {
			return ErrUnavailable
		}
		return nil
	})
	if e != nil {
		return "", ErrUnavailable
	}
	sort.Strings(paths)
	h := sha256.New()
	for _, path := range paths {
		raw, e := safeFile(path)
		if e != nil {
			return "", e
		}
		rel, _ := filepath.Rel(root, path)
		metadata, _ := json.Marshal([]string{rel, digest(raw)})
		h.Write(metadata)
		h.Write([]byte{10})
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func validate(c Config) error {
	if len(c.NodeSHA256) != 64 || len(c.RuntimeSHA256) != 64 {
		return ErrUnavailable
	}
	node, e := safeFile(c.NodePath)
	if e != nil || digest(node) != c.NodeSHA256 {
		return ErrUnavailable
	}
	tree, e := RuntimeDigest(c.RuntimeRoot)
	if e != nil || tree != c.RuntimeSHA256 {
		return ErrUnavailable
	}
	for _, name := range []string{"sidecar.mjs", "engine.mjs", "relay.mjs", "fingerprint.cjs", "target.cjs", "package-lock.json", "node_modules/playwright-core/package.json"} {
		if _, e = safeFile(filepath.Join(c.RuntimeRoot, name)); e != nil {
			return ErrUnavailable
		}
	}
	return nil
}

type Callback struct {
	Method string
	Params json.RawMessage
}

// CallbackError carries only the broker's dispatch classification and a closed
// diagnostic code. Underlying errors never enter IPC or model output.
type CallbackError struct {
	DispatchState string
	Code          string
}

// CallbackCode deliberately uses no prefixes/regular expressions: unrecognized
// worker/provider strings may contain private values and collapse to one code.
func CallbackCode(code string) string {
	switch code {
	case "playwrightAuthorityChanged", "playwrightAuthorityDenied", "playwrightAuthorityRequired", "playwrightBindingChanged", "playwrightBindingDenied", "playwrightCDPDenied", "playwrightDocumentChanged", "playwrightTargetChanged", "playwrightTargetDenied", "playwrightTargetUnpinned", "playwrightAttemptReplay", "playwrightBusy", "playwrightCommandDenied", "playwrightEnvelopeDenied", "playwrightFingerprintMismatch", "playwrightFrameTooLarge", "playwrightInputReplay", "playwrightInputSequenceDenied", "playwrightInputUncertain", "playwrightJournalInvalid", "playwrightReadInputDenied", "playwrightReceiptCapacity", "playwrightReceiptDenied", "playwrightReceiptFinal", "playwrightReceiptUncertain", "playwrightRedactionDenied", "playwrightRequestReplay", "playwrightPrivateDOMDenied", "playwrightDeadline", "playwrightRelayDenied", "playwrightUnavailable":
		return code
	}
	return "playwrightHostDenied"
}

func (e *CallbackError) Error() string { return "local Playwright callback unavailable" }

// Handler runs inline for one invocation and must honor its context. The
// transport never detaches a broker callback that could later acquire authority.
type Handler func(context.Context, Callback) (any, error)
type Result struct {
	RequestID      string  `json:"requestId"`
	DispatchState  string  `json:"dispatchState"`
	EffectState    string  `json:"effectState"`
	ErrorCode      string  `json:"errorCode,omitempty"`
	Value          *string `json:"value,omitempty"`
	InputSemantics string  `json:"inputSemantics,omitempty"`
}
type Event struct {
	RelayID string
	Method  string
	Params  json.RawMessage
}

// process has one reader and one waiter for its entire lifetime. Killing it
// closes both pipe ends, unblocks writes/reads, and prevents late frames from
// being handed to a replacement child. Per-command event pumps are joined before reuse.
type process struct {
	command   *exec.Cmd
	input     io.WriteCloser
	output    io.ReadCloser
	frames    chan []byte
	readDone  chan struct{}
	exited    chan struct{}
	stop      chan struct{}
	once      sync.Once
	writeMu   sync.Mutex
	readError string // published by closing readDone
}

func startProcess(config Config) (*process, error) {
	command := exec.Command(config.NodePath, filepath.Join(config.RuntimeRoot, "sidecar.mjs"))
	command.Dir = config.RuntimeRoot
	command.Env = []string{"PATH=/usr/bin:/bin", "LANG=en_US.UTF-8", "LC_ALL=en_US.UTF-8"}
	command.Stderr = io.Discard
	input, err := command.StdinPipe()
	if err != nil {
		return nil, err
	}
	output, writer, err := os.Pipe()
	if err != nil {
		input.Close()
		return nil, err
	}
	command.Stdout = writer
	if err = command.Start(); err != nil {
		input.Close()
		output.Close()
		writer.Close()
		return nil, err
	}
	writer.Close()
	p := &process{command: command, input: input, output: output, frames: make(chan []byte), readDone: make(chan struct{}), exited: make(chan struct{}), stop: make(chan struct{}), readError: "playwrightChildExited"}
	go func() { _ = command.Wait(); close(p.exited) }()
	go func() {
		defer close(p.readDone)
		defer p.terminate()
		scanner := bufio.NewScanner(output)
		scanner.Buffer(make([]byte, 4096), Limit+1)
		for scanner.Scan() {
			raw := append([]byte(nil), scanner.Bytes()...)
			if len(raw) > Limit {
				p.readError = "playwrightIPCFrame"
				return
			}
			select {
			case p.frames <- raw:
			case <-p.stop:
				return
			}
		}
		p.readError = "playwrightChildExited"
		if errors.Is(scanner.Err(), bufio.ErrTooLong) {
			p.readError = "playwrightIPCFrame"
		}
	}()
	return p, nil
}

func (p *process) write(value any) error {
	raw, err := json.Marshal(value)
	if err != nil || len(raw) > Limit {
		return ErrUnavailable
	}
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	_, err = p.input.Write(append(raw, 10))
	return err
}

func (p *process) terminate() {
	p.once.Do(func() {
		close(p.stop)
		_ = p.command.Process.Kill()
		_ = p.input.Close()
		_ = p.output.Close()
	})
}

func (p *process) await() error {
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	for _, done := range []<-chan struct{}{p.exited, p.readDone} {
		select {
		case <-done:
		case <-timer.C:
			return ErrUnavailable
		}
	}
	return nil
}

// Close rejects future work and cancels the active invocation. Cleanup is
// bounded, and callers may safely close the client more than once.
func (c *Client) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	select {
	case <-c.closed:
	default:
		close(c.closed)
	}
	p := c.child
	c.mu.Unlock()
	if p != nil {
		p.terminate()
		return p.await()
	}
	return nil
}

func (c *Client) discard(p *process) {
	p.terminate()
	_ = p.await()
	c.mu.Lock()
	if c.child == p {
		c.child = nil
	}
	c.mu.Unlock()
}

func (c *Client) process(ctx context.Context) (*process, error) {
	c.mu.Lock()
	select {
	case <-c.closed:
		c.mu.Unlock()
		return nil, failure(ctx, "playwrightChildExited")
	default:
	}
	p := c.child
	c.mu.Unlock()
	if p != nil {
		select {
		case <-p.exited:
			c.discard(p)
		default:
			return p, nil
		}
	}
	// A replacement must match the original pins, even after a prior child
	// died. A warm invocation never rehashes the entire reviewed runtime.
	if validate(c.config) != nil {
		return nil, failure(ctx, "playwrightRuntimeQualification")
	}
	if ctx.Err() != nil {
		return nil, failure(ctx, "playwrightDeadline")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
		return nil, failure(ctx, "playwrightChildExited")
	default:
	}
	p, err := startProcess(c.config)
	if err != nil {
		return nil, failure(ctx, "playwrightChildLaunch")
	}
	c.child = p
	return p, nil
}

func (c *Client) Execute(ctx context.Context, id string, command any, handler Handler, events <-chan Event) (Result, error) {
	commandJSON, marshalError := json.Marshal(command)
	if marshalError != nil || len(commandJSON) > 256*1024 {
		return Result{}, failure(ctx, "playwrightIPCFrame")
	}
	if c == nil || handler == nil {
		return Result{}, failure(ctx, "playwrightRuntimeQualification")
	}
	if !executionID(id) {
		return Result{}, failure(ctx, "playwrightIPCProtocol")
	}
	// Waiting for another command consumes the original deadline. A timed out
	// waiter never writes a frame or cancels the invocation that owns the lane.
	select {
	case c.lane <- struct{}{}:
		defer func() { <-c.lane }()
	case <-ctx.Done():
		return Result{}, failure(ctx, "playwrightDeadline")
	case <-c.closed:
		return Result{}, failure(ctx, "playwrightChildExited")
	}
	if ctx.Err() != nil {
		return Result{}, failure(ctx, "playwrightDeadline")
	}
	p, err := c.process(ctx)
	if err != nil {
		return Result{}, err
	}
	invocationCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	finished, watcherDone := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(watcherDone)
		select {
		case <-finished:
			return
		case <-ctx.Done():
		case <-c.closed:
		}
		cancel()
		p.terminate()
	}()
	c.serial++
	wireID := "ipc-" + strconv.FormatUint(c.serial, 10)
	eventsDone := make(chan struct{})
	reusable := false
	defer func() {
		close(finished)
		<-watcherDone
		// A child that stops consuming an in-flight event cannot strand the
		// event writer or make it write into the next invocation.
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-eventsDone:
		case <-timer.C:
			reusable = false
			p.terminate()
			<-eventsDone
		}
		timer.Stop()
		if !reusable || invocationCtx.Err() != nil {
			c.discard(p)
		}
	}()
	if p.write(map[string]any{"type": "execute", "id": wireID, "executionId": id, "command": json.RawMessage(commandJSON)}) != nil {
		close(eventsDone)
		return Result{}, failure(ctx, "playwrightIPCWrite")
	}
	if events == nil {
		close(eventsDone)
	} else {
		// CDP events must progress even while an inline broker callback awaits
		// its provider. This pump is joined before the lane is released.
		go func() {
			defer close(eventsDone)
			for {
				select {
				case <-finished:
					return
				case <-invocationCtx.Done():
					return
				case event, ok := <-events:
					if !ok {
						return
					}
					select {
					case <-finished:
						return
					default:
					}
					if invocationCtx.Err() != nil {
						return
					}
					if p.write(map[string]any{"type": "relayEvent", "executionId": wireID, "relayId": event.RelayID, "method": event.Method, "params": event.Params}) != nil {
						p.terminate()
						return
					}
				}
			}
		}()
	}
	seen := map[string]bool{}
	for {
		var raw []byte
		select {
		case <-invocationCtx.Done():
			return Result{}, failure(ctx, "playwrightChildExited")
		case <-p.readDone:
			return Result{}, failure(ctx, p.readError)
		case raw = <-p.frames:
		}
		if invocationCtx.Err() != nil {
			return Result{}, failure(ctx, "playwrightChildExited")
		}
		var envelope struct {
			Type        string          `json:"type"`
			ID          string          `json:"id"`
			ExecutionID string          `json:"executionId,omitempty"`
			Method      string          `json:"method,omitempty"`
			Params      json.RawMessage `json:"params,omitempty"`
			Result      json.RawMessage `json:"result,omitempty"`
		}
		d := json.NewDecoder(bytes.NewReader(raw))
		d.DisallowUnknownFields()
		if d.Decode(&envelope) != nil || d.Decode(new(any)) != io.EOF || envelope.ID == "" || len(envelope.ID) > 128 {
			return Result{}, failure(ctx, "playwrightIPCProtocol")
		}
		if envelope.Type == "result" {
			if envelope.ID != wireID {
				return Result{}, failure(ctx, "playwrightIPCProtocol")
			}
			var r Result
			d := json.NewDecoder(bytes.NewReader(envelope.Result))
			d.DisallowUnknownFields()
			if d.Decode(&r) != nil || d.Decode(new(any)) != io.EOF {
				return Result{}, failure(ctx, "playwrightIPCProtocol")
			}
			reusable = true
			return r, nil
		}
		if envelope.Type != "callback" || envelope.ExecutionID != wireID || !strings.HasPrefix(envelope.Method, "relay.") && envelope.Method != "admit" && envelope.Method != "current" && envelope.Method != "intent.confirm" && envelope.Method != "receipt.persist" {
			return Result{}, failure(ctx, "playwrightIPCProtocol")
		}
		if seen[envelope.ID] || len(seen) >= 4096 {
			return Result{}, failure(ctx, "playwrightIPCProtocol")
		}
		seen[envelope.ID] = true
		result, callbackError := handler(invocationCtx, Callback{envelope.Method, append(json.RawMessage(nil), envelope.Params...)})
		if invocationCtx.Err() != nil {
			return Result{}, failure(ctx, "playwrightChildExited")
		}
		response := map[string]any{"type": "callbackResult", "id": envelope.ID, "executionId": wireID}
		if callbackError != nil {
			response["errorCode"] = "playwrightHostDenied"
			state := "notDispatched"
			var boundary *CallbackError
			if errors.As(callbackError, &boundary) {
				response["errorCode"] = CallbackCode(boundary.Code)
				if boundary.DispatchState == "unknown" {
					state = "unknown"
				}
			}
			response["dispatchState"] = state
		} else {
			response["result"] = result
		}
		if p.write(response) != nil {
			return Result{}, failure(ctx, "playwrightIPCWrite")
		}
	}
}

func executionID(id string) bool {
	if len(id) == 0 || len(id) > 128 {
		return false
	}
	for _, char := range id {
		if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '.' || char == '_' || char == ':' || char == '-' {
			continue
		}
		return false
	}
	return true
}
