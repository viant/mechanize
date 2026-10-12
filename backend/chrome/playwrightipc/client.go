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
	"strings"
	"sync"
	"syscall"
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
type Client struct{ config Config }

func New(c Config) (*Client, error) {
	if validate(c) != nil {
		return nil, ErrUnavailable
	}
	return &Client{c}, nil
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

func (c *Client) Execute(ctx context.Context, id string, command any, handler Handler, events <-chan Event) (Result, error) {
	commandJSON, marshalError := json.Marshal(command)
	if marshalError != nil || len(commandJSON) > 256*1024 {
		return Result{}, failure(ctx, "playwrightIPCFrame")
	}
	if c == nil || handler == nil || validate(c.config) != nil {
		return Result{}, failure(ctx, "playwrightRuntimeQualification")
	}
	child := exec.CommandContext(ctx, c.config.NodePath, filepath.Join(c.config.RuntimeRoot, "sidecar.mjs"))
	child.Dir = c.config.RuntimeRoot
	child.Env = []string{"PATH=/usr/bin:/bin", "LANG=en_US.UTF-8", "LC_ALL=en_US.UTF-8"}
	child.Stderr = io.Discard
	input, e := child.StdinPipe()
	if e != nil {
		return Result{}, failure(ctx, "playwrightChildLaunch")
	}
	output, e := child.StdoutPipe()
	if e != nil {
		input.Close()
		return Result{}, failure(ctx, "playwrightChildLaunch")
	}
	if child.Start() != nil {
		input.Close()
		return Result{}, failure(ctx, "playwrightChildLaunch")
	}
	defer func() { input.Close(); child.Process.Kill(); child.Wait() }()
	var writeMu sync.Mutex
	write := func(v any) error {
		raw, e := json.Marshal(v)
		if e != nil || len(raw) > Limit {
			return ErrUnavailable
		}
		writeMu.Lock()
		defer writeMu.Unlock()
		_, e = input.Write(append(raw, 10))
		return e
	}
	if write(map[string]any{"type": "execute", "id": id, "command": command}) != nil {
		return Result{}, failure(ctx, "playwrightIPCWrite")
	}
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case event, ok := <-events:
				if !ok {
					return
				}
				_ = write(map[string]any{"type": "relayEvent", "relayId": event.RelayID, "method": event.Method, "params": event.Params})
			}
		}
	}()
	scanner := bufio.NewScanner(output)
	scanner.Buffer(make([]byte, 4096), Limit+1)
	seen := map[string]bool{}
	for scanner.Scan() {
		raw := scanner.Bytes()
		if len(raw) > Limit {
			return Result{}, failure(ctx, "playwrightIPCFrame")
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
			if envelope.ID != id {
				return Result{}, failure(ctx, "playwrightIPCProtocol")
			}
			var r Result
			d := json.NewDecoder(bytes.NewReader(envelope.Result))
			d.DisallowUnknownFields()
			if d.Decode(&r) != nil || d.Decode(new(any)) != io.EOF {
				return Result{}, failure(ctx, "playwrightIPCProtocol")
			}
			return r, nil
		}
		if envelope.Type != "callback" || envelope.ExecutionID != id || !strings.HasPrefix(envelope.Method, "relay.") && envelope.Method != "admit" && envelope.Method != "current" && envelope.Method != "intent.confirm" && envelope.Method != "receipt.persist" {
			return Result{}, failure(ctx, "playwrightIPCProtocol")
		}
		if seen[envelope.ID] || len(seen) >= 4096 {
			return Result{}, failure(ctx, "playwrightIPCProtocol")
		}
		seen[envelope.ID] = true
		result, e := handler(ctx, Callback{envelope.Method, append(json.RawMessage(nil), envelope.Params...)})
		response := map[string]any{"type": "callbackResult", "id": envelope.ID}
		if e != nil {
			response["errorCode"] = "playwrightHostDenied"
			state := "notDispatched"
			var boundary *CallbackError
			if errors.As(e, &boundary) {
				response["errorCode"] = CallbackCode(boundary.Code)
				if boundary.DispatchState == "unknown" {
					state = "unknown"
				}
			}
			response["dispatchState"] = state
		} else {
			response["result"] = result
		}
		if write(response) != nil {
			return Result{}, failure(ctx, "playwrightIPCWrite")
		}
	}
	if errors.Is(scanner.Err(), bufio.ErrTooLong) {
		return Result{}, failure(ctx, "playwrightIPCFrame")
	}
	return Result{}, failure(ctx, "playwrightChildExited")
}
