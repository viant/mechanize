// Package darwin implements the framed native-helper transport. It does not
// interpret a dispatch receipt as application or business success.
package darwin

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/viant/mechanize/session"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"
)

const ProtocolVersion = 1
const MaximumFrameBytes = 2 * 1024 * 1024

// Only a requested window capture response may contain a full-resolution PNG.
// Requests and every ordinary reply remain limited to MaximumFrameBytes.
const MaximumWindowFrameResponseBytes = ((MaximumCaptureBytes+2)/3)*4 + 65536

type Lease struct {
	ID         string `json:"id"`
	Generation uint64 `json:"generation"`
}
type Request struct {
	ProtocolVersion     int             `json:"protocolVersion"`
	RequestID           string          `json:"requestId"`
	Method              string          `json:"method"`
	HelperEpoch         string          `json:"helperEpoch,omitempty"`
	DeadlineRemainingMS int64           `json:"deadlineRemainingMs"`
	Lease               *Lease          `json:"lease,omitempty"`
	Params              json.RawMessage `json:"params,omitempty"`
}
type Receipt struct {
	DispatchState string `json:"dispatchState"`
	StartedAt     string `json:"startedAt,omitempty"`
	ReturnedAt    string `json:"returnedAt,omitempty"`
	NativeCode    int    `json:"nativeCode,omitempty"`
	TargetRef     string `json:"targetRef,omitempty"`
}
type NativeError struct {
	Code          string `json:"code"`
	Message       string `json:"message"`
	Stage         string `json:"stage"`
	RetryableRead bool   `json:"retryableRead"`
	DispatchState string `json:"dispatchState"`
}

func (e *NativeError) Error() string { return e.Code + ": " + e.Message }

type Reply struct {
	ProtocolVersion int             `json:"protocolVersion"`
	RequestID       string          `json:"requestId"`
	HelperEpoch     string          `json:"helperEpoch"`
	Result          json.RawMessage `json:"result,omitempty"`
	Error           *NativeError    `json:"error,omitempty"`
	Receipt         *Receipt        `json:"receipt,omitempty"`
}

// TransportError carries conservative mutation uncertainty after any request
// may have reached the helper. Callers must reconcile; they must never replay.
type TransportError struct {
	Cause         error
	DispatchState string
}

func (e *TransportError) Error() string { return "native transport: " + e.Cause.Error() }
func (e *TransportError) Unwrap() error { return e.Cause }

type Options struct {
	HelperPath     string
	AllowMutations bool
	// AllowLaunch grants only application lifecycle authority, never AX/input.
	AllowLaunch bool
	// AllowSemantic is the development AX-only profile; raw input remains disabled.
	AllowSemantic         bool
	AllowTargetedKeyboard bool
	// AllowSessionKeyboard explicitly grants login-session event delivery. It is
	// never inferred from process-targeted keyboard or used as a retry fallback.
	AllowSessionKeyboard bool
	// AllowWindowFrameClick grants only one-use capture-bound window clicks.
	AllowWindowFrameClick bool
	// AllowRecording grants passive capture only; no input/fence authority.
	AllowRecording bool
	RecordingOwner *RecordingOwner
	// Requirement and ExpectedUID are trusted enrollment configuration, never helper claims.
	Requirement string
	ExpectedUID *uint32
	// Artifact is inherited at descriptor 3, allocated/scoped by the broker.
	Artifact *os.File
	Stderr   io.Writer
	Fence    *os.File
}
type Client struct {
	command          *exec.Cmd
	input            io.WriteCloser
	output           io.ReadCloser
	lane             chan struct{}
	closeOnce        sync.Once
	stopped          chan struct{}
	waitErr          error
	watchdog         *os.File
	closeSignal      chan struct{}
	inputPossible    bool
	businessPossible bool
	verifiedIdentity *session.ProcessIdentity
	trustRequired    bool
	recording        *recordingTransport
}

func NewClient(ctx context.Context, options Options) (*Client, error) {
	if options.HelperPath == "" {
		return nil, errors.New("native helper path is required")
	}
	if (options.AllowTargetedKeyboard || options.AllowSessionKeyboard || options.AllowWindowFrameClick) && (!options.AllowSemantic || options.AllowMutations || options.AllowLaunch || options.AllowRecording) {
		return nil, errors.New("native input routes require explicit semantic composite profile")
	}
	profiles := 0
	for _, enabled := range []bool{options.AllowMutations, options.AllowLaunch, options.AllowSemantic, options.AllowRecording} {
		if enabled {
			profiles++
		}
	}
	if profiles > 1 {
		return nil, errors.New("native action authority profiles are mutually exclusive")
	}
	if (options.AllowMutations || options.AllowLaunch || options.AllowSemantic) && options.Fence == nil {
		return nil, errors.New("native action opt-in requires supervisor-owned inherited desktop fence")
	}
	if options.AllowRecording {
		if options.RecordingOwner == nil || options.RecordingOwner.Validate() != nil {
			return nil, errors.New("verified recording owner namespace, client and session required")
		}
	} else if options.RecordingOwner != nil {
		return nil, errors.New("recording owner requires recording-only profile")
	}
	handshake, err := prepareIdentity(options)
	if err != nil {
		return nil, err
	}
	defer handshake.close()
	args := []string{}
	if options.AllowMutations {
		args = append(args, "--allow-mutations")
	} else if options.AllowLaunch {
		args = append(args, "--allow-launch")
	} else if options.AllowSemantic {
		args = append(args, "--allow-semantic")
	} else if options.AllowRecording {
		args = append(args, "--allow-recording")
	}
	if options.AllowTargetedKeyboard {
		args = append(args, "--allow-targeted-keyboard")
	}
	if options.AllowSessionKeyboard {
		args = append(args, "--allow-session-keyboard")
	}
	if options.AllowWindowFrameClick {
		args = append(args, "--allow-window-frame-click")
	}
	command := exec.CommandContext(ctx, options.HelperPath, args...)
	command.Env = handshake.environment()
	if handshake != nil {
		command.Path = handshake.executable
	}
	placeholder, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	defer placeholder.Close()
	heartbeatRead, heartbeatWrite, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer heartbeatRead.Close()
	artifact := options.Artifact
	if artifact == nil {
		artifact = placeholder
	}
	fence := options.Fence
	if fence == nil {
		fence = placeholder
	}
	command.ExtraFiles = []*os.File{artifact, heartbeatRead, fence} // FD3 artifact, FD4 watchdog, FD5 fence
	launched := false
	defer func() {
		if !launched {
			heartbeatWrite.Close()
		}
	}()
	command.Stderr = options.Stderr
	input, err := command.StdinPipe()
	if err != nil {
		return nil, err
	}
	output, err := command.StdoutPipe()
	if err != nil {
		input.Close()
		return nil, err
	}
	if err = command.Start(); err != nil {
		input.Close()
		output.Close()
		return nil, err
	}
	launched = true
	client := &Client{command: command, input: input, output: output, lane: make(chan struct{}, 1), stopped: make(chan struct{}), watchdog: heartbeatWrite, closeSignal: make(chan struct{}), inputPossible: options.AllowMutations || options.AllowTargetedKeyboard || options.AllowSessionKeyboard || options.AllowWindowFrameClick, businessPossible: options.AllowMutations || options.AllowLaunch || options.AllowSemantic, trustRequired: handshake != nil}
	go func() {
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-client.closeSignal:
				return
			case <-client.stopped:
				return
			case <-ticker.C:
				if _, err := heartbeatWrite.Write([]byte{1}); err != nil {
					return
				}
			}
		}
	}()
	go func() { client.waitErr = command.Wait(); close(client.stopped) }()
	if handshake != nil {
		identity, authErr := handshake.authenticate(ctx, client.PID())
		if authErr != nil {
			if closeErr := client.Close(); closeErr != nil {
				return client, errors.Join(authErr, closeErr)
			}
			return nil, authErr
		}
		client.verifiedIdentity = &identity
	}
	if options.AllowRecording {
		client.recording = newRecordingTransport(*options.RecordingOwner, *options.ExpectedUID, client.Call)
	}
	return client, nil
}

// Call serializes one request. Cancellation kills this helper and invalidates
// every reference/lease; native AX is not assumed to be cooperatively cancellable.
func (c *Client) Call(ctx context.Context, request Request) (Reply, error) {
	var empty Reply
	if c.trustRequired && c.verifiedIdentity == nil {
		return empty, &TransportError{errors.New("native helper identity authentication incomplete"), "notDispatched"}
	}
	select {
	case c.lane <- struct{}{}:
		defer func() { <-c.lane }()
	case <-ctx.Done():
		return empty, &TransportError{ctx.Err(), "notDispatched"}
	}
	select {
	case <-c.stopped:
		return empty, &TransportError{errors.New("helper stopped"), "notDispatched"}
	default:
	}
	if request.ProtocolVersion == 0 {
		request.ProtocolVersion = ProtocolVersion
	}
	if request.RequestID == "" {
		return empty, errors.New("request ID is required")
	}
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline).Milliseconds()
		if remaining <= 0 {
			return empty, &TransportError{context.DeadlineExceeded, "notDispatched"}
		}
		if request.DeadlineRemainingMS <= 0 || remaining < request.DeadlineRemainingMS {
			request.DeadlineRemainingMS = remaining
		}
	}
	if request.DeadlineRemainingMS <= 0 || request.DeadlineRemainingMS > 30000 {
		return empty, errors.New("deadline must be 1...30000 milliseconds")
	}
	data, err := json.Marshal(request)
	if err != nil {
		return empty, err
	}
	if len(data) > MaximumFrameBytes {
		return empty, errors.New("native request frame too large")
	}
	type outcome struct {
		reply Reply
		err   error
	}
	result := make(chan outcome, 1)
	go func() {
		var header [4]byte
		binary.BigEndian.PutUint32(header[:], uint32(len(data)))
		err := writeAll(c.input, header[:])
		if err == nil {
			err = writeAll(c.input, data)
		}
		var reply Reply
		if err == nil {
			var body []byte
			body, err = readResponseFrame(c.output, request.Method)
			if err == nil {
				err = json.Unmarshal(body, &reply)
				if err == nil && len(body) > MaximumFrameBytes && (reply.Error != nil || len(reply.Result) == 0) {
					err = errors.New("oversized native reply requires successful capture result")
				}
			}
		}
		if err == nil && (reply.ProtocolVersion != ProtocolVersion || reply.RequestID != request.RequestID || reply.HelperEpoch == "") {
			err = errors.New("native protocol identity mismatch")
		}
		result <- outcome{reply, err}
	}()
	timer := time.NewTimer(time.Duration(request.DeadlineRemainingMS) * time.Millisecond)
	defer timer.Stop()
	select {
	case value := <-result:
		if value.err != nil {
			c.Close()
			return empty, &TransportError{value.err, "unknown"}
		}
		if value.reply.Error != nil {
			return value.reply, value.reply.Error
		}
		return value.reply, nil
	case <-ctx.Done():
		c.Close()
		return empty, &TransportError{ctx.Err(), "unknown"}
	case <-timer.C:
		c.Close()
		return empty, &TransportError{context.DeadlineExceeded, "unknown"}
	}
}
func (c *Client) Close() error {
	c.closeOnce.Do(func() {
		close(c.closeSignal)
		c.watchdog.Close()
		c.input.Close()
		// Give the independent helper watchdog a bounded cleanup opportunity.
		select {
		case <-c.stopped:
		case <-time.After(300 * time.Millisecond):
		}
		if c.command.Process != nil {
			_ = c.command.Process.Kill()
		}
		c.output.Close()
	})
	select {
	case <-c.stopped:
		return nil
	case <-time.After(time.Second):
		return fmt.Errorf("helper teardown exceeded one second")
	}
}
func writeAll(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := writer.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}
func readFrame(reader io.Reader) ([]byte, error) {
	return readFrameBounded(reader, MaximumFrameBytes)
}

func readResponseFrame(reader io.Reader, method string) ([]byte, error) {
	maximum := MaximumFrameBytes
	if method == "windows.captureFrame" {
		maximum = MaximumWindowFrameResponseBytes
	}
	return readFrameBounded(reader, maximum)
}

func readFrameBounded(reader io.Reader, maximum int) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, err
	}
	count := binary.BigEndian.Uint32(header[:])
	if count == 0 || uint64(count) > uint64(maximum) {
		return nil, errors.New("invalid native frame size")
	}
	body := make([]byte, count)
	_, err := io.ReadFull(reader, body)
	return body, err
}

// PID identifies the supervised helper for diagnostics, never an input target.
func (c *Client) PID() int {
	if c.command.Process == nil {
		return 0
	}
	return c.command.Process.Pid
}

// WaitStopped waits for this helper's reaping without issuing any desktop action.
func (c *Client) WaitStopped(ctx context.Context) error {
	select {
	case <-c.stopped:
		return c.waitErr
	case <-ctx.Done():
		return ctx.Err()
	}
}

// TrustedIdentity returns the immutable identity authenticated at launch. The
// boolean is false for unconfigured read-only fixture launches. Use Identity
// when a fresh liveness and PID/start-time crosscheck is also required.
func (c *Client) TrustedIdentity() (session.ProcessIdentity, bool) {
	if c.verifiedIdentity == nil {
		return session.ProcessIdentity{}, false
	}
	return *c.verifiedIdentity, true
}

// Identity uses public libproc PID/start-time inspection, not a PID alone.
func (c *Client) Identity() (session.ProcessIdentity, error) {
	identity, alive, err := session.InspectProcess(c.PID())
	if err != nil {
		return identity, err
	}
	if !alive {
		return identity, errors.New("helper is not alive")
	}
	if c.verifiedIdentity != nil && identity != *c.verifiedIdentity {
		return identity, errors.New("verified helper process identity changed")
	}
	return identity, nil
}

// StopCleanupError carries only closed phase/cause classifications. Its Error
// never formats native replies, credentials, executable paths or raw RPC bodies.
type StopCleanupError struct {
	Phase     string
	CauseCode string
	cause     error
}

func (e *StopCleanupError) Error() string {
	return "native helper cleanup unconfirmed: " + e.Phase + "/" + e.CauseCode
}
func (e *StopCleanupError) Unwrap() error { return e.cause }

func stopCauseCode(err error, stopped <-chan struct{}) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "deadline"
	}
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	select {
	case <-stopped:
		return "helperStopped"
	default:
	}
	var native *NativeError
	if errors.As(err, &native) {
		return "nativeRejected"
	}
	var transport *TransportError
	if errors.As(err, &transport) {
		return "transport"
	}
	return "callFailed"
}

// Stop is a supervisor-compatible stop/reap callback. Separate phase budgets
// share the caller's total deadline and cancellation. No failed cleanup is
// replayed, and physical cleanup never resolves authoritative business outcomes.
func (c *Client) Stop(ctx context.Context) (session.CleanupReport, error) {
	report := session.CleanupReport{InputInhibited: true, UnknownInputs: c.inputPossible, BusinessOutcomeUnknown: c.businessPossible}
	var failure *StopCleanupError
	phaseCall := func(method, epoch string) (Reply, error) {
		phaseCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		defer cancel()
		type callResult struct {
			reply Reply
			err   error
		}
		done := make(chan callResult, 1)
		go func() {
			reply, err := c.Call(phaseCtx, Request{ProtocolVersion: 1, RequestID: requestID(), Method: method, HelperEpoch: epoch, DeadlineRemainingMS: 500, Params: json.RawMessage(`{}`)})
			done <- callResult{reply: reply, err: err}
		}()
		select {
		case value := <-done:
			if err := phaseCtx.Err(); err != nil {
				return Reply{}, err
			}
			return value.reply, value.err
		case <-phaseCtx.Done():
			// Call may be inside its independent Close/reap on cancellation;
			// that work must not make this caller exceed its total deadline.
			return Reply{}, phaseCtx.Err()
		}
	}
	doctor, err := phaseCall("doctor", "")
	if err != nil {
		failure = &StopCleanupError{Phase: "doctor", CauseCode: stopCauseCode(err, c.stopped), cause: err}
	} else if doctor.Error != nil || doctor.Receipt != nil || doctor.HelperEpoch == "" {
		failure = &StopCleanupError{Phase: "doctor", CauseCode: "invalidAck"}
	} else {
		reply, releaseErr := phaseCall("input.releaseAll", doctor.HelperEpoch)
		if releaseErr != nil {
			failure = &StopCleanupError{Phase: "release", CauseCode: stopCauseCode(releaseErr, c.stopped), cause: releaseErr}
		} else if reply.Error != nil || reply.Receipt != nil || reply.HelperEpoch != doctor.HelperEpoch {
			failure = &StopCleanupError{Phase: "release", CauseCode: "identityOrReceiptMismatch"}
		} else {
			var ack struct {
				Unknown                *int  `json:"unknownReleases"`
				Revoked                *bool `json:"revoked"`
				BusinessOutcomeUnknown *bool `json:"businessOutcomeUnknown"`
				Released               *int  `json:"releasesDispatched,omitempty"`
				BusinessSuccess        *bool `json:"businessSuccess,omitempty"`
			}
			decoder := json.NewDecoder(bytes.NewReader(reply.Result))
			decoder.DisallowUnknownFields()
			decodeErr := decoder.Decode(&ack)
			var trailing any
			complete := decoder.Decode(&trailing) == io.EOF
			if decodeErr != nil || !complete || ack.Unknown == nil || *ack.Unknown < 0 || ack.Revoked == nil || !*ack.Revoked || ack.BusinessOutcomeUnknown == nil || ack.Released != nil && *ack.Released < 0 || ack.BusinessSuccess != nil && *ack.BusinessSuccess {
				failure = &StopCleanupError{Phase: "release", CauseCode: "invalidAck"}
			} else {
				// This is cleanup's lack of business proof, not the durable ledger's
				// outcome. A physical-release ACK cannot downgrade that uncertainty.
				report.BusinessOutcomeUnknown = report.BusinessOutcomeUnknown || *ack.BusinessOutcomeUnknown
				if *ack.Unknown == 0 {
					report.UnknownInputs = false
				} else {
					report.UnknownInputs = true
					failure = &StopCleanupError{Phase: "release", CauseCode: "unconfirmedReleases"}
				}
			}
		}
	}
	if failure != nil {
		report.Reason = failure.Error()
	}
	// Initiate teardown of this exact Client only. Caller expiry returns an
	// unconfirmed reap rather than waiting beyond its total deadline. The existing
	// Close continues inhibiting/killing/reaping; no replacement helper is launched.
	reaped := make(chan error, 1)
	go func() { reaped <- c.Close() }()
	select {
	case closeErr := <-reaped:
		if closeErr != nil {
			failure = &StopCleanupError{Phase: "reap", CauseCode: "notConfirmed", cause: closeErr}
			report.Reason = failure.Error()
			return report, failure
		}
		report.HelperStopped = true
	case <-ctx.Done():
		failure = &StopCleanupError{Phase: "reap", CauseCode: stopCauseCode(ctx.Err(), c.stopped), cause: ctx.Err()}
		report.Reason = failure.Error()
		return report, failure
	}
	if err := ctx.Err(); err != nil {
		failure = &StopCleanupError{Phase: "reap", CauseCode: stopCauseCode(err, c.stopped), cause: err}
		report.Reason = failure.Error()
		return report, failure
	}
	if failure != nil && report.UnknownInputs {
		return report, failure
	}
	// Immutable non-raw launch authority can prove physical exclusion without an
	// ACK, while retaining cleanup diagnostics and independent business uncertainty.
	return report, nil
}
