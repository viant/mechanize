package keychain

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
)

type migrationWorkerExecutorFixture struct {
	*migrationBackendFixture
	pin string
}

func (b *migrationWorkerExecutorFixture) commitAsIsolatedHelper(ctx context.Context, options migrationOptions, prepared *migrationPrepared, pin string) error {
	b.pin = pin
	return b.commit(ctx, options, prepared)
}

type migrationWorkerChannelFixture struct {
	mu            sync.Mutex
	input         *bytes.Reader
	output        bytes.Buffer
	reads, writes int
	failWriteAt   int
	closed        bool
}

func (c *migrationWorkerChannelFixture) Read(data []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reads++
	if c.closed {
		return 0, io.ErrClosedPipe
	}
	return c.input.Read(data)
}
func (c *migrationWorkerChannelFixture) Write(data []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes++
	if c.closed || c.writes == c.failWriteAt {
		return 0, errors.New(migrationPrivateCanary)
	}
	return c.output.Write(data)
}
func (c *migrationWorkerChannelFixture) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}

// AfterFunc may still be completing an idempotent Close after serve/load
// returns. Test observations must use the same mutex as the channel methods.
func (c *migrationWorkerChannelFixture) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}
func (c *migrationWorkerChannelFixture) readCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.reads
}
func (c *migrationWorkerChannelFixture) outputBytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return bytes.Clone(c.output.Bytes())
}
func migrationWorkerFixture(t *testing.T) (*migrationWorker, *migrationWorkerExecutorFixture, *[]string) {
	t.Helper()
	events := &[]string{}
	executor := &migrationWorkerExecutorFixture{migrationBackendFixture: &migrationBackendFixture{events: events, newPolicy: true}}
	config := migrationWorkerConfig{options: migrationFixtureOptions(), session: strings.Repeat("a", 64), executorRequirement: `identifier "com.viant.mechanize.custody-migration" and cdhash H"` + strings.Repeat("3", 40) + `"`}
	authority := func(ctx context.Context) (context.Context, error) { return ctx, nil }
	approval := func(_ context.Context, binding migrationWorkerApprovalBinding) error {
		*events = append(*events, "bound-approval")
		return nil
	}
	worker, err := newMigrationWorker(config, executor, authority, approval)
	if err != nil {
		t.Fatal(err)
	}
	return worker, executor, events
}
func migrationWorkerReq(worker *migrationWorker, id int, operation string) migrationWorkerRequest {
	return migrationWorkerRequest{Version: 1, ID: fmt.Sprintf("%064x", id), Session: worker.config.session, Operation: operation}
}
func migrationWorkerWire(t *testing.T, worker *migrationWorker, operations ...string) []byte {
	t.Helper()
	var data bytes.Buffer
	for i, operation := range operations {
		if err := writeMigrationWorkerRequest(&data, migrationWorkerReq(worker, i+1, operation)); err != nil {
			t.Fatal(err)
		}
	}
	return data.Bytes()
}
func migrationWorkerChannel(data []byte) *migrationWorkerChannelFixture {
	return &migrationWorkerChannelFixture{input: bytes.NewReader(data)}
}
func migrationWorkerReplies(t *testing.T, channel *migrationWorkerChannelFixture) []migrationWorkerResponse {
	t.Helper()
	var result []migrationWorkerResponse
	reader := bytes.NewReader(channel.outputBytes())
	for reader.Len() > 0 {
		response, err := readMigrationWorkerResponse(reader)
		if err != nil {
			t.Fatal("invalid worker reply")
		}
		result = append(result, response)
	}
	return result
}
func migrationWorkerRawFrame(data []byte) []byte {
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(len(data)))
	return append(prefix[:], data...)
}
func TestMigrationWorkerClosedProtocolRoundTripsBoundedItemMetadata(t *testing.T) {
	w, _, _ := migrationWorkerFixture(t)
	request := migrationWorkerReq(w, 1, "prepare")
	var wire bytes.Buffer
	if err := writeMigrationWorkerRequest(&wire, request); err != nil {
		t.Fatal(err)
	}
	decoded, err := readMigrationWorkerRequest(&wire)
	if err != nil || decoded != request {
		t.Fatal("request changed")
	}
	response := migrationWorkerResponse{Version: 1, ID: request.ID, Session: request.Session, Status: "prepared", Identity: bytes.Repeat([]byte{17}, 16384)}
	if err = writeMigrationWorkerResponse(&wire, response); err != nil || wire.Len() > migrationWorkerFrameLimit+4 {
		t.Fatal("bounded metadata reply failed")
	}
	got, err := readMigrationWorkerResponse(&wire)
	if err != nil || !reflect.DeepEqual(got, response) {
		t.Fatal("reply changed")
	}
}
func TestMigrationWorkerRejectsMalformedDuplicateExtraSecretAndAuthorityFields(t *testing.T) {
	w, _, _ := migrationWorkerFixture(t)
	valid, _ := json.Marshal(migrationWorkerReq(w, 1, "prepare"))
	bad := [][]byte{nil, []byte("{}"), append(bytes.Clone(valid), []byte("{}")...), append([]byte(" "), valid...),
		[]byte(strings.Replace(string(valid), `"version":1`, `"version":1,"version":1`, 1)),
		[]byte(strings.Replace(string(valid), `"version":1`, `"version":2`, 1)),
		[]byte(strings.Replace(string(valid), `"op":"prepare"`, `"op":"readKey"`, 1)),
		[]byte(strings.Replace(string(valid), `"id":"`, `"id":"INVALID`, 1)),
	}
	for _, field := range []string{"key", "value", "password", "credential", "policy", "identity", "nativeHuman", "approved", "approvalToken", "executorRequirement", "role", "options"} {
		bad = append(bad, []byte(strings.Replace(string(valid), `"version":1`, `"version":1,"`+field+`":"private-canary"`, 1)))
	}
	for _, data := range bad {
		if _, err := readMigrationWorkerRequest(bytes.NewReader(migrationWorkerRawFrame(data))); err != errMigrationUnavailable {
			t.Fatal("malformed or private field accepted")
		}
	}
	var huge [4]byte
	binary.BigEndian.PutUint32(huge[:], migrationWorkerFrameLimit+1)
	if _, err := readMigrationWorkerRequest(bytes.NewReader(huge[:])); err != errMigrationUnavailable {
		t.Fatal("oversized frame accepted")
	}
	for _, data := range [][]byte{{1}, migrationWorkerRawFrame(valid)[:8]} {
		if _, err := readMigrationWorkerRequest(bytes.NewReader(data)); err != errMigrationUnavailable {
			t.Fatal("truncated frame accepted")
		}
	}
}
func TestMigrationWorkerResponseCodecRejectsSecretExtrasAndUnexpectedIdentity(t *testing.T) {
	w, _, _ := migrationWorkerFixture(t)
	request := migrationWorkerReq(w, 1, "prepare")
	response := migrationWorkerResponse{Version: 1, ID: request.ID, Session: request.Session, Status: "verified"}
	valid, _ := json.Marshal(response)
	bad := []byte(strings.Replace(string(valid), `"version":1`, `"version":1,"password":"private-canary"`, 1))
	if _, err := readMigrationWorkerResponse(bytes.NewReader(migrationWorkerRawFrame(bad))); err == nil {
		t.Fatal("private reply field accepted")
	}
	for _, status := range []string{"verified", "unknown", "checked", "closed"} {
		response.Status = status
		response.Identity = []byte("public-ref")
		if err := writeMigrationWorkerResponse(io.Discard, response); err == nil {
			t.Fatal("identity exposed outside prepare")
		}
	}
	response.Status = "prepared"
	response.Identity = make([]byte, 16385)
	if err := writeMigrationWorkerResponse(io.Discard, response); err == nil {
		t.Fatal("oversized identity accepted")
	}
}
func TestMigrationWorkerAuthorityRequiredBeforeFirstReadAndNeverComesFromWire(t *testing.T) {
	for _, mode := range []string{"no-native-human", "callback-error", "nil-context", "unbounded", "extended-deadline"} {
		t.Run(mode, func(t *testing.T) {
			w, b, _ := migrationWorkerFixture(t)
			ctx := migrationFixtureContext(t, mode != "no-native-human")
			channel := migrationWorkerChannel(migrationWorkerWire(t, w, "prepare", "close"))
			switch mode {
			case "callback-error":
				w.authority = func(context.Context) (context.Context, error) { return nil, errors.New(migrationPrivateCanary) }
			case "nil-context":
				w.authority = func(context.Context) (context.Context, error) { return nil, nil }
			case "unbounded":
				ctx = masterFixtureContext(t, true)
			case "extended-deadline":
				w.authority = func(context.Context) (context.Context, error) {
					extended, cancel := context.WithTimeout(masterFixtureContext(t, true), time.Hour)
					t.Cleanup(cancel)
					return extended, nil
				}
			}
			if err := w.serve(ctx, channel); err != errMigrationUnavailable || channel.readCount() != 0 || b.prepares != 0 || !channel.isClosed() {
				t.Fatal("untrusted authority read or prepared")
			}
		})
	}
}
func TestMigrationWorkerAuthorityRecheckedForEveryOperation(t *testing.T) {
	w, b, _ := migrationWorkerFixture(t)
	calls := 0
	w.authority = func(ctx context.Context) (context.Context, error) {
		calls++
		if calls == 3 {
			return nil, errors.New(migrationPrivateCanary)
		}
		return ctx, nil
	}
	channel := migrationWorkerChannel(migrationWorkerWire(t, w, "prepare", "verify", "commit", "close"))
	if err := w.serve(migrationFixtureContext(t, true), channel); err != errMigrationUnavailable || b.prepares != 1 || b.commits != 0 || b.disposals != 1 {
		t.Fatal("revoked authority continued")
	}
}
func TestMigrationWorkerKnownSequenceBindsApprovalAndDispatchesOnce(t *testing.T) {
	w, b, events := migrationWorkerFixture(t)
	var approval migrationWorkerApprovalBinding
	w.approval = func(_ context.Context, binding migrationWorkerApprovalBinding) error {
		approval = binding
		*events = append(*events, "bound-approval")
		return nil
	}
	channel := migrationWorkerChannel(migrationWorkerWire(t, w, "prepare", "verify", "commit", "inspect", "close"))
	if err := w.serve(migrationFixtureContext(t, true), channel); err != nil {
		t.Fatal(err)
	}
	replies := migrationWorkerReplies(t, channel)
	statuses := []string{}
	for _, reply := range replies {
		statuses = append(statuses, reply.Status)
	}
	if !reflect.DeepEqual(statuses, []string{"prepared", "checked", "verified", "verified", "closed"}) || b.commits != 1 || b.disposals != 1 || b.pin != w.config.executorRequirement {
		t.Fatal("incorrect worker lifecycle")
	}
	if approval.Session != w.config.session || approval.RequestID != migrationWorkerReq(w, 3, "commit").ID || approval.OptionsSHA256 != migrationOptionsDigest(w.config.options) || approval.ExecutorRequirement != w.config.executorRequirement || approval.ItemReferenceSHA256 != migrationDigest(replies[0].Identity) {
		t.Fatal("approval omitted exact transition binding")
	}
	want := []string{"prepare", "verify-pins-and-old-policy", "verify-pins-and-old-policy", "bound-approval", "commit", "inspect", "inspect"}
	if !reflect.DeepEqual(*events, want) {
		t.Fatal("unsafe operation ordering")
	}
	if err := w.serve(migrationFixtureContext(t, true), migrationWorkerChannel(nil)); err == nil {
		t.Fatal("worker session reused")
	}
}
func TestMigrationWorkerInvalidPhaseCrossSessionAndDuplicateIDCannotDispatch(t *testing.T) {
	for _, mode := range []string{"commit-first", "missing-verify", "duplicate-prepare", "cross-session", "reused-id"} {
		t.Run(mode, func(t *testing.T) {
			w, b, _ := migrationWorkerFixture(t)
			var wire bytes.Buffer
			requests := []migrationWorkerRequest{migrationWorkerReq(w, 1, "prepare"), migrationWorkerReq(w, 2, "verify"), migrationWorkerReq(w, 3, "commit")}
			switch mode {
			case "commit-first":
				requests = requests[2:]
			case "missing-verify":
				requests = []migrationWorkerRequest{requests[0], requests[2]}
			case "duplicate-prepare":
				requests[1].Operation = "prepare"
			case "cross-session":
				requests[1].Session = strings.Repeat("b", 64)
			case "reused-id":
				requests[1].ID = requests[0].ID
			}
			for _, request := range requests {
				if err := writeMigrationWorkerRequest(&wire, request); err != nil {
					t.Fatal(err)
				}
			}
			channel := migrationWorkerChannel(wire.Bytes())
			if err := w.serve(migrationFixtureContext(t, true), channel); err != errMigrationUnavailable || b.commits != 0 {
				t.Fatal("invalid state dispatched")
			}
			if b.prepares > 0 && b.disposals != 1 {
				t.Fatal("invalid state leaked handle")
			}
		})
	}
}
func TestMigrationWorkerRawSecretFieldsRejectedBeforeBackend(t *testing.T) {
	w, b, _ := migrationWorkerFixture(t)
	data, _ := json.Marshal(migrationWorkerReq(w, 1, "prepare"))
	data = []byte(strings.Replace(string(data), `"version":1`, `"version":1,"key":"private-key-canary"`, 1))
	channel := migrationWorkerChannel(migrationWorkerRawFrame(data))
	err := w.serve(migrationFixtureContext(t, true), channel)
	if err != errMigrationUnavailable || b.prepares != 0 || len(channel.outputBytes()) != 0 {
		t.Fatal("secret field reached backend")
	}
}
func TestMigrationWorkerApprovalRefusalOrCancellationNeverDispatches(t *testing.T) {
	for _, mode := range []string{"denied", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			w, b, _ := migrationWorkerFixture(t)
			ctx, cancel := context.WithCancel(migrationFixtureContext(t, true))
			defer cancel()
			w.approval = func(context.Context, migrationWorkerApprovalBinding) error {
				if mode == "cancel" {
					cancel()
					return nil
				}
				return errors.New(migrationPrivateCanary)
			}
			channel := migrationWorkerChannel(migrationWorkerWire(t, w, "prepare", "verify", "commit", "close"))
			if err := w.serve(ctx, channel); err != errMigrationUnavailable || b.commits != 0 || b.disposals != 1 {
				t.Fatal("unapproved commit dispatched")
			}
		})
	}
}
func TestMigrationWorkerLostAcknowledgementIsUnknownAndCannotReplay(t *testing.T) {
	w, b, _ := migrationWorkerFixture(t)
	channel := migrationWorkerChannel(migrationWorkerWire(t, w, "prepare", "verify", "commit", "commit"))
	channel.failWriteAt = 3
	if err := w.serve(migrationFixtureContext(t, true), channel); err != errMigrationUnknown || w.phase != "unknown" || b.commits != 1 || b.disposals != 1 {
		t.Fatal("lost acknowledgement was cleared or replayed")
	}
	if strings.Contains(string(channel.outputBytes()), migrationPrivateCanary) {
		t.Fatal("backend error leaked")
	}
}
func TestMigrationWorkerPostDispatchFailuresAndRepeatCommitStayUnknown(t *testing.T) {
	for _, mode := range []string{"commit-error", "cancel", "inspection-error", "substitute", "old-policy", "repeat-commit"} {
		t.Run(mode, func(t *testing.T) {
			w, b, _ := migrationWorkerFixture(t)
			ctx, cancel := context.WithCancel(migrationFixtureContext(t, true))
			defer cancel()
			switch mode {
			case "commit-error":
				b.commitError = true
			case "cancel":
				b.commitHook = cancel
			case "inspection-error":
				b.inspectError = true
			case "substitute":
				b.substitute = true
			case "old-policy":
				b.newPolicy = false
			}
			operations := []string{"prepare", "verify", "commit", "close"}
			if mode == "repeat-commit" {
				operations[3] = "commit"
			}
			channel := migrationWorkerChannel(migrationWorkerWire(t, w, operations...))
			if err := w.serve(ctx, channel); err != errMigrationUnknown || b.commits != 1 || b.disposals != 1 || w.phase != "unknown" {
				t.Fatal("postdispatch failure replayed or lost unknown")
			}
		})
	}
}
func TestMigrationWorkerUnknownInspectUsesOnlySameItemAndNeverReplays(t *testing.T) {
	w, b, _ := migrationWorkerFixture(t)
	b.commitError = true
	channel := migrationWorkerChannel(migrationWorkerWire(t, w, "prepare", "verify", "commit", "inspect", "close"))
	if err := w.serve(migrationFixtureContext(t, true), channel); err != nil || b.commits != 1 {
		t.Fatal("explicit metadata reconciliation failed")
	}
	replies := migrationWorkerReplies(t, channel)
	if replies[2].Status != "unknown" || replies[3].Status != "verified" {
		t.Fatal("uncertainty was not explicitly reconciled")
	}
}
func TestMigrationWorkerRestartInspectBindsTrustedJournalIdentityAndNeverPrepares(t *testing.T) {
	for _, operation := range []string{"inspect", "prepare", "commit"} {
		t.Run(operation, func(t *testing.T) {
			w, b, _ := migrationWorkerFixture(t)
			config := w.config
			config.expectedIdentity = []byte("trusted-public-journal-ref")
			fresh, err := newMigrationWorker(config, b, w.authority, w.approval)
			if err != nil {
				t.Fatal(err)
			}
			channel := migrationWorkerChannel(migrationWorkerWire(t, fresh, operation, "close"))
			err = fresh.serve(migrationFixtureContext(t, true), channel)
			if b.prepares != 0 || b.commits != 0 {
				t.Fatal("restart reconciliation mutated")
			}
			if operation == "inspect" && err != nil {
				t.Fatal("same-item restart inspection failed")
			}
			if operation != "inspect" && err != errMigrationUnknown {
				t.Fatal("journal mode admitted preparation or commit")
			}
		})
	}
}
func TestMigrationWorkerCloseAndTransportLossReleaseHandle(t *testing.T) {
	for _, ops := range [][]string{{"prepare", "close"}, {"prepare"}} {
		w, b, _ := migrationWorkerFixture(t)
		channel := migrationWorkerChannel(migrationWorkerWire(t, w, ops...))
		_ = w.serve(migrationFixtureContext(t, true), channel)
		if b.disposals != 1 || b.commits != 0 || !channel.isClosed() {
			t.Fatal("worker close retained preparation")
		}
	}
}
func TestMigrationWorkerCancellationClosesBlockedRead(t *testing.T) {
	w, b, _ := migrationWorkerFixture(t)
	server, client := net.Pipe()
	defer client.Close()
	ctx, cancel := context.WithCancel(migrationFixtureContext(t, true))
	defer cancel()
	observed := &migrationReadObserved{Conn: server, entered: make(chan struct{})}
	done := make(chan error, 1)
	go func() { done <- w.serve(ctx, observed) }()
	select {
	case <-observed.entered:
	case <-time.After(time.Second):
		t.Fatal("worker did not begin read")
	}
	cancel()
	select {
	case err := <-done:
		if err != errMigrationUnavailable || b.prepares != 0 {
			t.Fatal("cancelled worker continued")
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled private channel remained blocked")
	}
}
func TestMigrationWorkerPrivateBackendStateAndErrorsDoNotReachReplies(t *testing.T) {
	w, b, _ := migrationWorkerFixture(t)
	b.prepareError = true
	channel := migrationWorkerChannel(migrationWorkerWire(t, w, "prepare", "close"))
	err := w.serve(migrationFixtureContext(t, true), channel)
	encoded, _ := json.Marshal(w)
	text := string(channel.outputBytes()) + fmt.Sprintf("%v %+v %#v %v", w, w, w, err) + string(encoded)
	if strings.Contains(text, migrationPrivateCanary) || strings.Contains(text, w.config.options.item.Account) || strings.Contains(text, w.config.options.canonicalExecutable) {
		t.Fatal("private backend state leaked")
	}
	if b.disposals != 1 {
		t.Fatal("failed preparation handle retained")
	}
}
func TestMigrationWorkerFactoryRequiresClosedTrustedConfiguration(t *testing.T) {
	w, b, _ := migrationWorkerFixture(t)
	for _, alter := range []func(*migrationWorkerConfig){
		func(c *migrationWorkerConfig) { c.session = "caller-role" }, func(c *migrationWorkerConfig) { c.executorRequirement = c.options.newRequirement },
		func(c *migrationWorkerConfig) { c.expectedIdentity = make([]byte, 16385) }, func(c *migrationWorkerConfig) { c.options.alias = "../item" },
	} {
		config := w.config
		alter(&config)
		if _, err := newMigrationWorker(config, b, w.authority, w.approval); err == nil {
			t.Fatal("invalid trusted config accepted")
		}
	}
	if _, err := newMigrationWorker(w.config, b, nil, w.approval); err == nil {
		t.Fatal("missing authority accepted")
	}
	if _, err := newMigrationWorker(w.config, b, w.authority, nil); err == nil {
		t.Fatal("missing independent approval accepted")
	}
}

type migrationReadObserved struct {
	net.Conn
	once    sync.Once
	entered chan struct{}
}

func (c *migrationReadObserved) Read(data []byte) (int, error) {
	c.once.Do(func() { close(c.entered) })
	return c.Conn.Read(data)
}
func TestMigrationWorkerAuthorityDeadlineAlsoBoundsFirstRead(t *testing.T) {
	w, b, _ := migrationWorkerFixture(t)
	parent := migrationFixtureContext(t, true)
	authorityContext, cancel := context.WithTimeout(parent, 30*time.Millisecond)
	defer cancel()
	w.authority = func(context.Context) (context.Context, error) { return authorityContext, nil }
	server, client := net.Pipe()
	defer client.Close()
	observed := &migrationReadObserved{Conn: server, entered: make(chan struct{})}
	done := make(chan error, 1)
	go func() { done <- w.serve(parent, observed) }()
	select {
	case <-observed.entered:
	case <-time.After(time.Second):
		t.Fatal("worker did not begin read")
	}
	select {
	case err := <-done:
		if err != errMigrationUnavailable || b.prepares != 0 {
			t.Fatal("expired authority continued")
		}
	case <-time.After(time.Second):
		t.Fatal("authority deadline did not close blocked read")
	}
}

func TestMigrationWorkerAuthorityCannotSwitchPrincipalOrClientAfterPreparation(t *testing.T) {
	for _, mode := range []string{"namespace", "client"} {
		t.Run(mode, func(t *testing.T) {
			w, b, _ := migrationWorkerFixture(t)
			calls := 0
			w.authority = func(ctx context.Context) (context.Context, error) {
				calls++
				if calls != 3 {
					return ctx, nil
				}
				principal, err := auth.FromContext(ctx)
				if err != nil {
					return nil, err
				}
				if mode == "namespace" {
					different, err := auth.NewPrincipal("fixture", "", "different-native-owner", []string{"consent:admin"})
					if err != nil {
						return nil, err
					}
					different.ClientID = principal.ClientID
					principal = different
				} else {
					principal.ClientID = "different-verified-client"
				}
				// Both alternate principals still have valid native-human
				// authority. Neither may inherit this prepared session.
				return auth.WithNativeHuman(auth.WithPrincipal(ctx, principal))
			}
			channel := migrationWorkerChannel(migrationWorkerWire(t, w, "prepare", "verify", "commit", "close"))
			err := w.serve(migrationFixtureContext(t, true), channel)
			if err != errMigrationUnavailable || b.prepares != 1 || b.commits != 0 || b.disposals != 1 || !channel.isClosed() {
				t.Fatal("worker changed operation owner after preparation")
			}
		})
	}
}
