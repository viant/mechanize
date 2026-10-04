package chrome

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
)

const fixtureOrigin = "https://fixture.example.test"

func principal(t *testing.T, subject string) auth.Principal {
	t.Helper()
	p, e := auth.NewPrincipal("fixture-issuer", "", subject, []string{"desktop:observe", "desktop:control"})
	if e != nil {
		t.Fatal(e)
	}
	return p
}
func enrollment(p auth.Principal, profile string) Enrollment {
	return Enrollment{Principal: p, ProfileChannel: profile, BrowserInstance: "browser1", ExtensionOrigin: "chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/", Origins: []string{fixtureOrigin}}
}
func fixtureBroker(t *testing.T, grants ...Enrollment) *Broker {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "mechanize-chrome-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	credentials := map[string]string{}
	for _, g := range grants {
		credentials[channelKey(g.ProfileChannel, g.BrowserInstance)] = strings.Repeat("secret", 8)
	}
	b, e := newBroker(Config{SocketPath: filepath.Join(dir, "broker.sock"), FixtureEnrollment: true, Grants: grants}, credentials)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { b.Close() })
	return b
}
func connectHost(t *testing.T, b *Broker, grant Enrollment) net.Conn {
	t.Helper()
	conn, e := net.Dial("unix", b.listener.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { conn.Close() })
	e = WriteFrame(conn, map[string]any{"type": "hello", "protocolVersion": 1, "profileChannel": grant.ProfileChannel, "browserInstance": grant.BrowserInstance, "extensionOrigin": grant.ExtensionOrigin, "fixtureEnrollment": true, "credential": strings.Repeat("secret", 8)})
	if e != nil {
		t.Fatal(e)
	}
	conn.SetReadDeadline(time.Now().Add(time.Second))
	hello, e := ReadFrame(conn)
	if e != nil {
		t.Fatal(e)
	}
	var result map[string]any
	if json.Unmarshal(hello, &result) != nil || result["type"] != "enrolled" {
		t.Fatal("missing grant")
	}
	conn.SetReadDeadline(time.Time{})
	return conn
}
func document(grant Enrollment, tab int) Document {
	return Document{Identity: Identity{ProfileChannel: grant.ProfileChannel, BrowserInstance: grant.BrowserInstance, TabID: tab, FrameID: 0, DocumentID: "document1", Generation: 1}, Origin: fixtureOrigin, Title: "Cases"}
}
func publish(t *testing.T, b *Broker, conn net.Conn, grant Enrollment, docs ...Document) {
	t.Helper()
	if e := WriteFrame(conn, map[string]any{"type": "documents", "documents": docs}); e != nil {
		t.Fatal(e)
	}
	until := time.Now().Add(time.Second)
	for time.Now().Before(until) {
		b.mu.Lock()
		c := b.channels[channelKey(grant.ProfileChannel, grant.BrowserInstance)]
		ready := len(c.documents) == len(docs)
		b.mu.Unlock()
		if ready {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("inventory not received")
}
func nextCommand(t *testing.T, conn net.Conn) Command {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(time.Second))
	data, e := ReadFrame(conn)
	if e != nil {
		t.Fatal(e)
	}
	conn.SetReadDeadline(time.Time{})
	var command Command
	if e = json.Unmarshal(data, &command); e != nil {
		t.Fatal(e)
	}
	return command
}
func code(t *testing.T, err error, want string) {
	t.Helper()
	var detail *model.MechanizeError
	if !errors.As(err, &detail) || detail.Code != want {
		t.Fatalf("want %s, got %v", want, err)
	}
}
func TestGatewayObservationAndUserIsolation(t *testing.T) {
	user := principal(t, "a")
	other := principal(t, "b")
	grant := enrollment(user, "profile1")
	b := fixtureBroker(t, grant)
	conn := connectHost(t, b, grant)
	publish(t, b, conn, grant, document(grant, 7))
	g, _ := NewGateway(b, GatewayOptions{})
	_, err := g.Observe(auth.WithPrincipal(context.Background(), other), other, model.Surface{Kind: "web", Origin: fixtureOrigin})
	code(t, err, "ambiguousTarget")
	_, err = g.Observe(auth.WithPrincipal(context.Background(), other), user, model.Surface{Kind: "web", Origin: fixtureOrigin})
	if !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatal(err)
	}
	type outcome struct {
		observation model.Observation
		err         error
	}
	done := make(chan outcome, 1)
	go func() {
		o, e := g.Observe(auth.WithPrincipal(context.Background(), user), user, model.Surface{Kind: "web", Origin: fixtureOrigin, Title: "Cases"})
		done <- outcome{o, e}
	}()
	c := nextCommand(t, conn)
	enabled := true
	if c.Action != "observe" || c.Identity.DocumentID != "document1" || c.BrokerEpoch == "" || c.ScopeHash == "" {
		t.Fatal("missing command identity")
	}
	if err = WriteFrame(conn, Reply{RequestID: c.RequestID, Identity: c.Identity, Nodes: []Node{{ID: "save", Role: "button", Name: "Save", Enabled: &enabled}}, Coverage: []string{"DOM fixture only"}}); err != nil {
		t.Fatal(err)
	}
	result := <-done
	if result.err != nil || len(result.observation.Nodes) != 1 || result.observation.Nodes[0].Identifier != "save" {
		t.Fatalf("observation %+v %v", result.observation, result.err)
	}
}
func TestTwoProfilesNeverGuessFirst(t *testing.T) {
	user := principal(t, "a")
	one, two := enrollment(user, "profile1"), enrollment(user, "profile2")
	b := fixtureBroker(t, one, two)
	a, c := connectHost(t, b, one), connectHost(t, b, two)
	publish(t, b, a, one, document(one, 7))
	publish(t, b, c, two, document(two, 7))
	_, _, err := b.selectDocument(user, model.Surface{Kind: "web", Origin: fixtureOrigin, TabID: "7"})
	code(t, err, "ambiguousTarget")
	selected, _, err := b.selectDocument(user, model.Surface{Kind: "web", Origin: fixtureOrigin, TabID: "profile2/browser1/7"})
	if err != nil || selected.grant.ProfileChannel != "profile2" {
		t.Fatalf("qualified profile selection failed: %v", err)
	}
}
func TestCancelledMutationRetainsLateReceiptWithoutReplay(t *testing.T) {
	user := principal(t, "a")
	grant := enrollment(user, "profile1")
	b := fixtureBroker(t, grant)
	conn := connectHost(t, b, grant)
	d := document(grant, 7)
	publish(t, b, conn, grant, d)
	c, _, _ := b.selectDocument(user, model.Surface{Kind: "web", Origin: fixtureOrigin})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	input := Command{Action: "element.press", Identity: d.Identity, AttemptID: "attempt1", Locator: &Locator{Strategy: "id", Value: "save", Exact: true}}
	go func() { _, e := b.call(ctx, c, input, true); done <- e }()
	sent := nextCommand(t, conn)
	cancel()
	code(t, <-done, "cancelled")
	_, err := b.call(context.Background(), c, input, true)
	code(t, err, "unknownEffect")
	if err = WriteFrame(conn, Reply{RequestID: sent.RequestID, AttemptID: sent.AttemptID, Identity: sent.Identity, DispatchState: "dispatched", EffectState: "unverified"}); err != nil {
		t.Fatal(err)
	}
	until := time.Now().Add(time.Second)
	for {
		b.mu.Lock()
		_, known := c.receipts["attempt1"]
		b.mu.Unlock()
		if known {
			break
		}
		if time.Now().After(until) {
			t.Fatal("late receipt not retained")
		}
		time.Sleep(time.Millisecond)
	}
	receipt, err := b.QueryReceipt(auth.WithPrincipal(context.Background(), user), user, "attempt1")
	if err != nil || receipt.DispatchState != "dispatched" {
		t.Fatal(receipt, err)
	}
	receipt, err = b.call(context.Background(), c, input, true)
	if err != nil || receipt.DispatchState != "dispatched" {
		t.Fatal("duplicate attempt not served from receipt")
	}
	input.Args = map[string]any{"value": "changed"}
	_, err = b.call(context.Background(), c, input, true)
	code(t, err, "attemptConflict")
}
func TestReceiptMismatchBlocksMutationAndReconnectCanQuery(t *testing.T) {
	user := principal(t, "a")
	grant := enrollment(user, "profile1")
	b := fixtureBroker(t, grant)
	conn := connectHost(t, b, grant)
	d := document(grant, 7)
	publish(t, b, conn, grant, d)
	c, _, _ := b.selectDocument(user, model.Surface{Kind: "web", Origin: fixtureOrigin})
	done := make(chan error, 1)
	go func() {
		_, e := b.call(context.Background(), c, Command{Action: "element.press", Identity: d.Identity, AttemptID: "attempt1"}, true)
		done <- e
	}()
	sent := nextCommand(t, conn)
	wrong := sent.Identity
	wrong.DocumentID = "another-document"
	if e := WriteFrame(conn, Reply{RequestID: sent.RequestID, AttemptID: sent.AttemptID, Identity: wrong, DispatchState: "dispatched"}); e != nil {
		t.Fatal(e)
	}
	code(t, <-done, "receiptMismatch")
	conn.Close()
	until := time.Now().Add(time.Second)
	for {
		b.mu.Lock()
		offline := c.conn == nil
		b.mu.Unlock()
		if offline {
			break
		}
		if time.Now().After(until) {
			t.Fatal("host did not disconnect")
		}
		time.Sleep(time.Millisecond)
	}
	reconnected := connectHost(t, b, grant)
	publish(t, b, reconnected, grant, d)
	queryDone := make(chan error, 1)
	go func() {
		_, e := b.QueryReceipt(auth.WithPrincipal(context.Background(), user), user, "attempt1")
		queryDone <- e
	}()
	query := nextCommand(t, reconnected)
	if query.Action != "receipt.query" || query.AttemptID != "attempt1" || query.ChannelEpoch != sent.ChannelEpoch || query.BrokerEpoch != sent.BrokerEpoch {
		t.Fatal("reconnect replayed or replaced fences")
	}
	if e := WriteFrame(reconnected, Reply{RequestID: query.RequestID, AttemptID: query.AttemptID, Identity: query.Identity, DispatchState: "dispatched"}); e != nil {
		t.Fatal(e)
	}
	if err := <-queryDone; err != nil {
		t.Fatal(err)
	}
	b.mu.Lock()
	unknown := len(c.unknown)
	b.mu.Unlock()
	if unknown != 0 {
		t.Fatal("retained receipt query did not clear transport uncertainty")
	}
}
func TestProductionAndMalformedEnrollmentFailClosed(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	_, err := newBroker(Config{SocketPath: filepath.Join(dir, "b.sock")}, nil)
	if err == nil {
		t.Fatal("production accepted")
	}
	grant := enrollment(principal(t, "a"), "profile1")
	grant.Origins = []string{"https://*.example.test"}
	_, err = newBroker(Config{SocketPath: filepath.Join(dir, "b.sock"), FixtureEnrollment: true, Grants: []Enrollment{grant}}, map[string]string{channelKey(grant.ProfileChannel, grant.BrowserInstance): strings.Repeat("s", 32)})
	if err == nil {
		t.Fatal("wildcard origin accepted")
	}
}

func TestGatewayReadPreservesTypedLocatorAndAssertionFailure(t *testing.T) {
	user := principal(t, "a")
	grant := enrollment(user, "profile1")
	b := fixtureBroker(t, grant)
	conn := connectHost(t, b, grant)
	publish(t, b, conn, grant, document(grant, 7))
	gateway, _ := NewGateway(b, GatewayOptions{})
	step := model.Step{ID: "read-case", Action: "element.read", Target: model.Selector{Surface: model.Surface{Kind: "web", Origin: fixtureOrigin}, Cardinality: "one", Locator: &model.Locator{Strategy: "id", Exact: true, Value: model.Value{Kind: model.ReferenceValue, Ref: "input.id"}}}, Arguments: map[string]model.Value{"attribute": {Kind: model.StringValue, String: "value"}}, Effect: model.Effect{Class: model.ReadOnly}, TimeoutMs: 1000}
	ctx := auth.WithPrincipal(context.Background(), user)
	done := make(chan error, 1)
	go func() {
		result, e := gateway.Execute(ctx, user, step, map[string]model.Value{"input.id": {Kind: model.StringValue, String: "literal ${notExpanded}\n\"quoted\""}})
		if e == nil && (result.Value == nil || result.Value.String != "actual-value" || result.VerificationState != "verified") {
			e = errors.New("read value mismatch")
		}
		done <- e
	}()
	observe := nextCommand(t, conn)
	if e := WriteFrame(conn, Reply{RequestID: observe.RequestID, Identity: observe.Identity}); e != nil {
		t.Fatal(e)
	}
	read := nextCommand(t, conn)
	if read.Action != "read" || read.Locator.Value != "literal ${notExpanded}\n\"quoted\"" || read.Args["attribute"] != "value" {
		t.Fatal("typed locator was reinterpreted")
	}
	value := "actual-value"
	if e := WriteFrame(conn, Reply{RequestID: read.RequestID, Identity: read.Identity, Value: &value}); e != nil {
		t.Fatal(e)
	}
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	step.Action = "expect"
	step.Arguments = nil
	step.Target.Locator.Value = model.Value{Kind: model.StringValue, String: "case"}
	step.Assertion = &model.Assertion{Matcher: "toHaveValue", Expected: &model.Value{Kind: model.StringValue, String: "wrong-value"}}
	go func() { _, e := gateway.Execute(ctx, user, step, nil); done <- e }()
	observe = nextCommand(t, conn)
	_ = WriteFrame(conn, Reply{RequestID: observe.RequestID, Identity: observe.Identity})
	read = nextCommand(t, conn)
	_ = WriteFrame(conn, Reply{RequestID: read.RequestID, Identity: read.Identity, Value: &value})
	code(t, <-done, "assertionFailed")
}

func TestInvalidInventoryAndReadOnlyGrantCannotMutate(t *testing.T) {
	user := principal(t, "a")
	grant := enrollment(user, "profile1")
	grant.Principal.Scopes = []string{"desktop:observe"}
	b := fixtureBroker(t, grant)
	conn := connectHost(t, b, grant)
	d := document(grant, 7)
	publish(t, b, conn, grant, d)
	c, _, e := b.selectDocument(user, model.Surface{Kind: "web", Origin: fixtureOrigin})
	if e != nil {
		t.Fatal(e)
	}
	_, e = b.call(context.Background(), c, Command{Action: "element.press", Identity: d.Identity, AttemptID: "a1"}, true)
	if !errors.Is(e, auth.ErrUnauthorized) {
		t.Fatalf("read-only enrollment mutation accepted: %v", e)
	}
	d.Origin = "https://untrusted.example.test"
	if e = WriteFrame(conn, map[string]any{"type": "documents", "documents": []Document{d}}); e != nil {
		t.Fatal(e)
	}
	until := time.Now().Add(time.Second)
	for {
		b.mu.Lock()
		empty := len(c.documents) == 0
		b.mu.Unlock()
		if empty {
			break
		}
		if time.Now().After(until) {
			t.Fatal("unauthorized origin inventory retained")
		}
		time.Sleep(time.Millisecond)
	}
	_, _, e = b.selectDocument(user, model.Surface{Kind: "web", Origin: fixtureOrigin})
	code(t, e, "ambiguousTarget")
}
