package chrome

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
)

func recordingReply(command Command, state string, events ...RecordEvent) Reply {
	last := uint64(0)
	for _, e := range events {
		last = max(last, e.Sequence)
	}
	return Reply{RequestID: command.RequestID, Identity: command.Identity, RecordingID: "record1", RecordingState: state, Events: events, LastSequence: last, RecordingLeaseExpiresUnixMS: time.Now().Add(30 * time.Second).UnixMilli()}
}
func TestRecordingScopeSecretBoundaryAndUnconfirmedStop(t *testing.T) {
	user, other := principal(t, "a"), principal(t, "b")
	grant := enrollment(user, "profile1")
	b := fixtureBroker(t, grant)
	conn := connectHost(t, b, grant)
	d := document(grant, 7)
	publish(t, b, conn, grant, d)
	g, _ := NewGateway(b, GatewayOptions{})
	ctx := auth.WithPrincipal(context.Background(), user)
	type outcome struct {
		batch RecordBatch
		err   error
	}
	done := make(chan outcome, 1)
	go func() {
		batch, e := g.StartRecording(ctx, user, model.Surface{Kind: "web", Origin: fixtureOrigin}, "record1")
		done <- outcome{batch, e}
	}()
	start := nextCommand(t, conn)
	if start.Action != "record.start" || start.Args["recordingId"] != "record1" {
		t.Fatal("unscoped recording start")
	}
	marker := RecordEvent{RecordingID: "record1", Sequence: 1, TimestampUnixMS: time.Now().UnixMilli(), Identity: start.Identity, Origin: fixtureOrigin, Kind: "start", Source: "chromeDOM", Lineage: "record1:document1:1"}
	if e := WriteFrame(conn, recordingReply(start, "recording", marker)); e != nil {
		t.Fatal(e)
	}
	result := <-done
	if result.err != nil || result.batch.State != "recording" || result.batch.LeaseExpiresUnixMS == 0 {
		t.Fatal(result)
	}
	_, e := g.RecordingEvents(auth.WithPrincipal(context.Background(), other), other, "record1", 0, 64)
	if !errors.Is(e, auth.ErrUnauthorized) {
		t.Fatalf("cross-user recording leak: %v", e)
	}
	go func() { batch, e := g.RecordingEvents(ctx, user, "record1", 1, 64); done <- outcome{batch, e} }()
	query := nextCommand(t, conn)
	raw := "swordfish"
	secret := marker
	secret.Kind = "fill"
	secret.Sequence = 2
	secret.Lineage = "record1:document1:2"
	secret.Redacted = true
	secret.Value = &raw
	secret.Trusted = true
	_ = WriteFrame(conn, recordingReply(query, "recording", secret))
	code(t, (<-done).err, "secretRecording")
	conn.Close()
	until := time.Now().Add(time.Second)
	for {
		b.mu.Lock()
		offline := b.channels[channelKey(grant.ProfileChannel, grant.BrowserInstance)].conn == nil
		b.mu.Unlock()
		if offline {
			break
		}
		if time.Now().After(until) {
			t.Fatal("host not closed")
		}
		time.Sleep(time.Millisecond)
	}
	stopped, e := g.StopRecording(ctx, user, "record1")
	if e != nil || stopped.State != "stopUnconfirmed" || len(stopped.Gaps) != 1 {
		t.Fatalf("false recording stop confirmation %+v %v", stopped, e)
	}
}
func TestTypedNavigationLeaseReceiptAndDestinationPolicy(t *testing.T) {
	user := principal(t, "a")
	grant := enrollment(user, "profile1")
	b := fixtureBroker(t, grant)
	conn := connectHost(t, b, grant)
	d := document(grant, 7)
	publish(t, b, conn, grant, d)
	leaseCalls := 0
	g, _ := NewGateway(b, GatewayOptions{Lease: func(ctx context.Context, p auth.Principal) (Lease, error) {
		leaseCalls++
		return Lease{ID: "held-desktop", Generation: 7}, nil
	}})
	ctx := auth.WithPrincipal(context.Background(), user)
	_, e := g.Navigate(ctx, user, model.Surface{Kind: "web", Origin: fixtureOrigin}, "https://untrusted.example.test", "attempt1")
	code(t, e, "originDenied")
	type outcome struct {
		result BrowserResult
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		result, e := g.Navigate(ctx, user, model.Surface{Kind: "web", Origin: fixtureOrigin}, fixtureOrigin+"/next", "attempt1")
		done <- outcome{result, e}
	}()
	observe := nextCommand(t, conn)
	_ = WriteFrame(conn, Reply{RequestID: observe.RequestID, Identity: observe.Identity})
	navigate := nextCommand(t, conn)
	if navigate.Action != "browser.navigate" || navigate.Args["url"] != fixtureOrigin+"/next" || navigate.AttemptID != "attempt1" {
		t.Fatal("wrong navigation payload")
	}
	next := d
	next.DocumentID = "document2"
	_ = WriteFrame(conn, Reply{RequestID: navigate.RequestID, AttemptID: navigate.AttemptID, Identity: navigate.Identity, DispatchState: "dispatched", Ready: true, NewDocument: &next})
	result := <-done
	if result.err != nil || result.result.DispatchState != "dispatched" || result.result.VerificationState != "unknown" || result.result.Document.DocumentID != "document2" || leaseCalls == 0 {
		t.Fatal(result, leaseCalls)
	}
	inventory, e := g.ListTabs(ctx, user)
	if e != nil || !inventory.Complete || len(inventory.Documents) != 1 {
		t.Fatal(inventory, e)
	}
}
func TestObservationDeltaKeepsUserScopeAndReportsOnlySemanticChange(t *testing.T) {
	user := principal(t, "a")
	grant := enrollment(user, "profile1")
	b := fixtureBroker(t, grant)
	conn := connectHost(t, b, grant)
	publish(t, b, conn, grant, document(grant, 7))
	g, _ := NewGateway(b, GatewayOptions{})
	ctx := auth.WithPrincipal(context.Background(), user)
	surface := model.Surface{Kind: "web", Origin: fixtureOrigin}
	type outcome struct {
		delta ObservationDelta
		err   error
	}
	done := make(chan outcome, 1)
	go func() { delta, e := g.ObserveSince(ctx, user, surface, ""); done <- outcome{delta, e} }()
	first := nextCommand(t, conn)
	_ = WriteFrame(conn, Reply{RequestID: first.RequestID, Identity: first.Identity, Nodes: []Node{{Role: "button", ID: "save", Name: "Save"}}})
	initial := <-done
	if initial.err != nil || !initial.delta.Reset || initial.delta.Snapshot == nil {
		t.Fatal(initial)
	}
	go func() {
		delta, e := g.ObserveSince(ctx, user, surface, initial.delta.ObservationID)
		done <- outcome{delta, e}
	}()
	second := nextCommand(t, conn)
	fresh := second.Identity
	fresh.Generation = 2
	_ = WriteFrame(conn, Reply{RequestID: second.RequestID, Identity: fresh, Nodes: []Node{{Role: "button", ID: "save", Name: "Save"}}})
	same := <-done
	if same.err != nil || same.delta.Reset || len(same.delta.Nodes) != 0 || !same.delta.CompleteScope || same.delta.Generation != 2 {
		t.Fatal(same)
	}
	go func() {
		delta, e := g.ObserveSince(ctx, user, surface, same.delta.ObservationID)
		done <- outcome{delta, e}
	}()
	third := nextCommand(t, conn)
	_ = WriteFrame(conn, Reply{RequestID: third.RequestID, Identity: third.Identity, Nodes: []Node{{Role: "button", ID: "save", Name: "Save report"}}})
	changed := <-done
	if changed.err != nil || len(changed.delta.Nodes) != 1 || changed.delta.Nodes[0].Name != "Save report" {
		t.Fatal(changed)
	}
}
func TestUnknownBrowserReceiptStillBlocksAllNewMutation(t *testing.T) {
	user := principal(t, "a")
	grant := enrollment(user, "profile1")
	b := fixtureBroker(t, grant)
	conn := connectHost(t, b, grant)
	d := document(grant, 7)
	publish(t, b, conn, grant, d)
	c, _, _ := b.selectDocument(user, model.Surface{Kind: "web", Origin: fixtureOrigin})
	done := make(chan error, 1)
	go func() {
		_, e := b.call(context.Background(), c, Command{Action: "browser.navigate", Identity: d.Identity, AttemptID: "a1"}, true)
		done <- e
	}()
	command := nextCommand(t, conn)
	_ = WriteFrame(conn, Reply{RequestID: command.RequestID, AttemptID: command.AttemptID, Identity: command.Identity, DispatchState: "dispatched", Error: browserError("redirectOriginDenied", "Outside enrolled scope", "unknown")})
	code(t, <-done, "redirectOriginDenied")
	_, e := b.call(context.Background(), c, Command{Action: "element.press", Identity: d.Identity, AttemptID: "a2"}, true)
	code(t, e, "unknownEffect")
}
