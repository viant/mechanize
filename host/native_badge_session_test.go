package host

import (
	"context"
	"encoding/json"
	"github.com/viant/mechanize/auth"
	native "github.com/viant/mechanize/backend/darwin"
	"github.com/viant/mechanize/session"
	"testing"
	"time"
)

type sessionBadgeHelper struct{ calls []native.Request }

func (f *sessionBadgeHelper) Close() error { return nil }
func (f *sessionBadgeHelper) Identity() (session.ProcessIdentity, error) {
	return session.ProcessIdentity{}, nil
}
func (f *sessionBadgeHelper) Stop(context.Context) (session.CleanupReport, error) {
	return session.CleanupReport{}, nil
}
func (f *sessionBadgeHelper) Call(ctx context.Context, r native.Request) (native.Reply, error) {
	f.calls = append(f.calls, r)
	result := json.RawMessage(`{"status":"hidden"}`)
	if r.Method == "doctor" {
		result = json.RawMessage(`{"axTrusted":true}`)
	}
	return native.Reply{ProtocolVersion: 1, RequestID: r.RequestID, HelperEpoch: "fixture", Result: result}, nil
}
func TestNativeBadgeSessionReleaseRetainsInputInhibitionAndWaitsOnlyForCurrentWork(t *testing.T) {
	p, _ := auth.NewPrincipal("fixture", "", "owner", []string{"desktop:control"})
	p.ClientID = "client"
	ctx := auth.WithPrincipal(context.Background(), p)
	helper := &sessionBadgeHelper{}
	held := &nativeControlHeld{principal: p, helper: helper, scope: session.Scope{AllowedBundles: []string{"com.fixture.app"}}, inhibited: true, lease: session.Lease{ID: "retained-input-lease"}}
	m := &NativeControlManager{held: held}
	m.mu.Lock()
	bounded, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- m.ReleasePresentationSession(bounded, p, "session") }()
	if err := <-done; err == nil {
		t.Fatal("busy presentation cleanup ignored deadline")
	}
	m.mu.Unlock()
	if len(helper.calls) != 0 {
		t.Fatal("blocked cleanup entered helper")
	}
	if err := m.ReleasePresentationSession(ctx, p, "session"); err != nil {
		t.Fatal(err)
	}
	if m.held != held || !held.inhibited || held.lease.ID != "retained-input-lease" {
		t.Fatal("presentation cleanup changed input authority")
	}
	if len(helper.calls) != 2 || helper.calls[0].Method != "doctor" || helper.calls[1].Method != "controlBadge.releaseSession" || helper.calls[1].Lease != nil {
		t.Fatal("cleanup issued non-presentation method")
	}
}
