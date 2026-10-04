package host

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/consent"
)

func TestRecordingBindingRejectsSameUserDifferentClientOrSession(t *testing.T) {
	p, _ := auth.NewPrincipal("fixture", "", "employee", []string{"desktop:control"})
	p.ClientID = "client-a"
	h := &Host{users: map[string]User{p.Namespace: {DesktopAccess: true, RecordingAllowed: true}}}
	entry := &recordingBinding{principal: p, binding: auth.ConsentBinding{SessionID: "session-a"}}
	b := &recordingBackend{host: h, bindings: map[string]*recordingBinding{recordingBindingKey(p, "demo"): entry}}
	ctx := auth.WithConsentBinding(auth.WithPrincipal(context.Background(), p), entry.binding)
	if got, err := b.owned(ctx, p, "demo"); err != nil || got != entry {
		t.Fatalf("owner rejected: %v", err)
	}
	other := p
	other.ClientID = "client-b"
	for _, candidate := range []struct {
		ctx context.Context
		p   auth.Principal
	}{
		{auth.WithPrincipal(ctx, other), other},
		{auth.WithConsentBinding(ctx, auth.ConsentBinding{SessionID: "session-b"}), p},
		{auth.WithPrincipal(context.Background(), p), p},
	} {
		if _, err := b.owned(candidate.ctx, candidate.p, "demo"); !errors.Is(err, auth.ErrUnauthorized) {
			t.Fatal("cross-client or session recording ownership accepted")
		}
	}
}

func TestRecordingRPCStopsOnGrantCancellation(t *testing.T) {
	p, _ := auth.NewPrincipal("fixture", "", "employee", []string{"desktop:control"})
	grant, cancelGrant := context.WithDeadline(context.Background(), time.Now().Add(time.Minute))
	defer cancelGrant()
	lease := &consent.Lease{Context: grant, Release: cancelGrant}
	caller, cancelCaller := context.WithTimeout(context.Background(), time.Second)
	defer cancelCaller()
	ctx, cancel := recordingRPCCtx(caller, p, lease)
	defer cancel()
	deadline, _ := ctx.Deadline()
	original, _ := caller.Deadline()
	if deadline != original {
		t.Fatal("recording RPC lost bounded caller deadline")
	}
	cancelGrant()
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("revoked grant did not cancel pending recording RPC")
	}
}
