package durable

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/viant/datly/exec"
	"github.com/viant/datly/spec"
	"github.com/viant/mechanize/auth"
)

func privateActor(t *testing.T) (context.Context, auth.Principal) {
	t.Helper()
	p, err := auth.NewPrincipal("fixture", "", "private-lock", []string{"desktop:control"})
	if err != nil {
		t.Fatal(err)
	}
	p.ClientID = "agent"
	return auth.WithPrincipal(context.Background(), p), p
}
func privateRequest(scope string) exec.ComponentRequest {
	return exec.ComponentRequest{Target: exec.ComponentTarget{Component: spec.Key{Kind: spec.KindComponent, Scope: "github.com/viant/mechanize/data/" + scope, Name: scope}, Route: spec.RouteRef{Method: "GET", Path: "/internal/data/" + scope}}}
}
func TestScopedInvocationCannotEscapeBuilderActorOrCallbackLifetime(t *testing.T) {
	ctx, p := privateActor(t)
	builder := &Builder{}
	user := &userHost{}
	owned, revoke := builder.withHeldUserLock(ctx, p, user)
	changed := p
	changed.ClientID = "another-agent"
	if _, err := builder.InvokePrivateComponent(auth.WithPrincipal(owned, changed), changed, privateRequest("consentrequests")); !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatalf("changed client borrowedlock: %v", err)
	}
	if _, err := (&Builder{}).InvokePrivateComponent(owned, p, privateRequest("consentrequests")); !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatalf("another builder borrowedlock: %v", err)
	}
	if _, err := builder.InvokePrivateComponent(owned, p, privateRequest("loadrun")); err == nil {
		t.Fatal("owned lock expanded private component allowlist")
	}
	revoke()
	if _, err := builder.InvokePrivateComponent(owned, p, privateRequest("consentrequests")); !errors.Is(err, errHeldUserLockExpired) {
		t.Fatalf("escapedcontext not revoked: %v", err)
	}
}
func TestScopedInvocationSerializesAndDrainsBeforeRevocation(t *testing.T) {
	ctx, p := privateActor(t)
	builder := &Builder{}
	user := &userHost{}
	owned, revoke := builder.withHeldUserLock(ctx, p, user)
	got, release, marked, err := builder.heldInvocation(owned, p)
	if err != nil || !marked || got != user {
		t.Fatalf("owned invocation rejected: %v", err)
	}
	started := make(chan struct{})
	drained := make(chan struct{})
	var wait sync.WaitGroup
	wait.Add(1)
	go func() { defer wait.Done(); close(started); revoke(); close(drained) }()
	<-started
	select {
	case <-drained:
		t.Fatal("revokedwhileinvocationinflight")
	default:
	}
	release()
	select {
	case <-drained:
	case <-time.After(time.Second):
		t.Fatal("revocation didnotdrain")
	}
	wait.Wait()
	if _, _, _, err := builder.heldInvocation(owned, p); !errors.Is(err, errHeldUserLockExpired) {
		t.Fatalf("lateinvocation accepted: %v", err)
	}
}
