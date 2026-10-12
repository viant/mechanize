package chrome

import (
	"context"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
)

func TestControllerPolicyAuthorizationExactLifetimeAndIdentity(t *testing.T) {
	for _, mode := range []string{"allowed", "foreignClient", "disabled", "originRemoved", "unapproved", "expired", "canceled", "documentChanged", "scopeUnqualified", "scopeRevoked", "cleanupPending", "disconnected"} {
		t.Run(mode, func(t *testing.T) {
			f := newReadFixture(t)
			p := f.p
			p.ClientID = "controller:fixture"
			ctx := auth.WithPrincipal(context.Background(), p)
			lifetime, cancel := context.WithCancel(context.Background())
			defer cancel()
			b := f.g.broker
			b.mu.Lock()
			c := b.channels[channelKey("p1", "b1")]
			c.controllerPolicy = ControllerPolicy{Enabled: true, Origins: []string{"http://localhost:*"}}
			s := &ControllerSession{ID: "trusted", Origin: "http://localhost:3000", DocumentID: "controller-document", Approved: true, ExpiresAt: time.Now().Add(time.Minute), ctx: lifetime, cancel: cancel}
			s.identity = ControllerIdentity{Principal: p, Origin: s.Origin, DocumentID: s.DocumentID, ConversationID: s.ID}
			c.controllerSessions = map[string]*ControllerSession{s.ID: s}
			switch mode {
			case "foreignClient":
				p.ClientID = "controller:other"
				ctx = auth.WithPrincipal(ctx, p)
			case "disabled":
				c.controllerPolicy.Enabled = false
			case "originRemoved":
				c.controllerPolicy.Origins = []string{"https://elsewhere.test"}
			case "unapproved":
				s.Approved = false
			case "expired":
				s.ExpiresAt = time.Now().Add(-time.Second)
			case "canceled":
				cancel()
			case "documentChanged":
				s.DocumentID = "changed"
			case "scopeUnqualified":
				c.scopeQualified = false
				c.profileQualified = false
			case "scopeRevoked":
				c.grant.Principal.Scopes = nil
			case "cleanupPending":
				c.controllerCleanupPending = true
			case "disconnected":
				c.conn = nil
			}
			b.mu.Unlock()
			authorization, err := f.g.AuthorizeControllerPolicy(ctx, p)
			if mode != "allowed" {
				if err == nil || authorization != nil {
					t.Fatal("unqualified policy admitted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer authorization.Release()
			if auth.NativeHuman(authorization.Context) {
				t.Fatal("policy minted human authority")
			}
			if _, ok := auth.ConsentBindingFromContext(authorization.Context); ok {
				t.Fatal("Chrome policy directly minted consent")
			}
			cancel()
			select {
			case <-authorization.Context.Done():
			case <-time.After(time.Second):
				t.Fatal("revoked connection did not cancel admission")
			}
			if f.mutations.Load() != 0 {
				t.Fatal("metadata admission dispatched input")
			}
		})
	}
}
