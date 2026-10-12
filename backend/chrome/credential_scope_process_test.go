package chrome

import (
	"context"
	"errors"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/auth/nativepeer"
	"net"
	"strings"
	"testing"
)

func TestCredentialScopeProcessPinInvalidatesReplacedChannelProcessOrActor(t *testing.T) {
	for _, mode := range []string{"channel", "process", "actor", "consent", "kernel"} {
		t.Run(mode, func(t *testing.T) {
			g, p, base, c, _ := setupFixture(t)
			ctx := auth.WithConsentBinding(base, auth.ConsentBinding{SessionID: "owned", Purpose: "cleanup"})
			g.broker.verifyPeerIdentity = func(context.Context, *net.UnixConn, nativepeer.ChromeProcessEvidence) error {
				if mode == "kernel" {
					return errors.New("changed")
				}
				return nil
			}
			source := CredentialProtectionScope{PreparationID: strings.Repeat("a", 64), Identity: Identity{ProfileChannel: c.grant.ProfileChannel, BrowserInstance: c.grant.BrowserInstance, TabID: 7, FrameID: 0, DocumentID: "source", Generation: 1}, Origin: c.grant.Origins[0], ChromeStartToken: c.processEvidence.ChromeParent.StartToken}
			pinned, finish, e := g.PinCredentialScopeProcesses(ctx, p, []CredentialProtectionScope{source})
			if e != nil {
				t.Fatal(e)
			}
			switch mode {
			case "channel":
				g.broker.mu.Lock()
				c.epoch = "replacement"
				g.broker.mu.Unlock()
			case "process":
				g.broker.mu.Lock()
				copy := *c.processEvidence
				c.processEvidence = &copy
				g.broker.mu.Unlock()
			case "actor":
				other := p
				other.ClientID = "different"
				pinned = auth.WithPrincipal(pinned, other)
			case "consent":
				pinned = auth.WithConsentBinding(pinned, auth.ConsentBinding{SessionID: "other", Purpose: "cleanup"})
			}
			if g.broker.checkCredentialScopeProcess(pinned, c) == nil {
				t.Fatal("changed pin retained authority")
			}
			if mode != "kernel" && finish(pinned) == nil {
				t.Fatal("full finish accepted replaced context")
			}
		})
	}
}

func TestCredentialScopeProcessPinDoesNotRequireDisconnectedPredecessor(t *testing.T) {
	g, p, base, c, _ := setupFixture(t)
	ctx := auth.WithConsentBinding(base, auth.ConsentBinding{SessionID: "owned", Purpose: "cleanup"})
	source := CredentialProtectionScope{PreparationID: strings.Repeat("a", 64), Identity: Identity{ProfileChannel: c.grant.ProfileChannel, BrowserInstance: c.grant.BrowserInstance, TabID: 7, FrameID: 0, DocumentID: "source", Generation: 1}, Origin: c.grant.Origins[0], ChromeStartToken: c.processEvidence.ChromeParent.StartToken}
	g.broker.mu.Lock()
	c.conn = nil
	g.broker.mu.Unlock()
	pinned, finish, e := g.PinCredentialScopeProcesses(ctx, p, []CredentialProtectionScope{source})
	if e != nil || pinned == nil || finish == nil {
		t.Fatal("disconnected predecessor blocked independent kernel path", e)
	}
	if e = finish(pinned); e != nil {
		t.Fatal(e)
	}
}
