package chrome

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
)

func TestPublishedPrivacyValidatesAdmissionOnceAndRechecksCallbackState(t *testing.T) {
	for _, mode := range []string{"valid", "revoked", "inactive", "unpublished", "replacedProof", "replacedConnection", "changedTarget", "pending", "unknown", "changedDocument", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			g, p, ctx, source, submit := privacyFixture(t)
			defer g.Close()
			ctx, cancel := context.WithCancel(ctx)
			defer cancel()
			var state *credentialPrivacyState
			armed, calls := false, 0
			var replacement net.Conn
			if mode == "replacedConnection" {
				var peer net.Conn
				replacement, peer = net.Pipe()
				defer replacement.Close()
				defer peer.Close()
			}
			admit := func(context.Context) error {
				if !armed {
					return nil
				}
				calls++
				if mode == "revoked" {
					return errors.New("PRIVATE_ADMISSION_CANARY")
				}
				if mode == "cancelled" {
					cancel()
				}
				g.broker.mu.Lock()
				defer g.broker.mu.Unlock()
				switch mode {
				case "inactive":
					state.active = false
				case "unpublished":
					state.published = false
				case "replacedProof":
					state.channel.privacy = &credentialPrivacyState{}
				case "replacedConnection":
					state.channel.conn = replacement
				case "changedTarget":
					state.identity.DocumentID = "replacement-document"
				case "pending":
					state.channel.pending["concurrent-read"] = &pending{command: Command{RequestID: "concurrent-read", Action: "read", Identity: state.identity}}
				case "unknown":
					state.channel.unknown["unknown-attempt"] = true
				case "changedDocument":
					state.channel.documents[0].DocumentID = "replacement-document"
				}
				return nil
			}
			proof, err := g.QualifyCredentialPrivacy(ctx, p, source, submit, admit)
			if err != nil {
				t.Fatal(err)
			}
			state = proof.state
			originalConn := state.channel.conn
			defer func() {
				g.broker.mu.Lock()
				state.channel.conn = originalConn
				g.broker.mu.Unlock()
			}()
			surface := model.Surface{Kind: "web", Origin: state.source.Document.Origin, TabID: state.authority.Document.QualifiedTabID()}
			armed = true
			err = g.VerifyCredentialPrivacy(ctx, p, proof, surface, true)
			if calls != 1 || (err == nil) != (mode == "valid") {
				t.Fatalf("callback state ignored or admission repeated: mode=%s calls=%d accepted=%v", mode, calls, err == nil)
			}
			if err != nil && err.Error() == "PRIVATE_ADMISSION_CANARY" {
				t.Fatal("private callback error escaped")
			}
		})
	}
}

func TestPublishedPrivacyMutationRetainsWriteScopeCheck(t *testing.T) {
	g, p, ctx, source, submit := privacyFixture(t)
	defer g.Close()
	calls := 0
	proof, err := g.QualifyCredentialPrivacy(ctx, p, source, submit, func(context.Context) error { calls++; return nil })
	if err != nil {
		t.Fatal(err)
	}
	readOnly := p
	readOnly.Scopes = []string{"desktop:observe"}
	ctx = auth.WithPrincipal(ctx, readOnly)
	surface := model.Surface{Kind: "web", Origin: proof.state.source.Document.Origin, TabID: proof.state.authority.Document.QualifiedTabID()}
	before := calls
	if g.VerifyCredentialPrivacy(ctx, readOnly, proof, surface, true) == nil || calls != before {
		t.Fatal("read-only actor reached private mutation admission")
	}
}
