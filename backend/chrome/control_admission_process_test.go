package chrome

import (
	"context"
	"errors"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/auth/nativepeer"
	"github.com/viant/mechanize/model"
	"net"
	"sync/atomic"
	"testing"
)

func TestAdmissionProcessReuseRejectsChangedOriginalBoundary(t *testing.T) {
	for _, mode := range []string{"connection", "evidence", "process", "epoch", "scope", "actor", "consent", "document", "lease", "kernel", "kernelRace", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			g, p, base, _ := controlFixture(t)
			defer g.Close()
			base = auth.WithConsentBinding(base, auth.ConsentBinding{SessionID: "original", GrantID: "grant", Purpose: "original admission"})
			a, err := g.AdmitControl(base, p, controlStep(t).Target.Surface)
			if err != nil {
				t.Fatal(err)
			}
			b, c := g.broker, g.controlChannel(a)
			b.verifyPeerIdentity = func(context.Context, *net.UnixConn, nativepeer.ChromeProcessEvidence) error {
				if mode == "kernel" {
					return errors.New("changed kernel peer")
				}
				if mode == "kernelRace" {
					b.mu.Lock()
					c.epoch = "changed-during-check"
					b.mu.Unlock()
				}
				return nil
			}
			ctx, err := g.admissionProcessContext(base, a, c)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "connection":
				replacement, other := net.Pipe()
				defer replacement.Close()
				defer other.Close()
				b.mu.Lock()
				c.conn = replacement
				b.mu.Unlock()
			case "evidence":
				b.mu.Lock()
				copied := *c.processEvidence
				c.processEvidence = &copied
				b.mu.Unlock()
			case "process":
				b.mu.Lock()
				c.processEvidence.NativeHost.StartToken = "changed-birth"
				b.mu.Unlock()
			case "epoch":
				b.mu.Lock()
				c.epoch = "changed-channel"
				b.mu.Unlock()
			case "scope":
				b.mu.Lock()
				c.scopeHash = "changed-scope"
				b.mu.Unlock()
			case "actor":
				other := p
				other.ClientID = "changed-client"
				ctx = auth.WithPrincipal(ctx, other)
			case "consent":
				ctx = auth.WithConsentBinding(ctx, auth.ConsentBinding{SessionID: "other", GrantID: "grant", Purpose: "original admission"})
			case "document":
				b.mu.Lock()
				c.documents[0].DocumentID = "replacement-document"
				b.mu.Unlock()
			case "lease":
				g.controlMu.Lock()
				copy := *g.controlRecordLocked(a).authority
				copy.Lease.ID = "replacement-lease"
				g.controlRecordLocked(a).authority = &copy
				g.controlMu.Unlock()
			case "cancelled":
				canceled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = canceled
			}
			if err = g.VerifyControl(ctx, p, a); err == nil {
				t.Fatal("changed original boundary borrowed signed admission proof", mode)
			}
		})
	}
}

func TestAdmissionReuseEndsAtReturnAndLaterInputVerifiesFullTrust(t *testing.T) {
	g, p, ctx, count := controlFixture(t)
	defer g.Close()
	b := g.broker
	var signatures, kernels atomic.Int64
	original := b.verifyPeer
	b.verifyPeer = func(c context.Context, n *net.UnixConn) (nativepeer.ChromeProcessEvidence, error) {
		signatures.Add(1)
		return original(c, n)
	}
	b.verifyPeerIdentity = func(context.Context, *net.UnixConn, nativepeer.ChromeProcessEvidence) error {
		kernels.Add(1)
		return nil
	}
	step := controlStep(t)
	a, err := g.AdmitControl(ctx, p, step.Target.Surface)
	if err != nil {
		t.Fatal(err)
	}
	first := signatures.Load()
	if first < 1 || kernels.Load() == 0 {
		t.Fatal("admission did not establish signed trust with fresh kernel checks")
	}
	_, err = g.AdmitControl(ctx, p, step.Target.Surface)
	if err != nil {
		t.Fatal(err)
	}
	if signatures.Load() <= first {
		t.Fatal("separate admission reused prior signature scope")
	}
	beforeInput := signatures.Load()
	result, err := g.ExecuteControl(ctx, p, step, nil, a)
	if err != nil || result.DispatchState != "dispatched" || count.Load() != 1 || signatures.Load() <= beforeInput {
		t.Fatal("actual later input skipped full trust or was replayed", err)
	}
}

func TestAdmissionUnsupportedReuseRetainsExistingFullVerification(t *testing.T) {
	g, p, ctx, _ := controlFixture(t)
	defer g.Close()
	a, err := g.AdmitControl(ctx, p, controlStep(t).Target.Surface)
	if err != nil {
		t.Fatal(err)
	}
	c := g.controlChannel(a)
	derived, err := g.admissionProcessContext(ctx, a, c)
	if err != nil || derived != ctx {
		t.Fatal("missing identity verifier introduced an additional gate")
	}
	g.broker.mu.Lock()
	c.fixtureOnly = true
	c.processEvidence = nil
	g.broker.mu.Unlock()
	derived, err = g.admissionProcessContext(ctx, a, c)
	if err != nil || derived != ctx {
		t.Fatal("fixture transport introduced an additional gate")
	}
}

func TestAdmissionCapturedProcessContextCannotSurviveCompletion(t *testing.T) {
	g, p, ctx, source, submit := privacyFixture(t)
	defer g.Close()
	var captured context.Context
	proof, err := g.QualifyCredentialPrivacy(ctx, p, source, submit, func(c context.Context) error {
		if c.Value(controlAdmissionProcessKey{}) != nil {
			captured = c
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	a, ok := proof.Authority()
	if !ok {
		t.Fatal("proof missing")
	}
	g.broker.verifyPeerIdentity = func(context.Context, *net.UnixConn, nativepeer.ChromeProcessEvidence) error { return nil }
	admitted, err := g.AdmitControlWithStatus(ctx, p, model.Surface{Kind: "web", Origin: a.Document.Origin, TabID: a.Document.QualifiedTabID()})
	if err != nil {
		t.Fatal(err)
	}
	if captured == nil || captured.Err() == nil {
		t.Fatal("admission process context outlived its owner")
	}
	if g.VerifyControl(captured, p, admitted.Authority) == nil {
		t.Fatal("completed admission context admitted later work")
	}
}
