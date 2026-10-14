package chrome

import (
	"context"
	"github.com/viant/mechanize/auth/nativepeer"
	"github.com/viant/mechanize/model"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// Count the existing exact admission path before assigning a deterministic
// signature cost. No DOM, credentials, input or private runtime is involved.
func TestControlAdmissionSignatureCostCensus(t *testing.T) {
	g, p, ctx, source, submit := privacyFixture(t)
	defer g.Close()
	proof, err := g.QualifyCredentialPrivacy(ctx, p, source, submit, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	a, ok := proof.Authority()
	if !ok {
		t.Fatal("privacy proof unavailable")
	}
	var full atomic.Int64
	original := g.broker.verifyPeer
	g.broker.verifyPeer = func(c context.Context, n *net.UnixConn) (nativepeer.ChromeProcessEvidence, error) {
		full.Add(1)
		return original(c, n)
	}
	g.broker.verifyPeerIdentity = func(context.Context, *net.UnixConn, nativepeer.ChromeProcessEvidence) error { return nil }
	admission, err := g.AdmitControlWithStatus(ctx, p, model.Surface{Kind: "web", Origin: a.Document.Origin, TabID: a.Document.QualifiedTabID()})
	if err != nil || !admission.Confirmed {
		t.Fatal(err)
	}
	t.Logf("full signed verifications per published admission: %d", full.Load())
}

func TestControlAdmissionDelayedSignaturesFitOriginalBudget(t *testing.T) {
	g, p, ctx, source, submit := privacyFixture(t)
	defer g.Close()
	proof, err := g.QualifyCredentialPrivacy(ctx, p, source, submit, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	a, ok := proof.Authority()
	if !ok {
		t.Fatal("privacy proof unavailable")
	}
	var full, identity atomic.Int64
	original := g.broker.verifyPeer
	g.broker.verifyPeer = func(c context.Context, n *net.UnixConn) (nativepeer.ChromeProcessEvidence, error) {
		full.Add(1)
		timer := time.NewTimer(240 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-c.Done():
			return nativepeer.ChromeProcessEvidence{}, c.Err()
		case <-timer.C:
		}
		return original(c, n)
	}
	g.broker.verifyPeerIdentity = func(context.Context, *net.UnixConn, nativepeer.ChromeProcessEvidence) error {
		identity.Add(1)
		return nil
	}
	bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	admission, err := g.AdmitControlWithStatus(bounded, p, model.Surface{Kind: "web", Origin: a.Document.Origin, TabID: a.Document.QualifiedTabID()})
	if err != nil || !admission.Confirmed {
		phase, reason := ControlFailureDiagnostic(err)
		t.Fatalf("3s admission exhausted repeated signed checks: created=%v confirmed=%v phase=%s reason=%s full=%d kernel=%d", admission.Created, admission.Confirmed, phase, reason, full.Load(), identity.Load())
	}
	if full.Load() > 2 || identity.Load() == 0 {
		t.Fatal("signed admission proof was not locally reused", full.Load(), identity.Load())
	}
}
