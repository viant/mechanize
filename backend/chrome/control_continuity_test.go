package chrome

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"

	"github.com/viant/mechanize/auth/nativepeer"
	"github.com/viant/mechanize/model"
)

func TestControlContinuityAvoidsSignatureScanButFullCheckRemains(t *testing.T) {
	g, p, ctx, source, submit := privacyFixture(t)
	defer g.Close()
	proof, err := g.QualifyCredentialPrivacy(ctx, p, source, submit, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	a, ok := proof.Authority()
	if !ok {
		t.Fatal("missing admitted authority")
	}
	admission, err := g.AdmitControlWithStatus(ctx, p, model.Surface{Kind: "web", Origin: a.Document.Origin, TabID: a.Document.QualifiedTabID()})
	if err != nil || !admission.Confirmed {
		t.Fatal("admission failed", err)
	}
	a = admission.Authority
	var full, identity atomic.Int32
	original := g.broker.verifyPeer
	g.broker.verifyPeer = func(c context.Context, n *net.UnixConn) (nativepeer.ChromeProcessEvidence, error) {
		full.Add(1)
		return original(c, n)
	}
	g.broker.verifyPeerIdentity = func(context.Context, *net.UnixConn, nativepeer.ChromeProcessEvidence) error {
		identity.Add(1)
		return nil
	}
	if err := g.VerifyControlContinuity(ctx, p, a); err != nil {
		t.Fatal(err)
	}
	if full.Load() != 0 || identity.Load() == 0 {
		t.Fatalf("metadata scans: full=%d identity=%d", full.Load(), identity.Load())
	}
	if err := g.VerifyControl(ctx, p, a); err != nil {
		t.Fatal(err)
	}
	if full.Load() == 0 {
		t.Fatal("ordinary execution check lost full signed verification")
	}
	// A changed kernel peer cannot inherit the admitted authority.
	g.broker.verifyPeerIdentity = func(context.Context, *net.UnixConn, nativepeer.ChromeProcessEvidence) error {
		return errors.New("changed peer")
	}
	if err := g.VerifyControlContinuity(ctx, p, a); err == nil {
		t.Fatal("changed peer accepted")
	}
}

func TestControlContinuityRejectsStaleLeaseAndCancellation(t *testing.T) {
	g, p, ctx, source, submit := privacyFixture(t)
	defer g.Close()
	proof, err := g.QualifyCredentialPrivacy(ctx, p, source, submit, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	a, ok := proof.Authority()
	if !ok {
		t.Fatal("missing authority")
	}
	admission, err := g.AdmitControlWithStatus(ctx, p, model.Surface{Kind: "web", Origin: a.Document.Origin, TabID: a.Document.QualifiedTabID()})
	if err != nil || !admission.Confirmed {
		t.Fatal("admission failed", err)
	}
	a = admission.Authority
	g.broker.verifyPeerIdentity = func(context.Context, *net.UnixConn, nativepeer.ChromeProcessEvidence) error { return nil }
	stale := a
	stale.Lease.Generation++
	if err := g.VerifyControlContinuity(ctx, p, stale); err == nil {
		t.Fatal("stale lease accepted")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := g.VerifyControlContinuity(canceled, p, a); err == nil {
		t.Fatal("canceled check accepted")
	}
	c := g.controlChannel(a)
	g.broker.mu.Lock()
	c.lifecycleInhibited = true
	g.broker.mu.Unlock()
	if err := g.VerifyControlContinuity(ctx, p, a); err == nil {
		t.Fatal("inhibited channel accepted")
	}
}
