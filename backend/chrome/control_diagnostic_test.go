package chrome

import (
	"context"
	"errors"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/auth/nativepeer"
	"github.com/viant/mechanize/model"
	"net"
	"strings"
	"testing"
	"time"
)

func TestControlMetadataDiagnosticsPreserveExactAdmissionBoundary(t *testing.T) {
	for _, mode := range []string{"replyNotValidated", "ackDeadline", "postAckProcessChanged"} {
		t.Run(mode, func(t *testing.T) {
			f := newReadFixture(t)
			ctx := f.ctx
			switch mode {
			case "replyNotValidated":
				f.rejectAcquire.Store(true)
			case "ackDeadline":
				f.loseAcquire.Store(true)
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 100*time.Millisecond)
				defer cancel()
			case "postAckProcessChanged":
				original := f.g.broker.verifyPeer
				f.g.broker.verifyPeer = func(c context.Context, n *net.UnixConn) (nativepeer.ChromeProcessEvidence, error) {
					e, err := original(c, n)
					if f.acquireCalls.Load() > 0 {
						e.NativeHost.StartToken = "changed-native-birth"
					}
					return e, err
				}
			}
			admission, err := f.g.AdmitControlWithStatus(ctx, f.p, readTarget().Surface)
			if err == nil || !admission.Created || admission.Confirmed || f.mutations.Load() != 0 {
				t.Fatal("fixture did not fail a created metadata admission without input")
			}
			phase, reason := ControlFailureDiagnostic(err)
			expectedPhase, expectedReason := "acquireReply", "notValidated"
			if mode == "ackDeadline" {
				expectedPhase, expectedReason = "acquireAck", "deadline"
			}
			if mode == "postAckProcessChanged" {
				expectedPhase, expectedReason = "postAckVerify", "nativeHostIdentityChanged"
			}
			if phase != expectedPhase || reason != expectedReason {
				t.Fatal("wrong finite boundary", phase, reason)
			}
		})
	}
}

func TestControlMetadataDiagnosticsKeepPreWriteAndRetirementSeparate(t *testing.T) {
	f := newReadFixture(t)
	c := f.g.broker.channels[channelKey("p1", "b1")]
	command := Command{Action: "executor.acquire", Identity: readTargetIdentity(), ControlLease: &Lease{ID: "fixture", Generation: 1}}
	original := errors.Join(auth.ErrUnauthorized, errors.New("PRIVATE_CANARY"))
	_, err := f.g.broker.call(f.ctx, c, command, false, func() error { return original })
	phase, reason := ControlFailureDiagnostic(err)
	if phase != "acquirePreWrite" || reason != "dispatchGateUnauthorized" || strings.Contains(err.Error(), "PRIVATE_CANARY") {
		t.Fatal("pre-write diagnostic lost or leaked")
	}
	a, e := f.g.AdmitControl(f.ctx, f.p, readTarget().Surface)
	if e != nil {
		t.Fatal(e)
	}
	f.g.controlMu.Lock()
	f.g.controlRecordLocked(a).retiring = true
	f.g.controlMu.Unlock()
	f.g.broker.mu.Lock()
	c.unknown["original-unknown"] = true
	f.g.broker.mu.Unlock()
	_, err = f.g.RetireControl(f.ctx, f.p, a)
	phase, reason = ControlFailureDiagnostic(err)
	if phase != "retireVerify" || reason != "executorUnknown" || !c.unknown["original-unknown"] {
		t.Fatal("retirement diagnostic erased original hazard", phase, reason)
	}
}
func readTargetIdentity() Identity {
	return Identity{ProfileChannel: "p1", BrowserInstance: "b1", TabID: 7, DocumentID: "doc1", Generation: 1}
}

func TestControlDiagnosticRejectsPrivateAndUnknownCodes(t *testing.T) {
	for _, err := range []error{errors.New("PRIVATE_CANARY"), browserError("PRIVATE_CANARY", "PRIVATE_CANARY", "unknown")} {
		wrapped := controlFailureAt("acquireReply", err)
		phase, reason := ControlFailureDiagnostic(wrapped)
		if phase != "acquireReply" || reason != "unavailable" || strings.Contains(wrapped.Error(), "PRIVATE_CANARY") {
			t.Fatal("open text entered finite diagnostic")
		}
	}
}

type admissionDiagnosticFixture struct {
	cause  error
	reason string
}

func (e *admissionDiagnosticFixture) Error() string                     { return "PRIVATE_CANARY" }
func (e *admissionDiagnosticFixture) Unwrap() error                     { return e.cause }
func (e *admissionDiagnosticFixture) CredentialAdmissionReason() string { return e.reason }

func TestPublishedPrivacyCallbackFailureSurvivesAcquireAndRetirement(t *testing.T) {
	g, p, ctx, source, submit := privacyFixture(t)
	defer g.Close()
	armed := false
	original := errors.New("PRIVATE_CANARY-original")
	callback := func(context.Context) error {
		if !armed {
			return nil
		}
		g.controlMu.Lock()
		current := testFirstControl(g)
		created := current != nil && current.Lease.ID != source.Lease.ID
		g.controlMu.Unlock()
		if created {
			return &admissionDiagnosticFixture{cause: original, reason: "credentialLease"}
		}
		return nil
	}
	proof, e := g.QualifyCredentialPrivacy(ctx, p, source, submit, callback)
	if e != nil {
		t.Fatal(e)
	}
	a, ok := proof.Authority()
	if !ok {
		t.Fatal("published proof unavailable")
	}
	surface := model.Surface{Kind: "web", Origin: a.Document.Origin, TabID: a.Document.QualifiedTabID()}
	if _, e = g.Observe(ctx, p, surface); e != nil {
		t.Fatal("published ordinary observation failed", e)
	}
	armed = true
	admission, e := g.AdmitControlWithStatus(ctx, p, surface)
	phase, reason := ControlFailureDiagnostic(e)
	if !admission.Created || admission.Confirmed || phase != "acquirePreWrite" || reason != "credentialLease" || !errors.Is(e, original) {
		t.Fatal("callback failure lost at acquisition", phase, reason, e)
	}
	_, cleanup := g.RetireControl(ctx, p, admission.Authority)
	phase, reason = ControlFailureDiagnostic(cleanup)
	if phase != "retirePreWrite" || reason != "credentialLease" || !errors.Is(cleanup, original) {
		t.Fatal("callback failure lost at retirement", phase, reason, cleanup)
	}
	// Open callback messages/codes still cannot enter the projection.
	phase, reason = ControlFailureDiagnostic(controlFailureAt("acquirePreWrite", &admissionDiagnosticFixture{reason: "PRIVATE_CANARY"}))
	if phase != "acquirePreWrite" || reason != "unavailable" {
		t.Fatal("open callback metadata projected")
	}
}

func TestCallbackDeadlineKeepsConsentReasonAtAcquirePreWrite(t *testing.T) {
	g, p, ctx, source, submit := privacyFixture(t)
	defer g.Close()
	armed := false
	callback := func(c context.Context) error {
		if !armed {
			return nil
		}
		g.controlMu.Lock()
		current := testFirstControl(g)
		created := current != nil && current.Lease.ID != source.Lease.ID
		g.controlMu.Unlock()
		if !created {
			return nil
		}
		<-c.Done()
		return &admissionDiagnosticFixture{cause: c.Err(), reason: "credentialConsent"}
	}
	proof, err := g.QualifyCredentialPrivacy(ctx, p, source, submit, callback)
	if err != nil {
		t.Fatal(err)
	}
	a, ok := proof.Authority()
	if !ok {
		t.Fatal("published proof missing")
	}
	armed = true
	bounded, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	admission, err := g.AdmitControlWithStatus(bounded, p, model.Surface{Kind: "web", Origin: a.Document.Origin, TabID: a.Document.QualifiedTabID()})
	phase, reason := ControlFailureDiagnostic(err)
	if !admission.Created || admission.Confirmed || bounded.Err() != context.DeadlineExceeded || !errors.Is(err, context.DeadlineExceeded) || phase != "acquirePreWrite" || reason != "credentialConsent" {
		t.Fatal("deadline replaced the deep callback reason", phase, reason, err)
	}
}
