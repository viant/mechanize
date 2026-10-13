package chrome

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
)

func privacyFixture(t *testing.T) (*Gateway, auth.Principal, context.Context, ControlAuthority, string) {
	g, p, ctx, _ := controlFixtureVersion(t, 2)
	binding := auth.ConsentBinding{SessionID: "private-session", GrantID: "private-grant", Purpose: "credential"}
	ctx = auth.WithConsentBinding(ctx, binding)
	a, err := g.AdmitControl(ctx, p, model.Surface{Kind: "web", Origin: "https://fixture.test"})
	if err != nil {
		t.Fatal(err)
	}
	submit := strings.Repeat("a", 64)
	g.broker.mu.Lock()
	c := g.broker.channels[channelKey(a.Document.ProfileChannel, a.Document.BrowserInstance)]
	c.privateFlow = &credentialFlow{authority: a, binding: binding, fillAttempt: strings.Repeat("b", 64), submitAttempt: submit, submitConfirmed: true}
	g.broker.mu.Unlock()
	return g, p, ctx, a, submit
}

func TestPublishedLoginHandoffDoesNotRepeatPrivateInspection(t *testing.T) {
	g, p, ctx, source, submit := privacyFixture(t)
	proof, err := g.QualifyCredentialPrivacy(ctx, p, source, submit, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	a, _ := proof.Authority()
	c := g.controlChannel(a)
	c.writeMu.Lock()
	done := make(chan error, 1)
	go func() {
		done <- g.VerifyCredentialPrivacy(ctx, p, proof, model.Surface{Kind: "web", Origin: a.Document.Origin, TabID: a.Document.QualifiedTabID()}, true)
	}()
	select {
	case err := <-done:
		c.writeMu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		c.writeMu.Unlock()
		<-done
		t.Fatal("post-login access repeated blocking private handshake")
	}
}

func TestPublishedPrivacyMissingInventoryRequestsQualificationWithoutAuthority(t *testing.T) {
	g, p, ctx, source, submit := privacyFixture(t)
	proof, err := g.QualifyCredentialPrivacy(ctx, p, source, submit, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	a, _ := proof.Authority()
	c := g.controlChannel(a)
	g.broker.mu.Lock()
	c.documents = nil
	g.broker.mu.Unlock()
	c.writeMu.Lock()
	err = g.VerifyCredentialPrivacy(ctx, p, proof, model.Surface{Kind: "web", Origin: a.Document.Origin, TabID: a.Document.QualifiedTabID()}, false)
	c.writeMu.Unlock()
	if !errors.Is(err, ErrCredentialPrivacyDocumentChanged) {
		t.Fatal("missing root did not request fresh qualification", err)
	}
	g.broker.mu.Lock()
	defer g.broker.mu.Unlock()
	if len(c.documents) != 0 {
		t.Fatal("missing root manufactured document authority")
	}
}

func TestPrivateRetirementSurvivesDOMGenerationChangeWithoutAllowingStaleInput(t *testing.T) {
	g, p, ctx, source, submit := privacyFixture(t)
	proof, err := g.QualifyCredentialPrivacy(ctx, p, source, submit, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	a, _ := proof.Authority()
	a, err = g.AdmitControl(ctx, p, model.Surface{Kind: "web", Origin: a.Document.Origin, TabID: a.Document.QualifiedTabID()})
	if err != nil {
		t.Fatal(err)
	}
	c := g.controlChannel(a)
	g.broker.mu.Lock()
	proof.state.identity.Generation++
	for i := range c.documents {
		if c.documents[i].DocumentID == a.Document.DocumentID {
			c.documents[i].Generation++
		}
	}
	g.broker.mu.Unlock()
	if err := g.broker.guardPrivacyCommand(ctx, c, Command{Action: "element.press", Identity: a.Document.Identity}, true); err == nil {
		t.Fatal("stale generation authorized input")
	}
	if retired, err := g.RetireControl(ctx, p, a); !retired || err != nil {
		t.Fatalf("same-document cleanup trapped old lease: retired=%v err=%v", retired, err)
	}
}
func TestCredentialPrivacyPromotesFreshAuthorityAndGuardsOrdinaryRouting(t *testing.T) {
	g, p, ctx, source, submit := privacyFixture(t)
	calls := 0
	admit := func(context.Context) error { calls++; return nil }
	proof, err := g.QualifyCredentialPrivacy(ctx, p, source, submit, admit)
	if err != nil {
		t.Fatal(err)
	}
	a, valid := proof.Authority()
	if !valid || a.Lease == source.Lease || a.Document.DocumentID == source.Document.DocumentID {
		t.Fatal("private source authority reused")
	}
	surface := model.Surface{Kind: "web", Origin: a.Document.Origin, TabID: a.Document.QualifiedTabID()}
	if err = g.VerifyCredentialPrivacy(ctx, p, proof, surface, true); err != nil {
		t.Fatal(err)
	}
	nextAdmission, e := g.AdmitControlWithStatus(ctx, p, surface)
	if e != nil || !nextAdmission.Created {
		t.Fatal("ordinary provider cannot own a fresh lease", e)
	}
	if ok, e := g.RetireControl(ctx, p, nextAdmission.Authority); e != nil || !ok {
		t.Fatal("ordinary lease retirement failed", e)
	}
	before := calls
	if _, _, err = g.controlSnapshot(ctx, p, surface); err != nil {
		t.Fatal(err)
	}
	if calls <= before {
		t.Fatal("public admission skipped live consent")
	}
	foreign := auth.WithConsentBinding(ctx, auth.ConsentBinding{SessionID: "different", GrantID: "private-grant", Purpose: "credential"})
	if g.VerifyCredentialPrivacy(foreign, p, proof, surface, false) == nil {
		t.Fatal("foreign session borrowed proof")
	}
	if _, err = g.Observe(foreign, p, surface); err == nil {
		t.Fatal("ordinary observation bypassed private session")
	}
	if _, err = g.broker.call(ctx, g.controlChannel(a), Command{Action: "record.start", Identity: a.Document.Identity}, true); err == nil {
		t.Fatal("DOM proof authorized recording")
	}
	if err = g.broker.guardPrivacyCommand(ctx, g.controlChannel(a), Command{Action: "browser.navigate", Identity: a.Document.Identity, Args: map[string]any{"url": "https://foreign.test/"}}, true); err == nil {
		t.Fatal("DOM proof broadened navigation origin")
	}
	if _, err = json.Marshal(proof); err == nil {
		t.Fatal("opaque proof serialized")
	}
	if g.CancelVaultCredential(ctx, p, source) != nil {
		t.Fatal("source lineage cancellation failed after promotion")
	}
	if g.VerifyCredentialPrivacy(ctx, p, proof, surface, false) == nil {
		t.Fatal("cancelled proof remained usable")
	}
}

func TestSameDocumentPrivacyRequiresClosedAdvanceAndFreshRedactionProof(t *testing.T) {
	var stage atomic.Value
	stage.Store("pending")
	g, p, ctx, _ := controlFixtureVersion(t, 2, func() string { return stage.Load().(string) })
	binding := auth.ConsentBinding{SessionID: "private", GrantID: "grant", Purpose: "login"}
	ctx = auth.WithConsentBinding(ctx, binding)
	source, e := g.AdmitControl(ctx, p, model.Surface{Kind: "web", Origin: "https://fixture.test"})
	if e != nil {
		t.Fatal(e)
	}
	submit := strings.Repeat("a", 64)
	g.broker.mu.Lock()
	c := g.broker.channels[channelKey(source.Document.ProfileChannel, source.Document.BrowserInstance)]
	c.privateFlow = &credentialFlow{authority: source, binding: binding, fillAttempt: strings.Repeat("b", 64), submitAttempt: submit, submitConfirmed: true}
	g.broker.mu.Unlock()
	_, e = g.AdvanceVaultCredential(ctx, p, source, submit, func(context.Context) error { return nil })
	if !errors.Is(e, ErrCredentialPostSubmitPending) {
		t.Fatal("pending SPA metadata unavailable", e)
	}
	g.broker.mu.Lock()
	pending := c.privateFlow.sameDocumentPrivacy
	connected := c.conn != nil
	g.broker.mu.Unlock()
	if pending || !connected {
		t.Fatal("pending status promoted or disconnected")
	}
	stage.Store("spaPrivacy")
	_, e = g.AdvanceVaultCredential(ctx, p, source, submit, func(context.Context) error { return nil })
	if !errors.Is(e, ErrCredentialPrivacyCandidate) {
		t.Fatal("privacy candidate not isolated", e)
	}
	proof, e := g.QualifyCredentialPrivacy(ctx, p, source, submit, func(context.Context) error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	next, ok := proof.Authority()
	if !ok || next.Document.DocumentID != source.Document.DocumentID || next.Lease == source.Lease {
		t.Fatal("SPA authority not freshly qualified")
	}
	if e = g.VerifyCredentialPrivacy(ctx, p, proof, model.Surface{Kind: "web", Origin: next.Document.Origin, TabID: next.Document.QualifiedTabID()}, false); e != nil {
		t.Fatal(e)
	}
}
func TestCredentialPrivacyRejectsForgedAndMalformedProofs(t *testing.T) {
	g, p, ctx, a, _ := privacyFixture(t)
	surface := model.Surface{Kind: "web", Origin: a.Document.Origin}
	if g.VerifyCredentialPrivacy(context.WithValue(ctx, "nativePrivacyApproved", true), p, CredentialPrivacyProof{}, surface, false) == nil {
		t.Fatal("zero proof admitted")
	}
	for _, mode := range []string{"valid", "missingRedactor", "extraSecret", "duplicate", "oldDoc", "nullFrame", "wrongPermit"} {
		t.Run(mode, func(t *testing.T) {
			pending := &credentialPrivacyPending{requestID: "request", attemptID: strings.Repeat("a", 64), permitID: strings.Repeat("b", 64), expected: a.Document.Identity, newDocument: true, done: make(chan Identity, 1)}
			next := a.Document.Identity
			next.DocumentID = "new-private-doc"
			frame := map[string]any{"type": "credentialPrivacyResult", "requestId": pending.requestID, "attemptId": pending.attemptID, "permitId": pending.permitID, "identity": next, "ready": true, "retiredAuthorityQuiesced": true, "redactionReady": true}
			switch mode {
			case "missingRedactor":
				frame["redactionReady"] = false
			case "extraSecret":
				frame["value"] = "PRIVATE-CANARY"
			case "oldDoc":
				frame["identity"] = a.Document.Identity
			case "wrongPermit":
				frame["permitId"] = strings.Repeat("c", 64)
			}
			raw, _ := json.Marshal(frame)
			if mode == "duplicate" {
				raw = append(raw[:len(raw)-1], []byte(`,"ready":true}`)...)
			}
			if mode == "nullFrame" {
				raw = bytes.Replace(raw, []byte(`"frameId":0`), []byte(`"frameId":null`), 1)
			}
			c := &channel{privacyPending: pending}
			if !g.broker.acceptCredentialPrivacyLocked(c, raw) {
				t.Fatal("private frame fell through")
			}
			id := <-pending.done
			if (id.DocumentID != "") != (mode == "valid") {
				t.Fatal("invalid proof admitted")
			}
			if !bytes.Equal(raw, make([]byte, len(raw))) {
				t.Fatal("private bytes retained")
			}
		})
	}
}
func TestCredentialPrivacyPublishedAccessIsRaceSafe(t *testing.T) {
	g, p, ctx, a, submit := privacyFixture(t)
	proof, err := g.QualifyCredentialPrivacy(ctx, p, a, submit, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	for i := 0; i < 8; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for j := 0; j < 50; j++ {
				proof.Authority()
			}
		}()
	}
	for i := 0; i < 3; i++ {
		if g.VerifyCredentialPrivacy(ctx, p, proof, model.Surface{Kind: "web", Origin: a.Document.Origin}, false) != nil {
			t.Fatal("fresh concurrent proof failed")
		}
	}
	wait.Wait()
	g.broker.mu.Lock()
	proof.state.active = false
	proof.state.changed = true
	g.broker.mu.Unlock()
	for i := 0; i < 2; i++ {
		if !errors.Is(g.VerifyCredentialPrivacy(ctx, p, proof, model.Surface{Kind: "web", Origin: a.Document.Origin}, false), ErrCredentialPrivacyDocumentChanged) {
			t.Fatal("authenticated navigation sentinel was not retained")
		}
	}
}

func TestCredentialPrivacyChangedReplyIsTypedAndDoesNotGrantAuthority(t *testing.T) {
	expected := Identity{ProfileChannel: "p", BrowserInstance: "b", TabID: 1, FrameID: 0, DocumentID: "old", Generation: 1}
	next := expected
	next.DocumentID = "new"
	for _, allow := range []bool{false, true} {
		p := &credentialPrivacyPending{requestID: "request", attemptID: strings.Repeat("a", 64), permitID: strings.Repeat("b", 64), expected: expected, allowNavigation: allow, done: make(chan Identity, 1)}
		raw, _ := json.Marshal(map[string]any{"type": "credentialPrivacyResult", "requestId": p.requestID, "attemptId": p.attemptID, "permitId": p.permitID, "identity": next, "ready": false, "retiredAuthorityQuiesced": true, "redactionReady": true, "documentChanged": true})
		c := &channel{privacyPending: p}
		b := &Broker{}
		if !b.acceptCredentialPrivacyLocked(c, raw) {
			t.Fatal("private navigation fell through")
		}
		id := <-p.done
		if allow {
			if p.failed || !p.changed || id != next {
				t.Fatal("authenticated navigation sentinel lost")
			}
		} else if !p.failed || id.DocumentID != "" {
			t.Fatal("navigation change accepted outside verify")
		}
	}
}

func TestPublishedPrivacyRejectsMissingOrChangedDocumentWithoutHandshake(t *testing.T) {
	for _, mode := range []string{"missing", "changed", "olderGeneration"} {
		t.Run(mode, func(t *testing.T) {
			g, p, ctx, source, submit := privacyFixture(t)
			proof, err := g.QualifyCredentialPrivacy(ctx, p, source, submit, func(context.Context) error { return nil })
			if err != nil {
				t.Fatal(err)
			}
			a, _ := proof.Authority()
			c := g.controlChannel(a)
			g.broker.mu.Lock()
			if mode == "missing" {
				c.documents = nil
			} else {
				for i := range c.documents {
					if c.documents[i].DocumentID == a.Document.DocumentID {
						if mode == "changed" {
							c.documents[i].DocumentID = "replaced-document"
						} else {
							c.documents[i].Generation = 0
						}
					}
				}
			}
			g.broker.mu.Unlock()
			c.writeMu.Lock()
			err = g.VerifyCredentialPrivacy(ctx, p, proof, model.Surface{Kind: "web", Origin: a.Document.Origin}, false)
			c.writeMu.Unlock()
			if err == nil {
				t.Fatal("stale ready state survived inventory change")
			}
			if mode == "changed" && !errors.Is(err, ErrCredentialPrivacyDocumentChanged) {
				t.Fatal("changed document lost typed sentinel", err)
			}
		})
	}
}

func TestCredentialPrivacyFailurePhasesAreClosedAndPreservePrivateSentinel(t *testing.T) {
	for _, phase := range []string{"admission", "fence", "reply", "commit", "probe", "promotion", "PRIVATE_CANARY"} {
		err := credentialPrivacyFailure(phase)
		if !errors.Is(err, errCredentialPrivacy) {
			t.Fatal("private sentinel lost")
		}
		code := CredentialPrivacyFailureCode(err)
		if strings.Contains(code, "PRIVATE") || strings.Contains(err.Error(), "PRIVATE") {
			t.Fatal("private phase text escaped")
		}
		if phase != "PRIVATE_CANARY" && code == "postSubmitPrivacyUnavailable" {
			t.Fatal("closed phase not classified", phase)
		}
		if phase == "PRIVATE_CANARY" && code != "postSubmitPrivacyUnavailable" {
			t.Fatal("unrecognized phase escaped")
		}
	}
	if code := CredentialPrivacyFailureCode(errors.New("PRIVATE_PROVIDER_CANARY")); code != "postSubmitPrivacyUnavailable" {
		t.Fatal("provider error became a phase")
	}
}
func TestCredentialPrivacyRejectedAdmissionReportsClosedPhaseBeforeHandshake(t *testing.T) {
	g, p, ctx, source, submit := privacyFixture(t)
	_, err := g.QualifyCredentialPrivacy(ctx, p, source, submit, func(context.Context) error { return errors.New("PRIVATE_CONSENT_CANARY") })
	if err == nil || CredentialPrivacyFailureCode(err) != "postSubmitPrivacyAdmissionUnavailable" || !errors.Is(err, errCredentialPrivacy) {
		t.Fatal("rejected live admission collapsed phase", CredentialPrivacyFailureCode(err))
	}
}

func TestPrivacyPromotionPublishesCommittedDOMWithoutSpeculativeControl(t *testing.T) {
	var inspections atomic.Int64
	g, p, ctx, inputs := controlFixtureVersion(t, 2, func() string { inspections.Add(1); return "privacyGenerationDrift" })
	binding := auth.ConsentBinding{SessionID: "promotion-session", GrantID: "promotion-grant", Purpose: "credential"}
	ctx = auth.WithConsentBinding(ctx, binding)
	source, err := g.AdmitControl(ctx, p, model.Surface{Kind: "web", Origin: "https://fixture.test"})
	if err != nil {
		t.Fatal(err)
	}
	submit := strings.Repeat("a", 64)
	g.broker.mu.Lock()
	c := g.broker.channels[channelKey(source.Document.ProfileChannel, source.Document.BrowserInstance)]
	c.privateFlow = &credentialFlow{authority: source, binding: binding, fillAttempt: strings.Repeat("b", 64), submitAttempt: submit, submitConfirmed: true}
	g.broker.mu.Unlock()
	proof, err := g.QualifyCredentialPrivacy(ctx, p, source, submit, func(context.Context) error { return nil })
	if err != nil {
		t.Fatalf("committed privacy publication failed: %s", CredentialPrivacyFailureCode(err))
	}
	if authority, ok := proof.Authority(); !ok || authority.Lease != (Lease{}) {
		t.Fatal("privacy publication must carry no dispatch lease")
	}
	g.controlMu.Lock()
	held := testFirstControl(g) != nil || testAnyControlRetiring(g)
	g.controlMu.Unlock()
	if held {
		t.Fatal("ordinary lease remained live after privacy-only publication")
	}
	// Publishing committed privacy performs no speculative ordinary control
	// and does not repeat the private inspector.
	if inputs.Load() != 0 {
		t.Fatal("privacy promotion dispatched application input")
	}
	if inspections.Load() > 1 {
		t.Fatal("private inspection repeated during privacy publication")
	}
}

func TestPublishedPrivacyRetainsAllAuthorityBarriers(t *testing.T) {
	for _, mode := range []string{"valid", "foreignConsent", "inactive", "missingInventory", "changedDocument", "unknownReceipt", "unpublishedCaller"} {
		t.Run(mode, func(t *testing.T) {
			g, p, ctx, source, submit := privacyFixture(t)
			proof, err := g.QualifyCredentialPrivacy(ctx, p, source, submit, func(context.Context) error { return nil })
			if err != nil {
				t.Fatal(err)
			}
			state := proof.state
			surface := model.Surface{Kind: "web", Origin: state.source.Document.Origin, TabID: state.authority.Document.QualifiedTabID()}
			g.broker.mu.Lock()
			state.published = mode != "unpublishedCaller"
			switch mode {
			case "inactive":
				state.active = false
			case "missingInventory":
				state.channel.documents = nil
			case "changedDocument":
				state.channel.documents[0].DocumentID = "replacement"
			case "unknownReceipt":
				state.channel.unknown["retained-unknown"] = true
			}
			g.broker.mu.Unlock()
			promoted := ctx
			if mode == "foreignConsent" {
				promoted = auth.WithConsentBinding(promoted, auth.ConsentBinding{SessionID: "foreign", GrantID: "private-grant", Purpose: "credential"})
			}
			if mode == "unpublishedCaller" {
				promoted = ctx
			}
			err = g.VerifyCredentialPrivacy(promoted, p, proof, surface, false)
			if (err == nil) != (mode == "valid") {
				t.Fatalf("promotion authority barrier mismatch: %s", mode)
			}
			if mode == "unpublishedCaller" {
				if _, published := proof.Authority(); published {
					t.Fatal("unpublished proof became public")
				}
			}
		})
	}
}

func TestCredentialPrivacyNegativeIsClosedCorrelatedAndGrantsNoAuthority(t *testing.T) {
	for _, mode := range []string{"notReady", "missingRedactor", "wrongRequest", "wrongPermit", "wrongDocument", "extra"} {
		t.Run(mode, func(t *testing.T) {
			g, _, _, a, _ := privacyFixture(t)
			p := &credentialPrivacyPending{requestID: "request", attemptID: strings.Repeat("a", 64), permitID: strings.Repeat("b", 64), expected: a.Document.Identity, allowSameDocument: false, newDocument: true, done: make(chan Identity, 1)}
			frame := map[string]any{"type": "credentialPrivacyResult", "requestId": p.requestID, "attemptId": p.attemptID, "permitId": p.permitID, "identity": a.Document.Identity, "ready": false, "retiredAuthorityQuiesced": true, "redactionReady": true}
			switch mode {
			case "missingRedactor":
				delete(frame, "redactionReady")
			case "wrongRequest":
				frame["requestId"] = "foreign"
			case "wrongPermit":
				frame["permitId"] = "foreign"
			case "wrongDocument":
				i := a.Document.Identity
				i.TabID++
				frame["identity"] = i
			case "extra":
				frame["value"] = "PRIVATE-CANARY"
			}
			c := &channel{privacyPending: p}
			raw, _ := json.Marshal(frame)
			if !g.broker.acceptCredentialPrivacyLocked(c, raw) {
				t.Fatal("private reply escaped")
			}
			if mode == "wrongRequest" {
				select {
				case <-p.done:
					t.Fatal("late foreign reply poisoned current qualification")
				default:
				}
				if p.failed || p.replied {
					t.Fatal("late foreign reply changed live state")
				}
				return
			}
			id := <-p.done
			if mode == "notReady" {
				if p.failed || !p.notReady || id != a.Document.Identity {
					t.Fatal("safe refusal rejected")
				}
			} else if !p.failed || id.DocumentID != "" {
				t.Fatal("malformed refusal accepted")
			}
		})
	}
}
