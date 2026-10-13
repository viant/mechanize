package chrome

import (
	"context"
	"encoding/json"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
	"strings"
	"testing"
)

// Legacy single-target fixtures inspect the one authority under controlMu.
func testFirstControl(g *Gateway) *ControlAuthority {
	for _, record := range g.controls {
		return record.authority
	}
	return nil
}
func testAnyControlRetiring(g *Gateway) bool {
	for _, record := range g.controls {
		if record.retiring {
			return true
		}
	}
	return false
}
func testMarkControlRetiring(g *Gateway) {
	if len(g.controls) == 0 {
		for _, c := range g.broker.channels {
			if len(c.documents) != 0 {
				g.setControlLocked(ControlAuthority{Owner: c.grant.Principal.Namespace, ClientID: c.grant.Principal.ClientID, Document: c.documents[0]})
				break
			}
		}
	}
	for _, record := range g.controls {
		record.retiring = true
	}
}

func TestControlUnknownTargetDoesNotBlockAnotherTargetAndLateDeathPreservesBoth(t *testing.T) {
	g, p, ctx, count := controlFixtureVersion(t, 2)
	step := controlStep(t)
	a, err := g.AdmitControl(ctx, p, step.Target.Surface)
	if err != nil {
		t.Fatal(err)
	}
	c := g.controlChannel(a)
	bdoc := a.Document
	bdoc.TabID = 8
	bdoc.DocumentID = "doc2"
	bdoc.TabHandle = bdoc.QualifiedTabID()
	id := strings.Repeat("d", 64)
	original := Command{Action: "element.press", Identity: a.Document.Identity, AttemptID: id, BrokerEpoch: a.BrokerEpoch, ChannelEpoch: a.ChannelEpoch, ScopeHash: a.ScopeHash, ControlLease: &a.Lease, FingerprintVersion: 2, FingerprintSHA256: strings.Repeat("e", 64)}
	receipt := Reply{Identity: original.Identity, AttemptID: id, ControlLease: &a.Lease, FingerprintVersion: 2, FingerprintSHA256: original.FingerprintSHA256, DispatchState: "unknown", EffectState: "unknown"}
	g.controlMu.Lock()
	g.controlRecordLocked(a).retiring = true
	g.controlMu.Unlock()
	g.broker.mu.Lock()
	c.documents = append(c.documents, bdoc)
	c.attempts[id] = original
	c.receipts[id] = receipt
	c.unknown[id] = true
	g.broker.mu.Unlock()
	same := step.Target.Surface
	same.TabID = a.Document.QualifiedTabID()
	if _, err := g.AdmitControl(ctx, p, same); err == nil {
		t.Fatal("hazardous target admitted")
	}
	other := step.Target.Surface
	other.TabID = bdoc.QualifiedTabID()
	b, err := g.AdmitControl(ctx, p, other)
	if err != nil {
		t.Fatal("disjoint target blocked by A", err)
	}
	step.Target.Surface = other
	result, err := g.ExecuteControlBound(ctx, p, step, nil, b, strings.Repeat("f", 64), func(context.Context, auth.Principal, BoundMutation) (BindingCommit, error) {
		return BindingCommit{BindingID: strings.Repeat("b", 64), CommitConfirmed: true, ReadbackMatched: true}, nil
	})
	if err != nil || result.DispatchState != "dispatched" || count.Load() != 1 {
		t.Fatal("authorized B input blocked/replayed", result, err)
	}
	foreign := p
	foreign.ClientID = "other-client"
	if _, err := g.AdmitControl(auth.WithPrincipal(ctx, foreign), foreign, other); err == nil {
		t.Fatal("another client acquired same physical target")
	}
	if retired, err := g.RetireControl(ctx, p, a); err == nil || retired {
		t.Fatal("original UNKNOWN inferred cleanup")
	}
	g.broker.mu.Lock()
	c.retiredTargets = map[string]Command{id: original}
	delete(c.unknown, id)
	g.broker.mu.Unlock()
	if retired, err := g.RetireControl(ctx, p, a); err != nil || !retired {
		t.Fatal("exact A death rejected", err)
	}
	if err := g.VerifyControl(ctx, p, b); err != nil {
		t.Fatal("late A retirement revoked B", err)
	}
	g.broker.mu.Lock()
	after, _ := json.Marshal(c.receipts[id])
	g.broker.mu.Unlock()
	before, _ := json.Marshal(receipt)
	if string(before) != string(after) || count.Load() != 1 {
		t.Fatal("original UNKNOWN changed or input replayed")
	}
	if retired, err := g.RetireControl(ctx, p, b); err != nil || !retired {
		t.Fatal("B cleanup failed", err)
	}
	g.controlMu.Lock()
	remaining := len(g.controls)
	g.controlMu.Unlock()
	if remaining != 0 {
		t.Fatal("target controls retained after exact retirement")
	}
}

func TestLifecycleStopRetiresEveryOwnedTarget(t *testing.T) {
	f := newLifecycleFixture(t, 0)
	second := f.channel.documents[0]
	second.TabID = 8
	second.DocumentID = "doc2"
	second.TabHandle = second.QualifiedTabID()
	f.gateway.broker.mu.Lock()
	f.channel.documents = append(f.channel.documents, second)
	f.gateway.broker.mu.Unlock()
	for _, d := range []Document{f.channel.documents[0], second} {
		a, _, err := f.gateway.controlSnapshot(f.ctx, f.principal, model.Surface{Kind: "web", Origin: d.Origin, TabID: d.QualifiedTabID()})
		if err != nil {
			t.Fatal(err)
		}
		a.Lease = Lease{ID: d.DocumentID + "-lease", Generation: 1}
		f.gateway.controlMu.Lock()
		f.gateway.setControlLocked(a)
		f.gateway.controlMu.Unlock()
	}
	guard, err := f.gateway.BeginLifecycleReceiptExport(f.ctx, f.principal, "p1", "b1")
	if err != nil {
		t.Fatal(err)
	}
	defer guard.Close()
	if err := guard.RetireControl(f.ctx, f.principal); err != nil {
		t.Fatal(err)
	}
	f.gateway.controlMu.Lock()
	remaining := len(f.gateway.controls)
	f.gateway.controlMu.Unlock()
	if remaining != 0 || f.commands.Load() != 2 || f.inputs.Load() != 0 {
		t.Fatal("whole-channel stop missed a target or emitted input")
	}
}

func TestGatewayCloseInhibitsEveryOwnedTarget(t *testing.T) {
	g, p, ctx, _ := controlFixtureVersion(t, 2)
	first, err := g.AdmitControl(ctx, p, model.Surface{Kind: "web", Origin: "https://fixture.test"})
	if err != nil {
		t.Fatal(err)
	}
	c := g.controlChannel(first)
	d := first.Document
	d.TabID = 8
	d.DocumentID = "doc2"
	d.TabHandle = d.QualifiedTabID()
	g.broker.mu.Lock()
	c.documents = append(c.documents, d)
	g.broker.mu.Unlock()
	second, err := g.AdmitControl(ctx, p, model.Surface{Kind: "web", Origin: d.Origin, TabID: d.QualifiedTabID()})
	if err != nil {
		t.Fatal(err)
	}
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	for _, a := range []ControlAuthority{first, second} {
		if err := g.VerifyControl(ctx, p, a); err == nil {
			t.Fatal("closed gateway retained executable target authority")
		}
	}
}

func TestControlLostInputACKRetainsAWhileBDispatchesThroughBroker(t *testing.T) {
	g, p, ctx, count := controlFixtureVersion(t, 2, func() string { return "dropTargetAReceipt" })
	step := controlStep(t)
	a, err := g.AdmitControl(ctx, p, step.Target.Surface)
	if err != nil {
		t.Fatal(err)
	}
	c := g.controlChannel(a)
	d := a.Document
	d.TabID = 8
	d.DocumentID = "doc2"
	d.TabHandle = d.QualifiedTabID()
	g.broker.mu.Lock()
	c.documents = append(c.documents, d)
	g.broker.mu.Unlock()
	commit := func(context.Context, auth.Principal, BoundMutation) (BindingCommit, error) {
		return BindingCommit{BindingID: strings.Repeat("b", 64), CommitConfirmed: true, ReadbackMatched: true}, nil
	}
	originalID := strings.Repeat("a", 64)
	step.TimeoutMs = 100
	original, err := g.ExecuteControlBound(ctx, p, step, nil, a, originalID, commit)
	if err == nil || original.DispatchState != "unknown" || count.Load() != 1 {
		t.Fatal("fixture did not lose actual A input ACK", original, err)
	}
	g.broker.mu.Lock()
	before, _ := json.Marshal(c.attempts[originalID])
	retained := c.unknown[originalID] && len(c.pending) == 1 && c.executorQualified && c.inventoryComplete
	_, invented := c.receipts[originalID]
	g.broker.mu.Unlock()
	if !retained || invented {
		t.Fatal("ordinary lost ACK unexpectedly changed shared qualification or invented receipt")
	}
	if retired, err := g.RetireControl(ctx, p, a); err == nil || retired {
		t.Fatal("lost ACK falsely established cleanup")
	}
	other := step.Target.Surface
	other.TabID = d.QualifiedTabID()
	b, err := g.AdmitControl(ctx, p, other)
	if err != nil {
		t.Fatal("actual lost A ACK prevented B admission", err)
	}
	step.Target.Surface = other
	step.TimeoutMs = 5000
	result, err := g.ExecuteControlBound(ctx, p, step, nil, b, strings.Repeat("c", 64), commit)
	if err != nil || result.DispatchState != "dispatched" || count.Load() != 2 {
		t.Fatal("B dispatch blocked or A input replayed", result, err)
	}
	same := step.Target.Surface
	same.TabID = a.Document.QualifiedTabID()
	if _, err := g.AdmitControl(ctx, p, same); err == nil {
		t.Fatal("A pending input was re-admitted")
	}
	g.broker.mu.Lock()
	after, _ := json.Marshal(c.attempts[originalID])
	hazard := c.unknown[originalID]
	_, invented = c.receipts[originalID]
	g.broker.mu.Unlock()
	if string(before) != string(after) || !hazard || invented || original.DispatchState != "unknown" {
		t.Fatal("B changed original lost-input audit")
	}
	if retired, err := g.RetireControl(ctx, p, b); err != nil || !retired {
		t.Fatal("A pending input prevented exact B retirement", err)
	}
}

func TestUnknownTargetHealthKeepsUnboundHazardsConservative(t *testing.T) {
	target := Identity{ProfileChannel: "p", BrowserInstance: "b", TabID: 8, DocumentID: "B", Generation: 2}
	original := Command{AttemptID: "original", Identity: Identity{ProfileChannel: "p", BrowserInstance: "b", TabID: 7, DocumentID: "A", Generation: 1}, ControlLease: &Lease{ID: "lease", Generation: 1}}
	for _, mode := range []string{"boundA", "sameTarget", "successorDocument", "missingCommand", "missingLease", "wrongAttempt", "incompleteIdentity"} {
		t.Run(mode, func(t *testing.T) {
			command := original
			if mode == "sameTarget" || mode == "successorDocument" {
				command.Identity = target
				command.Identity.Generation = 1
				if mode == "successorDocument" {
					command.Identity.DocumentID = "predecessor"
				}
			}
			if mode == "missingLease" {
				command.ControlLease = nil
			}
			if mode == "wrongAttempt" {
				command.AttemptID = "other"
			}
			if mode == "incompleteIdentity" {
				command.Identity.DocumentID = ""
			}
			c := &channel{attempts: map[string]Command{"original": command}, unknown: map[string]bool{"original": true}}
			if mode == "missingCommand" {
				delete(c.attempts, "original")
			}
			before, _ := json.Marshal(c.attempts)
			if domUnknownForTargetLocked(c, target) != (mode != "boundA") {
				t.Fatal("target classification ignored same-target/unbound uncertainty")
			}
			after, _ := json.Marshal(c.attempts)
			if string(before) != string(after) || !c.unknown["original"] {
				t.Fatal("classification rewrote retained uncertainty")
			}
		})
	}
}

func TestPlaywrightTypedTargetBPrivacyGuardSkipsBoundAUnknown(t *testing.T) {
	actor := principal(t, "owner")
	actor.ClientID = "client"
	binding := auth.ConsentBinding{SessionID: "session", GrantID: "grant", Purpose: "fixture"}
	command := Command{RequestID: "request", AttemptID: "B", Identity: Identity{ProfileChannel: "p", BrowserInstance: "b", TabID: 8, DocumentID: "B", Generation: 1}, ControlLease: &Lease{ID: "B-lease", Generation: 1}, ChannelEpoch: "channel", ScopeHash: "scope"}
	e := &playwrightExecution{command: command, actor: actor, consent: binding}
	other := command
	other.RequestID = "A-request"
	other.AttemptID = "A"
	other.Identity.TabID = 7
	other.Identity.DocumentID = "A"
	other.ControlLease = &Lease{ID: "A-lease", Generation: 1}
	c := &channel{epoch: "channel", scopeHash: "scope", playwright: e, pending: map[string]*pending{"request": {playwright: true, command: command}}, attempts: map[string]Command{"A": other}, unknown: map[string]bool{"A": true}}
	ctx := context.WithValue(auth.WithConsentBinding(auth.WithPrincipal(context.Background(), actor), binding), playwrightPrivacyKey{}, e)
	if !privacyOperationIdleLocked(ctx, c) {
		t.Fatal("typed B guard blocked by bound A history")
	}
	if privacyOperationIdleLocked(context.Background(), c) {
		t.Fatal("untyped context borrowed target proof")
	}
	c.unknown["unbound"] = true
	if privacyOperationIdleLocked(ctx, c) {
		t.Fatal("unbound hazard bypassed")
	}
}

func TestControlBAdmissionWhileExplicitReadAPending(t *testing.T) {
	g, p, ctx, count := controlFixtureVersion(t, 2, func() string { return "dropTargetARead" })
	a, err := g.AdmitControl(ctx, p, model.Surface{Kind: "web", Origin: "https://fixture.test"})
	if err != nil {
		t.Fatal(err)
	}
	c := g.controlChannel(a)
	d := a.Document
	d.TabID = 8
	d.DocumentID = "B"
	d.TabHandle = d.QualifiedTabID()
	g.broker.mu.Lock()
	c.documents = append(c.documents, d)
	g.broker.mu.Unlock()
	readCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := g.broker.call(readCtx, c, Command{Action: "observe", Identity: a.Document.Identity}, false)
		done <- err
	}()
	waitControl(t, func() bool { g.broker.mu.Lock(); defer g.broker.mu.Unlock(); return len(c.pending) == 1 })
	b, err := g.AdmitControl(ctx, p, model.Surface{Kind: "web", Origin: d.Origin, TabID: d.QualifiedTabID()})
	if err != nil {
		t.Fatal("slow explicit A read blocked B admission", err)
	}
	if err := g.VerifyControl(ctx, p, b); err != nil {
		t.Fatal(err)
	}
	step := controlStep(t)
	step.Target.Surface = model.Surface{Kind: "web", Origin: d.Origin, TabID: d.QualifiedTabID()}
	result, err := g.ExecuteControlBound(ctx, p, step, nil, b, strings.Repeat("b", 64), func(context.Context, auth.Principal, BoundMutation) (BindingCommit, error) {
		return BindingCommit{BindingID: strings.Repeat("c", 64), CommitConfirmed: true, ReadbackMatched: true}, nil
	})
	if err != nil || result.DispatchState != "dispatched" || count.Load() != 1 {
		t.Fatal("slow A read blocked B semantic mutation", result, err)
	}
	cancel()
	<-done
}

func TestControlSameTabSuccessorRemainsBlockedByOriginalInputOrLease(t *testing.T) {
	g, p, ctx, _ := controlFixtureVersion(t, 2)
	a, err := g.AdmitControl(ctx, p, model.Surface{Kind: "web", Origin: "https://fixture.test"})
	if err != nil {
		t.Fatal(err)
	}
	c := g.controlChannel(a)
	successor := a.Document
	successor.DocumentID = "successor"
	successor.Generation++
	id := strings.Repeat("a", 64)
	original := Command{AttemptID: id, Identity: a.Document.Identity, ControlLease: &a.Lease}
	g.broker.mu.Lock()
	c.documents = []Document{successor}
	c.attempts[id] = original
	c.unknown[id] = true
	g.broker.mu.Unlock()
	target := model.Surface{Kind: "web", Origin: successor.Origin, TabID: successor.QualifiedTabID()}
	if _, err := g.AdmitControl(ctx, p, target); err == nil {
		t.Fatal("successor bypassed old physical input hazard")
	}
	// Even receipt resolution cannot steal the still-owned old lease; exact
	// retirement remains required before the same tab gets another authority.
	g.broker.mu.Lock()
	delete(c.unknown, id)
	g.broker.mu.Unlock()
	g.controlMu.Lock()
	g.controlRecordLocked(a).retiring = true
	g.controlMu.Unlock()
	if _, err := g.AdmitControl(ctx, p, target); err == nil {
		t.Fatal("successor bypassed old retiring target lease")
	}
}
