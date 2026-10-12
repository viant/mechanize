package chrome

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
	"strings"
	"sync/atomic"
	"testing"
)

func TestCredentialSubmitOneShotQuarantinedAdvanceAndCancel(t *testing.T) {
	g, p, ctx, count := controlFixtureVersion(t, 2)
	binding := auth.ConsentBinding{SessionID: "session", GrantID: "grant", Purpose: "private"}
	ctx = auth.WithConsentBinding(ctx, binding)
	a, err := g.AdmitControl(ctx, p, model.Surface{Kind: "web", Origin: "https://fixture.test"})
	if err != nil {
		t.Fatal(err)
	}
	c := g.controlChannel(a)
	fill, submit := strings.Repeat("a", 64), strings.Repeat("b", 64)
	g.broker.mu.Lock()
	c.privateFlow = &credentialFlow{authority: a, fillAttempt: fill, binding: binding}
	c.privateCredentialAttempts = map[string]bool{fill: true}
	g.broker.mu.Unlock()
	allow := func(context.Context) error { return nil }
	if _, err = g.broker.call(ctx, c, Command{Action: "observe", Identity: a.Document.Identity}, false); err == nil {
		t.Fatal("quarantine admitted public command")
	}
	result, err := g.SubmitVaultCredential(ctx, p, a, fill, submit, allow)
	if err != nil || result.DispatchState != "dispatched" || count.Load() != 1 {
		t.Fatal("private submit failed", err, result)
	}
	if _, err = g.SubmitVaultCredential(ctx, p, a, fill, strings.Repeat("c", 64), allow); err == nil || count.Load() != 1 {
		t.Fatal("submit replay admitted")
	}
	next, err := g.AdvanceVaultCredential(ctx, p, a, submit, allow)
	if err != nil || next.Stage != "password" || next.Authority.Document.DocumentID == a.Document.DocumentID || next.Authority.Lease == a.Lease {
		t.Fatal("private navigation proof failed", err, next.Stage)
	}
	if g.VerifyControl(ctx, p, a) == nil {
		t.Fatal("old authority survived private navigation")
	}
	if g.CancelVaultCredential(ctx, p, next.Authority) != nil {
		t.Fatal("private cancellation failed")
	}
}
func TestCredentialAdvanceRejectsPublicFramesAndMalformedNavigation(t *testing.T) {
	old := Identity{ProfileChannel: "p", BrowserInstance: "b", TabID: 1, FrameID: 0, DocumentID: "old", Generation: 1}
	for _, mode := range []string{"valid", "sameDocument", "extraValue", "nullFrame", "duplicate", "foreignTab"} {
		t.Run(mode, func(t *testing.T) {
			pending := &credentialAdvancePending{requestID: "request", attemptID: strings.Repeat("a", 64), previous: old, done: make(chan credentialAdvanceReply, 1)}
			next := old
			next.DocumentID = "new"
			if mode == "sameDocument" {
				next = old
			}
			if mode == "foreignTab" {
				next.TabID++
			}
			frame := map[string]any{"type": "credentialAdvanceResult", "requestId": pending.requestID, "attemptId": pending.attemptID, "identity": next, "ready": true, "stage": "password"}
			if mode == "extraValue" {
				frame["value"] = "PRIVATE-CANARY"
			}
			raw, _ := json.Marshal(frame)
			if mode == "nullFrame" {
				raw = bytes.Replace(raw, []byte(`"frameId":0`), []byte(`"frameId":null`), 1)
			}
			if mode == "duplicate" {
				raw = append(raw[:len(raw)-1], []byte(`,"ready":true}`)...)
			}
			b := &Broker{}
			c := &channel{privateAdvance: pending}
			if !b.acceptCredentialAdvanceLocked(c, raw) {
				t.Fatal("private frame fell through")
			}
			reply := <-pending.done
			if reply.ready != (mode == "valid") {
				t.Fatal("malformed private navigation accepted", mode)
			}
			if !bytes.Equal(raw, make([]byte, len(raw))) {
				t.Fatal("private frame retained")
			}
		})
	}
}

func TestSameDocumentAdvanceAcceptsOnlyClosedReadOnlyStatus(t *testing.T) {
	old := Identity{ProfileChannel: "p", BrowserInstance: "b", TabID: 1, FrameID: 0, DocumentID: "old", Generation: 3}
	for _, stage := range []string{"pending", "rejected", "challenge", "unavailable"} {
		for _, mode := range []string{"valid", "ready", "foreign", "older", "extra"} {
			p := &credentialAdvancePending{requestID: "request", attemptID: strings.Repeat("a", 64), previous: old, done: make(chan credentialAdvanceReply, 1)}
			id := old
			id.Generation++
			frame := map[string]any{"type": "credentialAdvanceResult", "requestId": p.requestID, "attemptId": p.attemptID, "identity": id, "ready": false, "stage": stage}
			switch mode {
			case "ready":
				frame["ready"] = true
			case "foreign":
				id.TabID++
				frame["identity"] = id
			case "older":
				id.Generation = 1
				frame["identity"] = id
			case "extra":
				frame["text"] = "PRIVATE-CANARY"
			}
			raw, _ := json.Marshal(frame)
			c := &channel{privateAdvance: p, privateFlow: &credentialFlow{}}
			(&Broker{}).acceptCredentialAdvanceLocked(c, raw)
			r := <-p.done
			if mode == "valid" {
				if r.identity != id || r.stage != stage || r.ready || c.privateFlow.poisoned {
					t.Fatal("read-only status refused", stage)
				}
			} else if r.identity.DocumentID != "" || !c.privateFlow.poisoned {
				t.Fatal("invalid status admitted", stage, mode)
			}
		}
	}
}

func TestCredentialChallengeRetainsOnlyKnownPrivateLineageForHumanContinuation(t *testing.T) {
	var stage atomic.Value
	stage.Store("challenge")
	g, p, ctx, _ := controlFixtureVersion(t, 2, func() string { return stage.Load().(string) })
	binding := auth.ConsentBinding{SessionID: "session", GrantID: "grant", Purpose: "private"}
	ctx = auth.WithConsentBinding(ctx, binding)
	a, err := g.AdmitControl(ctx, p, model.Surface{Kind: "web", Origin: "https://fixture.test"})
	if err != nil {
		t.Fatal(err)
	}
	c := g.controlChannel(a)
	attempt := strings.Repeat("a", 64)
	g.broker.mu.Lock()
	c.privateFlow = &credentialFlow{authority: a, binding: binding, submitAttempt: attempt, submitConfirmed: true}
	g.broker.mu.Unlock()
	result, err := g.AdvanceVaultCredential(ctx, p, a, attempt, func(context.Context) error { return nil })
	if !errors.Is(err, ErrCredentialNativeChallenge) || result.Stage != "challenge" || result.Authority.Lease.ID != "" {
		t.Fatal("challenge minted authority or lost typed handoff", err)
	}
	g.broker.mu.Lock()
	retained := c.conn != nil && c.privateFlow != nil && c.privateAdvance == nil
	g.broker.mu.Unlock()
	if !retained {
		t.Fatal("known private challenge lineage was closed")
	}
	stage.Store("password")
	result, err = g.AdvanceVaultCredential(ctx, p, a, attempt, func(context.Context) error { return nil })
	if err != nil || result.Stage != "password" || result.Authority.Document.DocumentID == a.Document.DocumentID {
		t.Fatal("explicit post-human reprobe failed", err)
	}
}

func TestCredentialAdvanceDiagnosticPreProbeBoundaries(t *testing.T) {
	for _, mode := range []string{"admission", "generation", "flow", "pending"} {
		t.Run(mode, func(t *testing.T) {
			var probes atomic.Int64
			g, p, ctx, _ := controlFixtureVersion(t, 2, func() string { probes.Add(1); return "pending" })
			binding := auth.ConsentBinding{SessionID: "session", GrantID: "grant", Purpose: "private"}
			ctx = auth.WithConsentBinding(ctx, binding)
			a, e := g.AdmitControl(ctx, p, model.Surface{Kind: "web", Origin: "https://fixture.test"})
			if e != nil {
				t.Fatal(e)
			}
			c := g.controlChannel(a)
			attempt := strings.Repeat("a", 64)
			g.broker.mu.Lock()
			c.privateFlow = &credentialFlow{authority: a, binding: binding, submitAttempt: attempt, submitConfirmed: true}
			if mode == "generation" {
				c.documents[0].Generation++
			}
			if mode == "flow" {
				c.privateFlow.submitConfirmed = false
			}
			g.broker.mu.Unlock()
			_, e = g.AdvanceVaultCredential(ctx, p, a, attempt, func(context.Context) error {
				if mode == "admission" {
					return errors.New("PRIVATE-CANARY")
				}
				return nil
			})
			want := map[string]string{"admission": "postSubmitAdmissionUnavailable", "generation": "postSubmitControlAuthorityUnavailable", "flow": "postSubmitFlowUnavailable"}[mode]
			if mode == "pending" {
				if !errors.Is(e, ErrCredentialPostSubmitPending) || probes.Load() != 1 {
					t.Fatal("known pending changed", e)
				}
				return
			}
			if CredentialAdvanceAttention(e) != want || probes.Load() != 0 || strings.Contains(e.Error(), "CANARY") {
				t.Fatal("private phase missing or probe reached", mode, e)
			}
			g.broker.mu.Lock()
			retained := c.conn != nil && c.privateFlow != nil && c.privateAdvance == nil && len(c.unknown) == 0
			g.broker.mu.Unlock()
			if !retained {
				t.Fatal("diagnostic changed authority")
			}
		})
	}
	if CredentialAdvanceAttention(errors.New("postSubmitControlAuthorityUnavailable CANARY")) != "postSubmitAdvanceUnavailable" {
		t.Fatal("raw text adopted")
	}
}
