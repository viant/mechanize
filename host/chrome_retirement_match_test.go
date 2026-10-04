package host

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data"
	bindings "github.com/viant/mechanize/data/chromeattemptbindinglist"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/objective"
)

func retirementMatchFixture(t *testing.T, absent bool) (auth.Principal, ChromeRetirementFence, []data.ChromeRetirementManifest, []*bindings.Binding) {
	t.Helper()
	p, _ := auth.NewPrincipal("issuer", "tenant", "subject", []string{"desktop:control"})
	p.ClientID = "client"
	s := func(v string) *string { return &v }
	n := func(v int) *int { return &v }
	hash := strings.Repeat("a", 64)
	f := ChromeRetirementFence{"profile", "browser", "broker", "channel", hash}
	id := data.ChromeRetirementDigest([]string{"attempt", "run", "plan", "step"})
	browser := data.ChromeAttemptBrowserIDV2(p.Namespace, p.ClientID, id)
	effect := data.ChromeRetirementDigest([]string{"effect", id})
	result := integration.StepResult{DispatchState: "dispatched", VerificationState: "verified"}
	state, renderer := "confirmed", "unverified"
	if absent {
		result.DispatchState = "notDispatched"
		result.VerificationState = "unknown"
		state = "absent"
		renderer = "none"
	}
	raw, _ := json.Marshal(result)
	b := &bindings.Binding{Namespace: s(p.Namespace), Id: s(data.ChromeAttemptBindingID(p.Namespace, p.ClientID, id)), ClientId: s(p.ClientID), RunId: s("run"), PlanId: s("plan"), StepId: s("step"), StepIndex: n(0), DurableAttemptId: s(id), EffectId: s(effect), BrowserAttemptId: s(browser), ProfileChannel: s(f.ProfileChannel), BrowserInstance: s(f.BrowserInstance), BrokerEpoch: s(f.BrokerEpoch), ChannelEpoch: s(f.ChannelEpoch), ScopeHash: s(hash), TabId: n(7), FrameId: n(0), DocumentId: s("doc"), DocumentGeneration: n(1), RendererLeaseId: s("lease"), RendererLeaseGeneration: n(1), FingerprintVersion: n(2), FingerprintDigest: s(hash), PlanContentDigest: s(hash), StepDigest: s(hash), BusinessKeyDigest: s(data.ChromeAttemptRawDigest("business")), CommittedRunRevision: n(2), EndlySessionId: s("session"), EndlyOperationId: s("operation")}
	b.Attempt = &bindings.Attempt{Namespace: b.Namespace, Id: b.DurableAttemptId, RunId: b.RunId, PlanId: b.PlanId, StepId: b.StepId, State: s("intent"), LeaseEpoch: n(1)}
	b.Effect = &bindings.Effect{Namespace: b.Namespace, Id: b.EffectId, RunId: b.RunId, AttemptId: b.DurableAttemptId, BusinessKey: s("business"), Revision: n(2), State: s(state), EvidenceJson: s(string(raw))}
	b.Outcomes = []*bindings.Outcome{{Namespace: b.Namespace, Id: s(data.ChromeRetirementDigest([]string{"outcome-event", id})), RunId: b.RunId, AttemptId: b.DurableAttemptId, Sequence: n(3), Kind: s("outcome"), PayloadJson: s(string(raw))}}
	m := data.ChromeRetirementManifest{Version: 2, Identity: data.ChromeRetirementDocumentIdentity{ProfileChannel: f.ProfileChannel, BrowserInstance: f.BrowserInstance, TabID: 7, DocumentID: "doc"}, ReceiptRevision: 1, Readiness: data.ChromeRetirementReadiness{Quiesced: true, RecordingState: "none"}, Receipts: []data.ChromeRetirementReceipt{{AttemptID: browser, FingerprintSHA256: hash, FingerprintVersion: 2, DispatchState: result.DispatchState, EffectState: renderer}}}
	return p, f, []data.ChromeRetirementManifest{m}, []*bindings.Binding{b}
}

func TestMatchChromeRetirementBindings(t *testing.T) {
	for _, absent := range []bool{false, true} {
		p, f, m, b := retirementMatchFixture(t, absent)
		digest, err := MatchChromeRetirementBindings(p, f, m, b)
		if err != nil || len(digest) != 64 {
			t.Fatalf("absent=%v: %s %v", absent, digest, err)
		}
		again, _ := MatchChromeRetirementBindings(p, f, m, b)
		if again != digest {
			t.Fatal("unstable digest")
		}
	}
	p, f, m, b := retirementMatchFixture(t, true)
	m[0].Receipts = nil
	m[0].ReceiptRevision = 0
	if _, err := MatchChromeRetirementBindings(p, f, m, b); err != nil {
		t.Fatal(err)
	}
}

func TestMatchChromeRetirementRejectsIncomplete(t *testing.T) {
	cases := map[string]func(*auth.Principal, *ChromeRetirementFence, *[]data.ChromeRetirementManifest, *[]*bindings.Binding){
		"foreign binding": func(_ *auth.Principal, _ *ChromeRetirementFence, _ *[]data.ChromeRetirementManifest, b *[]*bindings.Binding) {
			v := "other"
			(*b)[0].ClientId = &v
		},
		"fence mismatch": func(_ *auth.Principal, f *ChromeRetirementFence, _ *[]data.ChromeRetirementManifest, _ *[]*bindings.Binding) {
			f.ChannelEpoch = "successor"
		},
		"missing outcome": func(_ *auth.Principal, _ *ChromeRetirementFence, _ *[]data.ChromeRetirementManifest, b *[]*bindings.Binding) {
			(*b)[0].Outcomes = nil
		},
		"absent dispatched": func(_ *auth.Principal, _ *ChromeRetirementFence, _ *[]data.ChromeRetirementManifest, b *[]*bindings.Binding) {
			v := "absent"
			(*b)[0].Effect.State = &v
		},

		"missing binding": func(_ *auth.Principal, _ *ChromeRetirementFence, _ *[]data.ChromeRetirementManifest, b *[]*bindings.Binding) {
			*b = nil
		},
		"missing dispatched receipt": func(_ *auth.Principal, _ *ChromeRetirementFence, m *[]data.ChromeRetirementManifest, _ *[]*bindings.Binding) {
			(*m)[0].Receipts = nil
			(*m)[0].ReceiptRevision = 0
		},
		"duplicate binding": func(_ *auth.Principal, _ *ChromeRetirementFence, _ *[]data.ChromeRetirementManifest, b *[]*bindings.Binding) {
			*b = append(*b, (*b)[0])
		},
		"overflow": func(_ *auth.Principal, _ *ChromeRetirementFence, _ *[]data.ChromeRetirementManifest, b *[]*bindings.Binding) {
			row := (*b)[0]
			*b = make([]*bindings.Binding, 65)
			for i := range *b {
				(*b)[i] = row
			}
		},
		"foreign graph": func(_ *auth.Principal, _ *ChromeRetirementFence, _ *[]data.ChromeRetirementManifest, b *[]*bindings.Binding) {
			v := "foreign"
			(*b)[0].Attempt.Namespace = &v
		},
		"unknown effect": func(_ *auth.Principal, _ *ChromeRetirementFence, _ *[]data.ChromeRetirementManifest, b *[]*bindings.Binding) {
			v := "unknown"
			(*b)[0].Effect.State = &v
		},
		"legacy": func(_ *auth.Principal, _ *ChromeRetirementFence, m *[]data.ChromeRetirementManifest, _ *[]*bindings.Binding) {
			(*m)[0].Version = 1
			(*m)[0].Receipts[0].FingerprintVersion = 0
		},
		"mismatch": func(_ *auth.Principal, _ *ChromeRetirementFence, m *[]data.ChromeRetirementManifest, _ *[]*bindings.Binding) {
			(*m)[0].Receipts[0].FingerprintSHA256 = strings.Repeat("b", 64)
		},
		"duplicate outcome": func(_ *auth.Principal, _ *ChromeRetirementFence, _ *[]data.ChromeRetirementManifest, b *[]*bindings.Binding) {
			(*b)[0].Outcomes = append((*b)[0].Outcomes, (*b)[0].Outcomes[0])
		},
		"document": func(_ *auth.Principal, _ *ChromeRetirementFence, m *[]data.ChromeRetirementManifest, _ *[]*bindings.Binding) {
			(*m)[0].Identity.DocumentID = "other"
		},
		"unknown receipt": func(_ *auth.Principal, _ *ChromeRetirementFence, m *[]data.ChromeRetirementManifest, _ *[]*bindings.Binding) {
			(*m)[0].Receipts[0].DispatchState = "unknown"
		},
	}
	for name, modify := range cases {
		t.Run(name, func(t *testing.T) {
			p, f, m, b := retirementMatchFixture(t, false)
			modify(&p, &f, &m, &b)
			if digest, err := MatchChromeRetirementBindings(p, f, m, b); err == nil || digest != "" {
				t.Fatal("accepted incomplete graph")
			}
		})
	}
}

func TestMatchChromeRetirementReconciled(t *testing.T) {
	t.Run("dispatched", func(t *testing.T) { retirementMatchReconciled(t, "dispatched") })
	t.Run("lost_ack", func(t *testing.T) { retirementMatchReconciled(t, "unknown") })
}

func retirementMatchReconciled(t *testing.T, dispatch string) {
	p, f, m, rows := retirementMatchFixture(t, false)
	b := rows[0]
	original := integration.StepResult{DispatchState: dispatch, VerificationState: "unknown"}
	raw, _ := json.Marshal(original)
	*b.Outcomes[0].PayloadJson = string(raw)
	proof := objective.Result{Truth: objective.True, Authority: objective.Observational, ObservedAt: time.Now(), Evidence: []objective.Evidence{{Kind: "fixture", Reference: "qualified"}}}
	current := integration.StepResult{DispatchState: dispatch, VerificationState: "verified", Postcondition: &proof}
	newRaw, _ := json.Marshal(current)
	*b.Effect.EvidenceJson = string(newRaw)
	*b.Effect.Revision = 3
	audit := data.ReconcileEffectAudit{PriorRunRevision: 2, PriorEffectRevision: 2, RunID: *b.RunId, PlanID: *b.PlanId, StepID: *b.StepId, AttemptID: *b.DurableAttemptId, EffectID: *b.EffectId, BusinessKey: *b.Effect.BusinessKey, OriginalStepHash: strings.Repeat("c", 64), OriginalEvidenceHash: data.ReconcileEffectHash(raw), Evidence: data.ReconcileEffectEvidence{ContractID: "contract", ContractHash: strings.Repeat("b", 64), RequiredAuthority: objective.Observational, FreshnessMs: 1000, Result: proof, StepResult: current}}
	auditRaw, _ := json.Marshal(audit)
	id := strings.Repeat("d", 64)
	kind := "effect_reconciliation"
	seq := 4
	payload := string(auditRaw)
	b.Outcomes = append(b.Outcomes, &bindings.Outcome{Namespace: b.Namespace, Id: &id, RunId: b.RunId, AttemptId: b.DurableAttemptId, Sequence: &seq, Kind: &kind, PayloadJson: &payload})
	if _, err := MatchChromeRetirementBindings(p, f, m, rows); err != nil {
		t.Fatal(err)
	}

	if dispatch == "unknown" {
		accepted, _ := MatchChromeRetirementBindings(p, f, m, rows)
		m[0].Receipts[0].EffectState = "verified"
		if _, err := MatchChromeRetirementBindings(p, f, m, rows); err != nil {
			t.Fatal("qualified renderer fact rejected:", err)
		}
		m[0].Receipts[0].EffectState = "none"
		if _, err := MatchChromeRetirementBindings(p, f, m, rows); err == nil {
			t.Fatal("accepted dispatched receipt without effect")
		}
		m[0].Receipts[0].EffectState = "unverified"
		m[0].Receipts[0].DispatchState = "notDispatched"
		if _, err := MatchChromeRetirementBindings(p, f, m, rows); err == nil {
			t.Fatal("accepted absence as lost acknowledgement")
		}
		m[0].Receipts[0].DispatchState = "dispatched"
		b.Outcomes = b.Outcomes[:1]
		if _, err := MatchChromeRetirementBindings(p, f, m, rows); err == nil {
			t.Fatal("accepted unknown dispatch without reconciliation")
		}
		b.Outcomes = append(b.Outcomes, &bindings.Outcome{Namespace: b.Namespace, Id: &id, RunId: b.RunId, AttemptId: b.DurableAttemptId, Sequence: &seq, Kind: &kind, PayloadJson: &payload})
		if recovered, err := MatchChromeRetirementBindings(p, f, m, rows); err != nil || recovered != accepted {
			t.Fatal("lost acknowledgement digest changed on restore", err)
		}
	}
	audit.OriginalEvidenceHash = strings.Repeat("e", 64)
	auditRaw, _ = json.Marshal(audit)
	payload = string(auditRaw)
	if _, err := MatchChromeRetirementBindings(p, f, m, rows); err == nil {
		t.Fatal("accepted mismatched original evidence")
	}
}
