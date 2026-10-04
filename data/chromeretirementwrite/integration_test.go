package chromeretirementwrite_test

import (
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/viant/datly/exec"
	"github.com/viant/datly/spec"
	"github.com/viant/datly/standalone"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data"
	get "github.com/viant/mechanize/data/chromeretirementget"
	write "github.com/viant/mechanize/data/chromeretirementwrite"
	datahost "github.com/viant/mechanize/data/host"
	"github.com/viant/xdatly/handler"
)

func retirementFixture(t *testing.T) (context.Context, auth.Principal, data.ChromeRetirementAuthority, *standalone.Server) {
	t.Helper()
	p, _ := auth.NewPrincipal("fixture", "", "retirement-ledger", []string{"desktop:control"})
	p.ClientID = "fixture-client"
	ctx, err := data.WithScope(auth.WithPrincipal(context.Background(), p), data.Scope{Namespace: p.Namespace})
	if err != nil {
		t.Fatal(err)
	}
	hash := strings.Repeat("a", 64)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	a := data.ChromeRetirementAuthority{Namespace: p.Namespace, ClientID: p.ClientID, RequestID: "retire-1", ProfileChannel: "profile", BrowserInstance: "browser", TrustScope: "desktop", OldBrokerEpoch: "broker-old", OldChannelEpoch: "channel-old", OldScopeHash: hash, Phase: "intended", GuardProof: "qualified-guard", CreatedAt: now, Now: now, Process: data.ChromeRetirementProcessEvidence{Version: 1, NativeHostPID: 20, NativeHostBirth: "1790000000:2", NativeHostImageDigest: hash, ChromePID: 10, ChromeBirth: "1790000000:1", ChromeImageDigest: hash, KernelPeerQualified: true, ImmediateParentQualified: true}, Policy: data.ChromeRetirementPolicyEvidence{Version: 1, ExtensionID: strings.Repeat("a", 32), TrustScope: "desktop", OriginScopeDigest: hash, NativeHostRequirementDigest: hash, ChromeRequirementDigest: hash, BrokerRequirementDigest: hash}, Proof: data.ChromeRetirementPhaseProof{Version: 1, InputInhibited: true}}
	a.TransitionID = data.ChromeRetirementID(a.Namespace, a.ClientID, a.ProfileChannel, a.BrowserInstance, a.RequestID)
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "../.."))
	s, err := datahost.Open(ctx, root, t.TempDir(), data.Scope{Namespace: p.Namespace})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Shutdown(context.Background()); err != nil {
			t.Error(err)
		}
	})
	// Materialization precedes the short-lived host-issued lifecycle capability.
	if err := s.PrepareComponent(ctx, spec.Key{Kind: spec.KindComponent, Scope: "github.com/viant/mechanize/data/chromeretirementwrite", Name: "WriteChromeRetirement"}); err != nil {
		t.Fatal(err)
	}
	a.Now = time.Now().UTC().Format(time.RFC3339Nano)
	a.CreatedAt = a.Now
	return ctx, p, a, s
}
func retirementInput(a data.ChromeRetirementAuthority) *write.WriteChromeRetirementInput {
	row := map[string]any{"namespace": a.Namespace, "id": a.TransitionID, "clientId": a.ClientID, "requestId": a.RequestID, "profileChannel": a.ProfileChannel, "browserInstance": a.BrowserInstance, "trustScope": a.TrustScope, "oldBrokerEpoch": a.OldBrokerEpoch, "oldChannelEpoch": a.OldChannelEpoch, "oldScopeHash": a.OldScopeHash, "processEvidenceJson": a.ProcessJSON, "policyEvidenceJson": a.PolicyJSON, "evidenceDigest": a.EvidenceDigest, "phase": a.Phase, "revision": a.PriorRevision, "createdAt": a.CreatedAt, "updatedAt": a.Now}
	if a.Phase == "intended" {
		row["revision"] = 1
	} else {
		row["manifestDigest"] = a.ManifestDigest
		row["manifestCount"] = a.ManifestCount
		row["receiptCount"] = a.ReceiptCount
	}
	if a.Phase == "adopted" {
		row["adoptionEvidenceJson"] = a.AdoptionJSON
		row["adoptionDigest"] = a.AdoptionDigest
	}
	manifests := []map[string]any{}
	if a.Phase == "prepared" {
		for _, m := range a.Manifests {
			raw, digest, _ := data.ChromeRetirementManifestJSON(m)
			identity, _ := json.Marshal(m.Identity)
			manifests = append(manifests, map[string]any{"namespace": a.Namespace, "transitionId": a.TransitionID, "id": data.ChromeRetirementManifestID(m.Identity), "documentIdentityJson": string(identity), "receiptRevision": m.ReceiptRevision, "receiptCount": len(m.Receipts), "canonicalManifestJson": raw, "manifestDigest": digest, "createdAt": a.Now})
		}
	}
	row["manifests"] = manifests
	row["audit"] = []map[string]any{{"namespace": a.Namespace, "id": a.AuditID, "transitionId": a.TransitionID, "phase": a.Phase, "priorRevision": a.PriorRevision, "sequence": a.PriorRevision + 1, "requestId": a.RequestID, "payloadJson": a.AuditPayloadJSON, "createdAt": a.Now}}
	body, _ := json.Marshal(row)
	var r write.Retirement
	_ = json.Unmarshal(body, &r)
	markRetirementFields(&r)
	for _, m := range r.Manifests {
		markRetirementFields(m)
	}
	for _, e := range r.Audit {
		markRetirementFields(e)
	}
	in := &write.WriteChromeRetirementInput{}
	in.SetNamespace(a.Namespace)
	in.SetClientID(a.ClientID)
	in.SetTransitionID(a.TransitionID)
	in.SetWriteChromeRetirement([]*write.Retirement{&r})
	return in
}

func markRetirementFields(value any) {
	rv := reflect.ValueOf(value)
	v := rv.Elem()
	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		if v.Type().Field(i).Name == "Has" || field.Kind() == reflect.Pointer && field.IsNil() || field.Kind() == reflect.Slice && field.Len() == 0 {
			continue
		}
		setter := rv.MethodByName("Set" + v.Type().Field(i).Name)
		if setter.IsValid() {
			setter.Call([]reflect.Value{field})
		}
	}
}
func writeRetirement(ctx context.Context, s *standalone.Server, in *write.WriteChromeRetirementInput) (bool, error) {
	var o handler.Outcome
	_, err := s.InvokeComponent(ctx, exec.ComponentRequest{Target: exec.ComponentTarget{Component: spec.Key{Kind: spec.KindComponent, Scope: "github.com/viant/mechanize/data/chromeretirementwrite", Name: "WriteChromeRetirement"}, Route: spec.RouteRef{Method: "PATCH", Path: "/internal/data/chromeretirementwrite"}}, Input: in, Completion: func(v handler.Outcome) { o = v }})
	return o.CommitConfirmed(), err
}
func loadRetirement(ctx context.Context, s *standalone.Server, a data.ChromeRetirementAuthority) (*get.LoadChromeRetirementOutput, error) {
	in := &get.LoadChromeRetirementInput{}
	in.SetNamespace(a.Namespace)
	in.SetClientID(a.ClientID)
	in.SetTransitionID(a.TransitionID)
	v, err := s.InvokeComponent(ctx, exec.ComponentRequest{Target: exec.ComponentTarget{Component: spec.Key{Kind: spec.KindComponent, Scope: "github.com/viant/mechanize/data/chromeretirementget", Name: "LoadChromeRetirement"}, Route: spec.RouteRef{Method: "GET", Path: "/internal/data/chromeretirementget"}}, Input: in})
	if err != nil {
		return nil, err
	}
	return v.(*get.LoadChromeRetirementOutput), nil
}

func TestGeneratedChromeRetirementLedgerRetainsResolvedNonemptyHistoryAndExactPhases(t *testing.T) {
	ctx, p, a, s := retirementFixture(t)
	var storedManifests any
	for _, phase := range []string{"intended", "prepared", "released", "adopted"} {
		a.Phase = phase
		a.PriorRevision = data.ChromeRetirementPhaseRevision(phase) - 1
		a.Now = time.Now().UTC().Format(time.RFC3339Nano)
		if phase == "intended" {
			a.CreatedAt = a.Now
		} else {
			a.Proof.NoPending = true
			a.Proof.NoUnknown = true
			a.Proof.ExecutorsQuiescent = true
			a.Proof.ReceiptCoverageComplete = true
			a.Proof.RecordingHistoryRetained = true
			a.Proof.BusinessLedgerReconciled = true
			a.Proof.HostResolutionDigest = strings.Repeat("c", 64)
		}
		if phase == "prepared" {
			a.Manifests = []data.ChromeRetirementManifest{{Version: 1, Identity: data.ChromeRetirementDocumentIdentity{ProfileChannel: a.ProfileChannel, BrowserInstance: a.BrowserInstance, TabID: 7, FrameID: 0, DocumentID: "original-doc"}, ReceiptRevision: 1, Receipts: []data.ChromeRetirementReceipt{{AttemptID: "opaque-browser-attempt", FingerprintSHA256: strings.Repeat("b", 64), DispatchState: "dispatched", EffectState: "unverified"}}, Readiness: data.ChromeRetirementReadiness{Quiesced: true, RecordingState: "none"}}}
		}
		if phase == "released" || phase == "adopted" {
			a.Proof.FenceReleaseConfirmed = true
		}
		if phase == "adopted" {
			a.Adoption = &data.ChromeRetirementAdoptionEvidence{Version: 1, BrokerEpoch: "broker-new", ChannelEpoch: "channel-new", ScopeHash: a.OldScopeHash, Process: a.Process, Policy: a.Policy, FreshDocumentsQualified: true}
		}
		authCtx, err := data.WithChromeRetirementAuthority(ctx, a)
		if err != nil {
			t.Fatal(err)
		}
		a, err = data.RequireChromeRetirementAuthority(authCtx)
		if err != nil {
			t.Fatal(err)
		}
		in := retirementInput(a)
		baseline, err := loadRetirement(ctx, s, a)
		if err != nil {
			t.Fatal(err)
		}
		baselineJSON, _ := json.Marshal(baseline)
		for _, tamper := range []string{"old fence", "request identity", "audit missing", "wire client", "phase", "manifest count"} {
			if tamper == "manifest count" && phase == "intended" {
				continue
			}
			bad := retirementInput(a)
			r := bad.WriteChromeRetirement[0]
			switch tamper {
			case "old fence":
				v := "forged-fence"
				r.SetOldBrokerEpoch(&v)
			case "request identity":
				v := "different-request"
				r.SetRequestId(&v)
			case "audit missing":
				r.SetAudit(nil)
			case "wire client":
				bad.SetClientID("different-client")
			case "phase":
				v := "adopted"
				if phase == "adopted" {
					v = "intended"
				}
				r.SetPhase(&v)
			case "manifest count":
				v := a.ManifestCount + 1
				r.SetManifestCount(&v)
			}
			if committed, err := writeRetirement(authCtx, s, bad); err == nil || committed {
				t.Fatalf("phase %s accepted %s mutation", phase, tamper)
			}
			unchanged, err := loadRetirement(ctx, s, a)
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := json.Marshal(unchanged)
			if string(raw) != string(baselineJSON) {
				t.Fatal("invalid graph partially mutated ledger")
			}
		}
		if phase == "intended" {
			if committed, err := writeRetirement(ctx, s, in); err == nil || committed {
				t.Fatal("caller body minted lifecycle authority")
			}
		}
		if committed, err := writeRetirement(authCtx, s, in); err != nil || !committed {
			t.Fatalf("phase %s: committed=%v %v", phase, committed, err)
		}
		out, err := loadRetirement(ctx, s, a)
		if err != nil || len(out.Data) != 1 {
			t.Fatalf("readback %v %v", out, err)
		}
		r := out.Data[0]
		if r.Phase == nil || *r.Phase != phase || r.Revision == nil || *r.Revision != a.PriorRevision+1 || len(r.Audit) != a.PriorRevision+1 {
			t.Fatal("phase revision or immutable audits changed")
		}
		if phase == "prepared" {
			storedManifests = r.Manifests
			if len(r.Manifests) != 1 || r.ReceiptCount == nil || *r.ReceiptCount != 1 {
				t.Fatal("nonempty unverified business receipt history discarded")
			}
		}
		if phase == "released" || phase == "adopted" {
			if !reflect.DeepEqual(storedManifests, r.Manifests) {
				t.Fatal("release/adoption relabelled retained receipt history")
			}
		}
		before, _ := json.Marshal(out)
		if committed, err := writeRetirement(authCtx, s, retirementInput(a)); err == nil || committed {
			t.Fatal("same old revision created duplicate phase/audit")
		}
		after, err := loadRetirement(ctx, s, a)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(after)
		if string(raw) != string(before) {
			t.Fatal("rejected stale write mutated history")
		}
		foreign := a
		foreign.ClientID = "different-client"
		if _, err := loadRetirement(ctx, s, foreign); err == nil {
			t.Fatal("another client read retirement")
		}
		changed := p
		changed.ClientID = "different-client"
		if _, err := data.WithChromeRetirementAuthority(auth.WithPrincipal(ctx, changed), a); err == nil {
			t.Fatal("another client reused lifecycle authority")
		}
	}
}
