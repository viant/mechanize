package host

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
	repairs "github.com/viant/mechanize/engine/recovery"
	"github.com/viant/mechanize/model"
	core "github.com/viant/mechanize/recovery"
)

type nativeRecoveryEvidenceFixture struct {
	p                  auth.Principal
	ctx                context.Context
	snapshot           repairs.Snapshot
	policy             NativeRecoveryEvidencePolicy
	observation        model.Observation
	resolves, observes int
	provider           *NativeRecoveryEvidenceProvider
}

func newNativeRecoveryEvidenceFixture(t *testing.T) *nativeRecoveryEvidenceFixture {
	t.Helper()
	p, err := auth.NewPrincipal("fixture", "", "native-evidence", []string{"desktop:control"})
	if err != nil {
		t.Fatal(err)
	}
	p.ClientID = "fixture-client"
	surface := model.Surface{Kind: "native", BundleID: "com.example.Editor", ProcessID: 42, ProcessStartToken: "1790000000:1"}
	target := model.Selector{Surface: surface, Cardinality: "one", Locator: &model.Locator{Strategy: "id", Exact: true, Value: model.Value{Kind: model.StringValue, String: "old-save"}}, Scope: model.Scope{Window: map[string]model.Value{"title": {Kind: model.StringValue, String: "Editor"}}}}
	step := model.Step{ID: "save", Action: "element.press", SemanticsProfile: "save.v1", Target: target, TimeoutMs: 1000, Effect: model.Effect{Class: model.IdempotentMutation}}
	truth := true
	now := time.Now()
	f := &nativeRecoveryEvidenceFixture{p: p, ctx: auth.WithPrincipal(context.Background(), p), snapshot: repairs.Snapshot{Reference: repairs.RunReference{RunID: "run", PlanID: "plan", Revision: 3, ContentHash: "content", PlanHash: "plan-hash", Status: "paused"}, Plan: model.Plan{Steps: []model.Step{step}}}, policy: NativeRecoveryEvidencePolicy{PolicyHash: "trusted-policy-v1", SafeIdentifiers: []string{"changed-save", "old-save"}, SafeNames: []string{"Save", "Editor", "Other"}, Contracts: []core.Contract{{Profile: step.SemanticsProfile, Action: step.Action, Surface: surface, Permissions: []string{"desktop:control"}, Qualified: true, TargetScope: &target}}}, observation: model.Observation{Surface: surface, ID: "private-observation-id", Epoch: "private-helper-epoch", Sequence: 42, Started: now.Add(-time.Millisecond), Ended: now, Nodes: []model.Node{{Ref: model.ElementRef{ID: "private-window"}, Role: "window", Name: "Editor"}, {Ref: model.ElementRef{ID: "private-other-window"}, Role: "window", Name: "Other"}, {Ref: model.ElementRef{ID: "private-handle", Epoch: "private-node-epoch", AppLaunchID: "private-launch", Generation: 13}, ParentID: "private-window", Role: "button", NativeRole: "AXButton", Name: "Save", Identifier: "changed-save", Enabled: &truth, Visible: &truth, Focused: &truth, Actions: []string{"private-action"}, Values: map[string]model.Value{"value": {Kind: model.StringValue, String: "private-secret-value"}}, Unavailable: []string{"private-node-diagnostic"}, NativeOwnerProcessID: surface.ProcessID, NativeOwnerStartToken: surface.ProcessStartToken, NativeOwnerBundleID: surface.BundleID, NativeOwnerMatchesRoot: &truth}, {Ref: model.ElementRef{ID: "private-label"}, Role: "private-arbitrary-role", Name: "private-document-title", Identifier: "private-user-identifier", Values: map[string]model.Value{"text": {Kind: model.StringValue, String: "private-password"}}}}}}
	f.provider, err = NewNativeRecoveryEvidence(NativeRecoveryEvidenceOptions{Resolve: func(ctx context.Context, got auth.Principal, snapshot repairs.Snapshot) (NativeRecoveryEvidencePolicy, error) {
		f.resolves++
		if got.Namespace != p.Namespace || got.ClientID != p.ClientID || snapshot.Reference.RunID != f.snapshot.Reference.RunID {
			return NativeRecoveryEvidencePolicy{}, auth.ErrUnauthorized
		}
		return f.policy, ctx.Err()
	}, Observe: func(ctx context.Context, got auth.Principal, gotSurface model.Surface) (model.Observation, error) {
		f.observes++
		if got.Namespace != p.Namespace || got.ClientID != p.ClientID || gotSurface != surface {
			return model.Observation{}, auth.ErrUnauthorized
		}
		return f.observation, ctx.Err()
	}})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestNativeRecoveryEvidenceStripsSecretsAndRefreshesStableSemanticProof(t *testing.T) {
	f := newNativeRecoveryEvidenceFixture(t)
	evidence, err := f.provider.Prepare(f.ctx, f.p, f.snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if !evidence.Verified || !evidence.Redacted || len(evidence.EvidenceRefs) != 1 || evidence.ValidUntil.After(f.observation.Ended.Add(5*time.Second)) {
		t.Fatalf("invalid qualified proof: %+v", evidence)
	}
	encoded, _ := json.Marshal(evidence.Observation)
	if strings.Contains(string(encoded), "private-") || strings.Contains(string(encoded), "private ") {
		t.Fatalf("unredacted metadata leaked: %s", encoded)
	}
	if evidence.Observation.ID != "" || evidence.Observation.Epoch != "" || evidence.Observation.Sequence != 0 || len(evidence.Observation.Unavailable) != 0 {
		t.Fatal("observation handle/diagnostic leaked")
	}
	seen := false
	for _, node := range evidence.Observation.Nodes {
		if node.Ref != (model.ElementRef{}) || node.ParentID != "" || node.NativeRole != "" || node.NativeOwnerProcessID != 0 || node.NativeOwnerMatchesRoot != nil || len(node.Values) != 0 || len(node.Unavailable) != 0 || len(node.Actions) != 0 {
			t.Fatal("raw node metadata leaked")
		}
		if node.Identifier == "changed-save" {
			seen = node.Name == "Save" && node.Role == "button" && node.Enabled != nil && *node.Enabled && node.Visible != nil && *node.Visible && node.Focused != nil && *node.Focused
		}
	}
	if !seen {
		t.Fatal("explicitly enrolled semantic metadata missing")
	}
	// Fresh raw IDs, generations, timestamps and order do not change semantics.
	f.observation.ID, f.observation.Epoch = "new-raw-id", "new-epoch"
	f.observation.Nodes[2].Ref.ID, f.observation.Nodes[2].Ref.Generation = "new-handle", 99
	f.observation.Nodes[0].Ref.ID = "new-window"
	f.observation.Nodes[2].ParentID = "new-window"
	f.observation.Nodes[0], f.observation.Nodes[1] = f.observation.Nodes[1], f.observation.Nodes[0]
	f.observation.Started, f.observation.Ended = time.Now().Add(-time.Millisecond), time.Now()
	refreshed, err := f.provider.Prepare(f.ctx, f.p, f.snapshot)
	if err != nil || !reflect.DeepEqual(refreshed.EvidenceRefs, evidence.EvidenceRefs) {
		t.Fatalf("unchanged UI changed proof: %v", err)
	}
	if err := f.provider.Verify(f.ctx, f.p, f.snapshot, evidence); err != nil {
		t.Fatal(err)
	}
	if f.resolves != 3 || f.observes != 3 {
		t.Fatalf("verification did not independently resolve and observe: %d %d", f.resolves, f.observes)
	}
}

func TestNativeRecoveryEvidenceRejectsActorBeforeCallbacks(t *testing.T) {
	for _, mode := range []string{"namespace", "client", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			f := newNativeRecoveryEvidenceFixture(t)
			p, ctx := f.p, f.ctx
			switch mode {
			case "namespace":
				p, _ = auth.NewPrincipal("fixture", "", "other", []string{"desktop:control"})
			case "client":
				p.ClientID = "other-client"
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if _, err := f.provider.Prepare(ctx, p, f.snapshot); err == nil {
				t.Fatal("unbound actor accepted")
			}
			if f.resolves != 0 || f.observes != 0 {
				t.Fatal("invalid actor reached policy or backend")
			}
		})
	}
}

func TestNativeRecoveryEvidenceDoesNotBroadenNativeRoot(t *testing.T) {
	surface := model.Surface{Kind: "native", BundleID: "com.fixture.editor", ProcessID: 55, ProcessStartToken: "100:2"}
	target := model.Selector{Surface: surface, Cardinality: "one", Locator: &model.Locator{Strategy: "id", Exact: true, Value: model.Value{Kind: model.StringValue, String: "save"}}}
	ids := map[string]bool{"save": true}
	if err := recoveryEvidenceSelectorPolicy(target, surface, ids, nil, 0); err != nil {
		t.Fatal(err)
	}
	for _, root := range []string{"menuBar", "focusedElement"} {
		target.Scope.NativeRoot = root
		if err := recoveryEvidenceSelectorPolicy(target, surface, ids, nil, 0); err == nil {
			t.Fatal("whole-app recovery evidence qualified a scoped root", root)
		}
	}
}

func TestNativeRecoveryEvidenceRejectsIncompleteForeignOrUnqualifiedProof(t *testing.T) {
	for _, mode := range []string{"foreign surface", "foreign node", "owner mismatch", "scoped observation", "window subtree", "window roots", "truncated", "unavailable observation", "too many nodes", "stale", "future", "missing birth", "malformed birth", "unknown effect", "no enrollment", "duplicate label", "duplicate contract", "wrong scope", "unsafe window", "unsafe leaf", "unmatched profile", "unqualified", "changed predicate"} {
		t.Run(mode, func(t *testing.T) {
			f := newNativeRecoveryEvidenceFixture(t)
			switch mode {
			case "foreign surface":
				f.observation.Surface.ProcessID++
			case "foreign node":
				f.observation.Nodes[2].NativeOwnerProcessID++
			case "owner mismatch":
				nope := false
				f.observation.Nodes[2].NativeOwnerMatchesRoot = &nope
			case "window subtree":
				f.observation.WindowScope = map[string]string{"title": "Editor"}
			case "window roots":
				f.observation.WindowRootsOnly = true
			case "scoped observation":
				f.observation.NativeRoot = "focusedElement"
			case "truncated":
				f.observation.Truncated = true
			case "unavailable observation":
				f.observation.Unavailable = []string{"private incomplete diagnostic"}
			case "too many nodes":
				f.observation.Nodes = make([]model.Node, 257)
			case "stale":
				f.observation.Ended = time.Now().Add(-6 * time.Second)
				f.observation.Started = f.observation.Ended
			case "future":
				f.observation.Ended = time.Now().Add(time.Second)
			case "missing birth":
				f.snapshot.Plan.Steps[0].Target.Surface.ProcessStartToken = ""
			case "malformed birth":
				f.snapshot.Plan.Steps[0].Target.Surface.ProcessStartToken = "invalid-birth"
			case "unknown effect":
				f.snapshot.Unknown = true
			case "no enrollment":
				f.policy.Contracts = nil
			case "duplicate label":
				f.policy.SafeNames = []string{"Save", "Save"}
			case "duplicate contract":
				f.policy.Contracts = append(f.policy.Contracts, f.policy.Contracts[0])
			case "wrong scope":
				copy := *f.policy.Contracts[0].TargetScope
				copy.Scope.Window = map[string]model.Value{"id": {Kind: model.StringValue, String: "other-window"}}
				f.policy.Contracts[0].TargetScope = &copy
			case "unsafe window":
				f.policy.SafeNames = []string{"Save"}
			case "unsafe leaf":
				f.policy.SafeIdentifiers = []string{"changed-save"}
			case "unmatched profile":
				f.policy.Contracts[0].Profile = "synthetic.v1"
			case "unqualified":
				f.policy.Contracts[0].Qualified = false
			case "changed predicate":
				f.policy.Contracts[0].Postcondition = &model.Predicate{Kind: "adapter", Adapter: "native", Name: "fake"}
			}
			if _, err := f.provider.Prepare(f.ctx, f.p, f.snapshot); err == nil {
				t.Fatal("invalid observation/enrollment accepted")
			}
		})
	}
}

func TestNativeRecoveryEvidenceVerificationRejectsChangedBindingsAndUI(t *testing.T) {
	for _, mode := range []string{"UI", "reparented UI", "policy", "allowlist", "revision", "client", "expired", "future proof", "tampered node", "tampered scope"} {
		t.Run(mode, func(t *testing.T) {
			f := newNativeRecoveryEvidenceFixture(t)
			evidence, err := f.provider.Prepare(f.ctx, f.p, f.snapshot)
			if err != nil {
				t.Fatal(err)
			}
			p, ctx := f.p, f.ctx
			switch mode {
			case "UI":
				nope := false
				f.observation.Nodes[2].Enabled = &nope
			case "reparented UI":
				f.observation.Nodes[2].ParentID = "private-other-window"
			case "policy":
				f.policy.PolicyHash = "trusted-policy-v2"
			case "allowlist":
				f.policy.SafeNames = nil
			case "revision":
				f.snapshot.Reference.Revision++
			case "client":
				p.ClientID = "different-client"
				ctx = auth.WithPrincipal(context.Background(), p)
			case "expired":
				evidence.ValidUntil = time.Now().Add(-time.Millisecond)
			case "future proof":
				evidence.Observation.Ended = time.Now().Add(time.Hour)
				evidence.ValidUntil = evidence.Observation.Ended.Add(time.Second)
			case "tampered node":
				evidence.Observation.Nodes[0].Values = map[string]model.Value{"value": {Kind: model.StringValue, String: "secret"}}
			case "tampered scope":
				evidence.Contracts[0].TargetScope.Scope.Window = map[string]model.Value{"id": {Kind: model.StringValue, String: "other-window"}}
			}
			if err := f.provider.Verify(ctx, p, f.snapshot, evidence); err == nil {
				t.Fatal("changed evidence accepted")
			}
		})
	}
}

func TestNativeRecoveryEvidenceResolverCannotMutateOriginalScope(t *testing.T) {
	f := newNativeRecoveryEvidenceFixture(t)
	before, _ := json.Marshal(f.snapshot)
	f.provider.options.Resolve = func(_ context.Context, _ auth.Principal, supplied repairs.Snapshot) (NativeRecoveryEvidencePolicy, error) {
		supplied.Plan.Steps[0].Target.Scope.Window["title"] = model.Value{Kind: model.StringValue, String: "Other"}
		policy := f.policy
		policy.Contracts = append([]core.Contract(nil), policy.Contracts...)
		policy.Contracts[0].TargetScope = &supplied.Plan.Steps[0].Target
		return policy, nil
	}
	if _, err := f.provider.Prepare(f.ctx, f.p, f.snapshot); err == nil {
		t.Fatal("resolver changed original enrolled scope")
	}
	after, _ := json.Marshal(f.snapshot)
	if string(before) != string(after) {
		t.Fatal("resolver mutated private original snapshot")
	}
	if f.observes != 0 {
		t.Fatal("synthetic mutated scope reached backend")
	}
}

func TestNativeRecoveryEvidenceUsesContextGrantsRatherThanCallerExpandedScopes(t *testing.T) {
	f := newNativeRecoveryEvidenceFixture(t)
	p := f.p
	p.Scopes = append(append([]string(nil), p.Scopes...), "fixture:qualification")
	f.policy.Contracts[0].Permissions = append(f.policy.Contracts[0].Permissions, "fixture:qualification")
	f.provider.options.Resolve = func(_ context.Context, actual auth.Principal, _ repairs.Snapshot) (NativeRecoveryEvidencePolicy, error) {
		if actual.HasScope("fixture:qualification") {
			t.Fatal("caller-expanded grant reached resolver")
		}
		return f.policy, nil
	}
	if _, err := f.provider.Prepare(f.ctx, p, f.snapshot); !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatalf("expanded grant qualified a route: %v", err)
	}
	if f.observes != 0 {
		t.Fatal("unauthorized route reached observation")
	}
}

func TestNativeRecoveryEvidenceCallbackCancellationAndErrors(t *testing.T) {
	f := newNativeRecoveryEvidenceFixture(t)
	ctx, cancel := context.WithCancel(f.ctx)
	f.provider.options.Resolve = func(context.Context, auth.Principal, repairs.Snapshot) (NativeRecoveryEvidencePolicy, error) {
		cancel()
		return f.policy, nil
	}
	if _, err := f.provider.Prepare(ctx, f.p, f.snapshot); !errors.Is(err, context.Canceled) || f.observes != 0 {
		t.Fatal("cancelled resolution reached backend")
	}
	f = newNativeRecoveryEvidenceFixture(t)
	failed := errors.New("fixture observation unavailable")
	f.provider.options.Observe = func(context.Context, auth.Principal, model.Surface) (model.Observation, error) {
		return model.Observation{}, failed
	}
	if evidence, err := f.provider.Prepare(f.ctx, f.p, f.snapshot); !errors.Is(err, failed) || evidence.Verified || evidence.Redacted {
		t.Fatal("backend error qualified evidence")
	}
}
