package host

import (
	"context"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/viant/datly/exec"
	"github.com/viant/datly/spec"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	"github.com/viant/mechanize/data"
	get "github.com/viant/mechanize/data/chromeattemptbindingget"
	datahost "github.com/viant/mechanize/data/host"
	"github.com/viant/mechanize/engine/durable"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
)

func TestGeneratedChromeBindingAdapterCommitsBeforeFixtureKnownAbsence(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(file), ".."))
	storage := t.TempDir()
	p, _ := auth.NewPrincipal("fixture", "", "binding-adapter-integration", []string{"desktop:control"})
	p.ClientID = "enrolled-client"
	ctx := auth.WithPrincipal(context.Background(), p)
	var b *durable.Builder
	var dispatchContext context.Context
	var actual data.CommittedStepIntent
	var descriptor chrome.BoundMutation
	var committed chrome.BindingCommit
	var callbackErr error
	var err error
	b, err = durable.New(durable.Options{SourceRoot: root, StorageRoot: storage, LeaseEpoch: func(context.Context, auth.Principal) (int, error) { return 1, nil }, PrepareStepAuthority: func(ctx context.Context, p auth.Principal, _ model.Step) (context.Context, int, error) {
		ctx, err := data.WithScope(ctx, data.Scope{Namespace: p.Namespace, LeaseEpoch: 1})
		return ctx, 1, err
	}}, func(ctx context.Context, p auth.Principal, step model.Step, _ map[string]model.Value) (integration.StepResult, error) {
		dispatchContext = ctx
		actual, callbackErr = data.RequireCommittedStepIntent(ctx, p)
		if callbackErr != nil {
			return integration.StepResult{DispatchState: "notDispatched", VerificationState: "unknown"}, callbackErr
		}
		pinned := chrome.ControlAuthority{Owner: p.Namespace, ClientID: p.ClientID, BrokerEpoch: "broker", ChannelEpoch: "channel", ScopeHash: strings.Repeat("a", 64), Lease: chrome.Lease{ID: "lease", Generation: 1}}
		pinned.Document.Identity = chrome.Identity{ProfileChannel: "profile", BrowserInstance: "browser", TabID: 7, DocumentID: "document", Generation: 1}
		browserID := data.ChromeAttemptBrowserIDV2(p.Namespace, p.ClientID, actual.AttemptID)
		fingerprint, err := chrome.FingerprintMutationV2(chrome.Command{Action: step.Action, Identity: pinned.Document.Identity, BrokerEpoch: pinned.BrokerEpoch, ChannelEpoch: pinned.ChannelEpoch, ScopeHash: pinned.ScopeHash, ControlLease: &pinned.Lease, AttemptID: browserID, Locator: &chrome.Locator{Strategy: "id", Value: "save", Exact: true}})
		if err != nil {
			callbackErr = err
			return integration.StepResult{DispatchState: "notDispatched", VerificationState: "unknown"}, err
		}
		descriptor = chrome.BoundMutation{Action: step.Action, BrowserAttemptID: browserID, Identity: pinned.Document.Identity, BrokerEpoch: pinned.BrokerEpoch, ChannelEpoch: pinned.ChannelEpoch, ScopeHash: pinned.ScopeHash, ControlLease: pinned.Lease, Fingerprint: fingerprint}
		// This is the production adapter and actual builder-held generated bridge,
		// including confirmed POST completion and exact GET readback before return.
		committed, callbackErr = commitChromeBinding(ctx, p, step, pinned, descriptor, b.InvokeCommittedComponent)
		return integration.StepResult{DispatchState: "notDispatched", VerificationState: "unknown"}, callbackErr
	})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close(ctx)
	r, err := integration.NewWithOptions(b.Execute, integration.Options{PreparePlan: b.PreparePlan, AttachInitialOperation: func(ctx context.Context, p auth.Principal, id string, revision int, session, operation string) error {
		_, err := b.AttachOperation(ctx, p, id, revision, session, operation)
		return err
	}})
	if err != nil {
		t.Fatal(err)
	}
	session, err := r.Open(ctx, "binding adapter fixture")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close(ctx, session.SessionID)
	plan, err := script.Compile(`web.tab(origin:"https://fixture.test").getById("save",exact:true).click()`)
	if err != nil {
		t.Fatal(err)
	}
	plan.Steps[0].TimeoutMs = 120000
	plan.Steps[0].Effect.BusinessKey = map[string]model.Value{"case": {Kind: model.StringValue, String: "adapter-case"}}
	wait, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	op, err := r.StartPlan(wait, session.SessionID, *plan, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.Wait(wait, session.SessionID, op.ID); err != nil {
		t.Fatal(err)
	}
	if callbackErr != nil || !committed.CommitConfirmed || !committed.ReadbackMatched || committed.BindingID != data.ChromeAttemptBindingID(p.Namespace, p.ClientID, actual.AttemptID) {
		t.Fatalf("actual binding adapter did not commit and read back: %+v %v", committed, callbackErr)
	}
	if _, err = data.RequireCommittedStepIntent(dispatchContext, p); err == nil {
		t.Fatal("binding dispatch context survived return")
	}
	scoped, err := data.WithScope(ctx, data.Scope{Namespace: p.Namespace, LeaseEpoch: 1})
	if err != nil {
		t.Fatal(err)
	}
	s, err := datahost.Open(scoped, root, storage, data.Scope{Namespace: p.Namespace, LeaseEpoch: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Shutdown(context.Background())
	in := &get.LoadChromeAttemptBindingInput{}
	in.SetNamespace(p.Namespace)
	in.SetClientID(p.ClientID)
	in.SetBrowserAttemptID(descriptor.BrowserAttemptID)
	value, err := s.InvokeComponent(scoped, exec.ComponentRequest{Target: exec.ComponentTarget{Component: spec.Key{Kind: spec.KindComponent, Scope: "github.com/viant/mechanize/data/chromeattemptbindingget", Name: "LoadChromeAttemptBinding"}, Route: spec.RouteRef{Method: "GET", Path: "/internal/data/chromeattemptbindingget"}}, Input: in})
	if err != nil {
		t.Fatal(err)
	}
	out := value.(*get.LoadChromeAttemptBindingOutput)
	if len(out.Data) != 1 {
		t.Fatal("exact generated reader lost committed adapter binding")
	}
	row := out.Data[0]
	if row.Id == nil || *row.Id != committed.BindingID || row.DurableAttemptId == nil || *row.DurableAttemptId != actual.AttemptID || row.FingerprintDigest == nil || *row.FingerprintDigest != descriptor.Fingerprint.SHA256 || row.DocumentId == nil || *row.DocumentId != descriptor.Identity.DocumentID || row.CommittedRunRevision == nil || *row.CommittedRunRevision != actual.RunRevision || row.Effect == nil || row.Effect.State == nil || *row.Effect.State != "absent" || row.Effect.Revision == nil || *row.Effect.Revision != 2 || len(row.Outcomes) != 1 {
		t.Fatal("adapter binding or actual absence outcome changed on persisted readback")
	}
	// Exercise the production retirement collector against the populated generated
	// graph, including the immutable plan, while the durable bridge holds admission.
	err = b.WithChromeRetirementComponents(ctx, p, func(held context.Context, invoke durable.RetirementComponentInvoker) error {
		_, authority := retirementAuthorityFixture(t)
		authority.Namespace = p.Namespace
		authority.ClientID = p.ClientID
		authority.Phase = "intended"
		authority.PriorRevision = 0
		authority.Manifests = nil
		authority.ProfileChannel = descriptor.Identity.ProfileChannel
		authority.BrowserInstance = descriptor.Identity.BrowserInstance
		authority.OldBrokerEpoch = descriptor.BrokerEpoch
		authority.OldChannelEpoch = descriptor.ChannelEpoch
		authority.OldScopeHash = descriptor.ScopeHash
		authority.Now = time.Now().UTC().Format(time.RFC3339Nano)
		authority.CreatedAt = authority.Now
		authority.TransitionID = data.ChromeRetirementID(p.Namespace, p.ClientID, authority.ProfileChannel, authority.BrowserInstance, authority.RequestID)
		bound, err := data.WithChromeRetirementAuthority(held, authority)
		if err != nil {
			return err
		}
		fence := ChromeRetirementFence{authority.ProfileChannel, authority.BrowserInstance, authority.OldBrokerEpoch, authority.OldChannelEpoch, authority.OldScopeHash}
		manifest := data.ChromeRetirementManifest{Version: 2, Identity: data.ChromeRetirementDocumentIdentity{ProfileChannel: authority.ProfileChannel, BrowserInstance: authority.BrowserInstance, TabID: descriptor.Identity.TabID, FrameID: descriptor.Identity.FrameID, DocumentID: descriptor.Identity.DocumentID}, Readiness: data.ChromeRetirementReadiness{Quiesced: true, RecordingState: "none"}}
		digest, err := collectChromeRetirementHistory(bound, p, fence, []data.ChromeRetirementManifest{manifest}, committedComponentInvoker(invoke))
		if err != nil {
			return err
		}
		if len(digest) != 64 {
			t.Fatal("generated populated history did not resolve")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("populated retirement history: %v", err)
	}

}
