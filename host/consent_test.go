package host

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/viant/datly/exec"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/data"
	datahost "github.com/viant/mechanize/data/host"
	automation "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestBrokerDatlyEndlyCancellationAndBoundaries(t *testing.T) {
	p, _ := auth.NewPrincipal("fixture", "", "human", []string{"desktop:observe", "consent:admin"})
	p.ClientID = "enrolled-agent"
	p.ClientName = "Enrolled Agent"
	requester := auth.WithPrincipal(context.Background(), p)
	native, e := auth.WithNativeHuman(requester)
	if e != nil {
		t.Fatal(e)
	}
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Dir(filepath.Dir(file))
	scoped, e := data.WithScope(requester, data.Scope{Namespace: p.Namespace})
	if e != nil {
		t.Fatal(e)
	}
	server, e := datahost.Open(scoped, root, t.TempDir(), data.Scope{Namespace: p.Namespace})
	if e != nil {
		t.Fatal(e)
	}
	defer server.Shutdown(context.Background())
	dispatched := make(chan struct{}, 1)
	stopped := make(chan struct{}, 1)
	var broker *ConsentBroker
	rt, e := automation.New(func(ctx context.Context, p auth.Principal, step model.Step, values map[string]model.Value) (automation.StepResult, error) {
		binding, ok := ConsentBindingFromContext(ctx)
		if !ok {
			return automation.StepResult{}, errors.New("binding lost")
		}
		scope, _ := ConsentScope(step.Target.Surface)
		lease, e := broker.Authorize(ctx, p, consent.Operation{GrantID: binding.GrantID, SessionID: binding.SessionID, Scope: scope, Mode: consent.Observe, Purpose: binding.Purpose})
		if e != nil {
			return automation.StepResult{}, e
		}
		dispatched <- struct{}{}
		<-lease.Context.Done()
		// The fixture dispatch has stopped and has no external cleanup. Only now release.
		lease.Release()
		stopped <- struct{}{}
		return automation.StepResult{DispatchState: "notDispatched"}, lease.Context.Err()
	})
	if e != nil {
		t.Fatal(e)
	}
	session, e := rt.Open(requester, "fixture")
	if e != nil {
		t.Fatal(e)
	}
	defer rt.Close(requester, session.SessionID)
	broker, e = NewConsentBroker(ConsentBrokerOptions{
		Invoke: func(ctx context.Context, _ auth.Principal, r exec.ComponentRequest) (any, error) {
			return server.InvokeComponent(ctx, r)
		},
		Enrolled: func(context.Context, auth.Principal) (User, error) { return User{Subject: "human"}, nil },
		SessionOwned: func(ctx context.Context, p auth.Principal, id string) error {
			if id != session.SessionID {
				return auth.ErrUnauthorized
			}
			return nil
		},
		Policy: func(context.Context, auth.Principal, consent.Scope, []consent.Mode, int) error { return nil },
	})
	if e != nil {
		t.Fatal(e)
	}
	in := consent.RequestInput{Scope: consent.Scope{Kind: "application", BundleID: "fixture.editor"}, Modes: []consent.Mode{consent.Observe}, Purpose: "Inspect fixture", DurationSeconds: 60}
	request, e := broker.Request(requester, p, session.SessionID, in)
	if e != nil {
		t.Fatal(e)
	}
	decide, _ := json.Marshal(map[string]any{"requestID": request.ID, "decision": consent.AllowSession})
	if _, e = broker.NativeRPC(requester, "decide", decide); e == nil {
		t.Fatal("MCP requester decided consent")
	}
	value, e := broker.NativeRPC(native, "decide", decide)
	if e != nil {
		t.Fatal(e)
	}
	grant := value.(*consent.Grant)
	bound := WithConsentBinding(requester, ConsentBinding{GrantID: grant.ID, SessionID: session.SessionID, Purpose: in.Purpose})
	for _, bad := range []consent.Operation{
		{GrantID: grant.ID, SessionID: session.SessionID, Scope: consent.Scope{Kind: "application", BundleID: "other.editor"}, Mode: consent.Observe, Purpose: in.Purpose},
		{GrantID: grant.ID, SessionID: session.SessionID, Scope: in.Scope, Mode: consent.Control, Purpose: in.Purpose},
		{GrantID: grant.ID, SessionID: session.SessionID, Scope: in.Scope, Mode: consent.Observe, Purpose: "Other purpose"},
	} {
		if _, e = broker.Authorize(bound, p, bad); e == nil {
			t.Fatal("operation scope widened")
		}
	}
	step := model.Step{ID: "observe", Action: "element.read", Arguments: map[string]model.Value{"attribute": {Kind: model.StringValue, String: "text"}}, Target: model.Selector{Cardinality: "one", Locator: &model.Locator{Strategy: "id", Value: model.Value{Kind: model.StringValue, String: "fixture"}, Exact: true}, Surface: model.Surface{Kind: "native", BundleID: "fixture.editor"}}, TimeoutMs: 1000, Effect: model.Effect{Class: model.ReadOnly}}
	operation, e := rt.StartPlan(bound, session.SessionID, model.Plan{SchemaVersion: 1, Steps: []model.Step{step}}, nil)
	if e != nil {
		t.Fatal(e)
	}
	select {
	case <-dispatched:
	case <-time.After(5 * time.Second):
		status, _ := rt.Status(requester, session.SessionID, operation.ID)
		t.Fatalf("Endly fixture did not dispatch: %+v", status)
	}
	revoke, _ := json.Marshal(map[string]any{"grantID": grant.ID})
	if _, e = broker.NativeRPC(native, "revoke", revoke); e != nil {
		t.Fatal(e)
	}
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("revoke failed to cancel Endly lease")
	}
	for i := 0; i < 3; i++ {
		if _, e = broker.NativeRPC(native, "snapshot", nil); e != nil {
			t.Fatal(e)
		}
	}
	v, e := broker.NativeRPC(native, "snapshot", nil)
	if e != nil {
		t.Fatal(e)
	}
	snapshot := v.(consent.Snapshot)
	if len(snapshot.Grants) != 1 || snapshot.Grants[0].RevocationState != consent.Revoked {
		t.Fatalf("cleanup not reconciled: %+v", snapshot)
	}
	// A separate once grant must be consumed durably before the caller can dispatch.
	onceRequest, e := broker.Request(requester, p, session.SessionID, in)
	if e != nil {
		t.Fatal(e)
	}
	onceRaw, _ := json.Marshal(map[string]any{"requestID": onceRequest.ID, "decision": consent.AllowOnce})
	onceValue, e := broker.NativeRPC(native, "decide", onceRaw)
	if e != nil {
		t.Fatal(e)
	}
	onceGrant := onceValue.(*consent.Grant)
	onceCtx := WithConsentBinding(requester, ConsentBinding{GrantID: onceGrant.ID, SessionID: session.SessionID, Purpose: in.Purpose})
	op := consent.Operation{GrantID: onceGrant.ID, SessionID: session.SessionID, Scope: in.Scope, Mode: consent.Observe, Purpose: in.Purpose}
	lease, e := broker.Authorize(onceCtx, p, op)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = broker.Authorize(onceCtx, p, op); e == nil {
		t.Fatal("once grant admitted a second dispatch")
	}
	lease.Release()

}
