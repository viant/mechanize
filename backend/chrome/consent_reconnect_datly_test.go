package chrome

import (
	"context"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/data"
	datahost "github.com/viant/mechanize/data/host"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// The authenticated broker and canonical consent components are real; only the
// renderer's final action and mutation-binding store are inert fixture delegates.
// This exercises a complete Endly operation after the held recovery CAS.
func TestConsentReconnectDatlyRecoveryThenOneEndlyDispatch(t *testing.T) {
	f := newLifecycleFixture(t, 0, true)
	_, file, _, _ := runtime.Caller(0)
	scope := data.Scope{Namespace: f.principal.Namespace}
	ctx, err := data.WithScope(f.ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	server, err := datahost.Open(ctx, filepath.Dir(filepath.Dir(filepath.Dir(file))), t.TempDir(), scope)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Shutdown(context.Background())
	var service *consent.Service
	var op consent.Operation
	commitCount := 0
	rt, err := integration.New(func(c context.Context, p auth.Principal, step model.Step, _ map[string]model.Value) (integration.StepResult, error) {
		// Match ConsentBroker.bound: Endly supplies authenticated identity;
		// connector scope is established by the trusted host callback.
		c, e := data.WithScope(c, data.Scope{Namespace: p.Namespace})
		if e != nil {
			return integration.StepResult{}, e
		}
		grant, e := service.FindPermanentGrant(c, op)
		if e != nil || grant == nil {
			return integration.StepResult{}, e
		}
		lease, e := service.Authorize(c, op)
		if e != nil {
			return integration.StepResult{}, e
		}
		defer lease.Release()
		authority, e := f.gateway.AdmitControl(lease.Context, p, step.Target.Surface)
		if e != nil {
			return integration.StepResult{}, e
		}
		result, e := f.gateway.ExecuteControlBound(lease.Context, p, step, nil, authority, strings.Repeat("d", 64), func(context.Context, auth.Principal, BoundMutation) (BindingCommit, error) {
			commitCount++
			return BindingCommit{BindingID: strings.Repeat("a", 64), CommitConfirmed: true, ReadbackMatched: true}, nil
		})
		if e == nil {
			_, e = f.gateway.RetireControl(lease.Context, p, authority)
		}
		return result, e
	})
	if err != nil {
		t.Fatal(err)
	}
	opened, err := rt.Open(ctx, "recovery-fixture")
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close(ctx, opened.SessionID)
	client := consent.Client{ID: f.principal.ClientID, DisplayName: "Fixture", SessionID: opened.SessionID, Verification: "verified"}
	options := consent.Options{Namespace: f.principal.Namespace, Invoke: server.InvokeComponent, VerifyClient: func(context.Context) (consent.Client, error) { return client, nil }, VerifyActor: func(context.Context) (consent.Actor, error) {
		return consent.Actor{ID: "fixture-human", Human: true, Admin: true}, nil
	}, ResolveClient: func(context.Context, string, string) (consent.Client, error) { return client, nil }, Policy: func(context.Context, consent.Client, consent.Scope, []consent.Mode, int) error { return nil }, WithCleanupProof: func(c context.Context, _ consent.Client, _ consent.Scope, commit func(context.Context) error) error {
		return f.gateway.WithConsentReconnectProof(c, f.principal, func() error { return commit(c) })
	}}
	service, err = consent.New(options)
	if err != nil {
		t.Fatal(err)
	}
	req, err := service.CreateRequest(ctx, opened.SessionID, consent.RequestInput{Scope: consent.Scope{Kind: "origin", Origin: "https://fixture.test"}, Modes: []consent.Mode{consent.Control}, Purpose: "fixture action", DurationSeconds: 60})
	if err != nil {
		t.Fatal(err)
	}
	grant, err := service.Decide(ctx, req.ID, consent.AllowUntilRevoked)
	if err != nil {
		t.Fatal(err)
	}
	op = consent.Operation{GrantID: grant.ID, SessionID: opened.SessionID, Scope: grant.Scope, Mode: consent.Control, Purpose: grant.Purpose}
	prior, err := service.Authorize(ctx, op)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.ReportDispatchCleanupUnknown(ctx, grant.ID); err != nil {
		t.Fatal(err)
	}
	prior.Release()
	service, err = consent.New(options)
	if err != nil {
		t.Fatal(err)
	}
	running, err := rt.StartPlan(ctx, opened.SessionID, model.Plan{SchemaVersion: 1, Steps: []model.Step{controlStep(t)}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	terminal, err := rt.Wait(bounded, opened.SessionID, running.ID)
	if err != nil {
		t.Fatal(err)
	}
	if f.inputs.Load() != 1 || commitCount != 1 {
		t.Fatalf("operation did not dispatch exactly once: inputs%d commits%d terminal%+v", f.inputs.Load(), commitCount, terminal)
	}
	if _, err = rt.Wait(bounded, opened.SessionID, running.ID); err != nil || f.inputs.Load() != 1 {
		t.Fatal("status replayed action", err)
	}
}
