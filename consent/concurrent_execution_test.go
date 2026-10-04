package consent_test

import (
	"context"
	"errors"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/viant/datly/exec"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/engine/durable"
	automation "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
)

// Generated consent components share the real Builder's admission mutex with
// Endly execution. No fake mutex, timer-driven unlock or direct SQL is used.
func TestHumanRevocationCancelsSharedDatlyEndlyExecutionWithoutLockInversion(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	source := filepath.Dir(filepath.Dir(file))
	p, err := auth.NewPrincipal("fixture", "", "concurrent-consent", []string{"desktop:control", "consent:admin"})
	if err != nil {
		t.Fatal(err)
	}
	p.ClientID = "execution-agent"
	p.ClientName = "Execution Agent"
	actor := auth.WithPrincipal(context.Background(), p)
	var service *consent.Service
	var operation consent.Operation
	started := make(chan struct{})
	released := make(chan struct{})
	nestedDenied := make(chan bool, 1)
	builder, err := durable.New(durable.Options{SourceRoot: source, StorageRoot: t.TempDir(), LeaseEpoch: func(context.Context, auth.Principal) (int, error) { return 1, nil }}, func(ctx context.Context, principal auth.Principal, step model.Step, values map[string]model.Value) (automation.StepResult, error) {
		if step.ID == "materialize-nondispatched-outcome" {
			return automation.StepResult{DispatchState: "notDispatched", VerificationState: "unknown"}, errors.New("fixture preloads generated outcome; no input")
		}
		lease, err := service.Authorize(ctx, operation)
		if err != nil {
			return automation.StepResult{DispatchState: "notDispatched"}, err
		}
		close(started)
		<-lease.Context.Done()
		// A nested consent authorization must reject inhibition without waiting for
		// the human's database lookup, which is waiting on this execution boundary.
		attempted, err := service.Authorize(context.WithoutCancel(ctx), operation)
		nestedDenied <- err != nil && attempted == nil
		lease.Release()
		close(released)
		return automation.StepResult{DispatchState: "notDispatched", VerificationState: "unknown"}, lease.Context.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	scheduler, err := automation.NewWithOptions(builder.Execute, automation.Options{PreparePlan: builder.PreparePlan})
	if err != nil {
		t.Fatal(err)
	}
	session, err := scheduler.Open(actor, "Concurrent revoke fixture")
	if err != nil {
		t.Fatal(err)
	}
	scope := data.Scope{Namespace: p.Namespace}
	actor, err = data.WithScope(actor, scope)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := auth.WithNativeHuman(actor)
	if err != nil {
		t.Fatal(err)
	}
	client := consent.Client{ID: p.ClientID, DisplayName: p.ClientName, SessionID: session.SessionID, Verification: "verified"}
	service, err = consent.New(consent.Options{Namespace: p.Namespace, Invoke: func(ctx context.Context, request exec.ComponentRequest) (any, error) {
		return builder.InvokePrivateComponent(ctx, p, request)
	}, VerifyClient: func(context.Context) (consent.Client, error) { return client, nil }, ResolveClient: func(context.Context, string, string) (consent.Client, error) { return client, nil }, VerifyActor: func(ctx context.Context) (consent.Actor, error) {
		if !auth.NativeHuman(ctx) {
			return consent.Actor{}, errors.New("separate human required")
		}
		return consent.Actor{ID: p.Subject, Human: true, Admin: true}, nil
	}, Policy: func(context.Context, consent.Client, consent.Scope, []consent.Mode, int) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	in := consent.RequestInput{Scope: consent.Scope{Kind: "desktop"}, Modes: []consent.Mode{consent.Control, consent.Observe}, Purpose: "Concurrent stop fixture", DurationSeconds: 120}
	request, err := service.CreateRequest(actor, session.SessionID, in)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := service.Decide(admin, request.ID, consent.AllowSession)
	if err != nil {
		t.Fatal(err)
	}
	operation = consent.Operation{GrantID: grant.ID, SessionID: session.SessionID, Scope: consent.Scope{Kind: "application", BundleID: "com.fixture.app"}, Mode: consent.Control, Purpose: in.Purpose}
	step := model.Step{ID: "wait-for-revoke", Action: "element.press", TimeoutMs: 30000, Effect: model.Effect{Class: model.ExternalNonIdempotent, BusinessKey: map[string]model.Value{"case": {Kind: model.StringValue, String: "concurrent-revoke"}}}, Target: model.Selector{Surface: model.Surface{Kind: "native", BundleID: "com.fixture.app"}, Cardinality: "one", Locator: &model.Locator{Strategy: "id", Value: model.Value{Kind: model.StringValue, String: "fixture"}, Exact: true}}}
	// Materialize the generated outcome and revocation components before the
	// measured lock-order boundary. Cold DQL/Go-AST loading under the race runtime
	// is unrelated to registry/admission lock liveness and still uses real Endly.
	warmStep := step
	warmStep.ID = "materialize-nondispatched-outcome"
	warmOp, err := scheduler.StartPlan(actor, session.SessionID, model.Plan{SchemaVersion: 1, Steps: []model.Step{warmStep}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	warmCtx, warmCancel := context.WithTimeout(actor, 30*time.Second)
	warmFinished, err := scheduler.Wait(warmCtx, session.SessionID, warmOp.ID)
	warmCancel()
	if err != nil || warmFinished.Status != "failed" {
		t.Fatalf("generatedoutcomeprewarm %+v %v", warmFinished, err)
	}
	warmRequest, err := service.CreateRequest(actor, session.SessionID, in)
	if err != nil {
		t.Fatal(err)
	}
	warmGrant, err := service.Decide(admin, warmRequest.ID, consent.AllowSession)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.Revoke(admin, warmGrant.ID); err != nil {
		t.Fatal(err)
	}
	op, err := scheduler.StartPlan(actor, session.SessionID, model.Plan{SchemaVersion: 1, Steps: []model.Step{step}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(10 * time.Second):
		t.Fatal("realEndly callback didnotadmitconsent")
	}
	type revoked struct {
		state consent.RevocationState
		err   error
	}
	stopped := make(chan revoked, 1)
	go func() { state, err := service.Revoke(admin, grant.ID); stopped <- revoked{state, err} }()
	select {
	case <-released:
	case <-time.After(5 * time.Second):
		t.Fatal("humanrevoke blocked execution cancellation/release")
	}
	select {
	case result := <-stopped:
		if result.err != nil || result.state != consent.Requested {
			t.Fatalf("revoke %+v", result)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("revocationDB didnotresumeafterexecutionreleased")
	}
	if !<-nestedDenied {
		t.Fatal("nestedauthorization escaped requestedrevocation")
	}
	wait, cancel := context.WithTimeout(actor, 5*time.Second)
	defer cancel()
	finished, err := scheduler.Wait(wait, session.SessionID, op.ID)
	if err != nil || finished.Status != "failed" {
		t.Fatalf("cancelledexecution %+v %v", finished, err)
	}
	defer builder.Close(context.Background())
	defer scheduler.Close(actor, session.SessionID)
	state, err := service.Revoke(admin, grant.ID)
	if err != nil || state != consent.Stopping {
		t.Fatalf("stopping %s %v", state, err)
	}
	state, err = service.Revoke(admin, grant.ID)
	if err != nil || state != consent.Revoked {
		t.Fatalf("cleanrevocation %s %v", state, err)
	}
}

func TestAuthorizeRechecksInhibitionAfterGeneratedLookup(t *testing.T) {
	f := newFixture(t)
	grant := grant(t, f, consent.AllowSession)
	lookupStarted := make(chan struct{})
	continueLookup := make(chan struct{})
	var once sync.Once
	options := f.options
	originalPolicy := options.Policy
	options.Policy = func(ctx context.Context, client consent.Client, scope consent.Scope, modes []consent.Mode, duration int) error {
		// Policy runs after the generated reader has returned an active record.
		// Revocation can commit while that earlier admission record is still local.
		if ctx.Value(authorizeLookupKey{}) == true {
			once.Do(func() { close(lookupStarted); <-continueLookup })
		}
		return originalPolicy(ctx, client, scope, modes, duration)
	}
	service, err := consent.New(options)
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan *consent.Lease, 1)
	go func() {
		lease, _ := service.Authorize(context.WithValue(f.client, authorizeLookupKey{}, true), operation(grant))
		result <- lease
	}()
	<-lookupStarted
	if _, err = service.Revoke(f.admin, grant.ID); err != nil {
		t.Fatal(err)
	}
	close(continueLookup)
	select {
	case lease := <-result:
		if lease != nil {
			lease.Release()
			t.Fatal("lookup raced past revocation")
		}
	case <-time.After(time.Second):
		t.Fatal("authorization didnotcomplete")
	}
}

type authorizeLookupKey struct{}
