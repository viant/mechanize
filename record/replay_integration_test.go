package record_test

import (
	"context"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/record"
	"sync"
	"testing"
	"time"
)

func TestRecordedParameterizedExportExecutesThroughEndlyWithoutClaimingBusinessSuccess(t *testing.T) {
	surface := model.Surface{Kind: "web", Origin: "https://fixture.test", TabID: "profile/browser/7"}
	captured := "CAPTURED_VALUE_MUST_NOT_REPLAY"
	event := record.RecordEvent{EventSurface: "web", RecordingID: "recorded-fixture", Sequence: 1, Kind: "fill", Origin: surface.Origin, Identity: &chrome.Identity{ProfileChannel: "profile", BrowserInstance: "browser", TabID: 7, DocumentID: "recorded-document", Generation: 1}, Locator: &chrome.Locator{Strategy: "testId", Value: "customer", Exact: true}, Source: "chromeDOM", Trusted: true, SourceAttested: true, SelectorConfidence: "high", Lineage: "fixture-event", Value: &captured, Redacted: true}
	exported, err := (record.Compiler{}).Compile(record.Request{Name: "parameterized recording", Surface: surface, Reviewed: true, Inputs: map[string]model.InputDefinition{"customer": {Type: model.StringValue, Required: true, Sensitive: true}}, Parameters: map[uint64]string{1: "customer"}}, []record.RecordEvent{event}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(exported.Plan.Steps) != 1 {
		t.Fatal("recorded step missing")
	}
	p, err := auth.NewPrincipal("fixture", "", "recording-replay", []string{"desktop:control"})
	if err != nil {
		t.Fatal(err)
	}
	p.ClientID = "fixture-client"
	ctx := auth.WithPrincipal(context.Background(), p)
	var mu sync.Mutex
	seen := []string{}
	runtime, err := integration.New(func(callCtx context.Context, actor auth.Principal, step model.Step, values map[string]model.Value) (integration.StepResult, error) {
		actual, err := auth.FromContext(callCtx)
		if err != nil || actual.Namespace != p.Namespace || actor.ClientID != p.ClientID {
			t.Fatal("execution actor lost")
		}
		if step.Action != "element.fill" || step.Target.Locator.Value.String != "customer" || step.Effect.BusinessKey["recording"].String != "recorded-fixture" {
			t.Fatal("export contract changed")
		}
		value, err := model.ResolveValue(step.Arguments["value"], values)
		if err != nil {
			return integration.StepResult{}, err
		}
		if value.String == captured {
			t.Fatal("captured text replayed")
		}
		mu.Lock()
		seen = append(seen, value.String)
		mu.Unlock()
		return integration.StepResult{DispatchState: "dispatched", VerificationState: "verified"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	session, err := runtime.Open(ctx, "recorded export fixture")
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close(ctx, session.SessionID)
	if _, err := runtime.StartPlan(ctx, session.SessionID, exported.Plan, nil); err == nil {
		t.Fatal("missing required replacement input accepted")
	}
	if _, err := runtime.StartPlan(ctx, session.SessionID, exported.Plan, map[string]model.Value{"customer": {Kind: model.NumberValue, Number: 7}}); err == nil {
		t.Fatal("incorrect required input type accepted")
	}
	for _, value := range []string{"replacement-one", "replacement-two"} {
		operation, err := runtime.StartPlan(ctx, session.SessionID, exported.Plan, map[string]model.Value{"customer": {Kind: model.StringValue, String: value}})
		if err != nil {
			t.Fatal(err)
		}
		wait, cancel := context.WithTimeout(ctx, 5*time.Second)
		_, err = runtime.Wait(wait, session.SessionID, operation.ID)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		result, err := runtime.Result(ctx, session.SessionID, operation.ID)
		if err != nil || result.BusinessStatus != "unverified" {
			t.Fatal("execution promoted to business success", err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 2 || seen[0] != "replacement-one" || seen[1] != "replacement-two" {
		t.Fatal("Endly did not execute changed inputs exactly once", seen)
	}
}
