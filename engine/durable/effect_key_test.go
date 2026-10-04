package durable

import (
	"context"
	"github.com/viant/mechanize/auth"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestEffectBusinessKeyCanonicalTypedResolutionAndSecretRejection(t *testing.T) {
	plan := model.Plan{Inputs: map[string]model.InputDefinition{"case": {Type: model.StringValue}, "secret": {Type: model.StringValue, Sensitive: true}}, Bindings: []model.Binding{{Name: "derived", Value: &model.Value{Kind: model.ReferenceValue, Ref: "input.secret"}}}}
	step := model.Step{Effect: model.Effect{Class: model.ExternalNonIdempotent, BusinessKey: map[string]model.Value{"case": {Kind: model.ReferenceValue, Ref: "input.case"}, "line": {Kind: model.NumberValue, Number: 7}}}}
	values := map[string]model.Value{"input.case": {Kind: model.StringValue, String: "case-1"}, "input.secret": {Kind: model.StringValue, String: "SEEDED_SECRET"}, "binding.derived": {Kind: model.StringValue, String: "SEEDED_SECRET"}}
	canonical, err := effectBusinessKey(plan, step, values)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"case":{"kind":"string","string":"case-1"},"line":{"kind":"number","number":7}}`
	if canonical != want {
		t.Fatalf("typed entity key=%s want=%s", canonical, want)
	}
	step.Effect.BusinessKey = map[string]model.Value{"line": {Kind: model.NumberValue, Number: 7}, "case": {Kind: model.ReferenceValue, Ref: "input.case"}}
	same, err := effectBusinessKey(plan, step, values)
	if err != nil || same != canonical {
		t.Fatalf("map order changed business entity key: %s %v", same, err)
	}
	values["binding.alias"] = model.Value{Kind: model.ReferenceValue, Ref: "input.secret"}
	for _, ref := range []string{"input.secret", "binding.derived", "binding.alias", "binding.missing"} {
		step.Effect.BusinessKey = map[string]model.Value{"case": {Kind: model.ReferenceValue, Ref: ref}}
		key, err := effectBusinessKey(plan, step, values)
		if err == nil || key != "" || strings.Contains(err.Error(), "SEEDED_SECRET") {
			t.Fatalf("sensitive/unresolved key accepted or leaked: %q %v", key, err)
		}
	}
	step.Effect.BusinessKey = nil
	if _, err = effectBusinessKey(plan, step, values); err == nil || !strings.Contains(err.Error(), "JSON/YAML workflow envelope") {
		t.Fatalf("missing external key had no remediation: %v", err)
	}
	step.Effect.Class = model.IdempotentMutation
	if key, err := effectBusinessKey(plan, step, values); err != nil || key != "" {
		t.Fatalf("missing optional entity key manufactured: %q %v", key, err)
	}
}

func TestExternalEffectMissingBusinessKeyFailsBeforeIntentOrDispatch(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	p, _ := auth.NewPrincipal("fixture", "", "missing-business-key", []string{"desktop:control"})
	ctx := auth.WithPrincipal(context.Background(), p)
	calls := 0
	b, err := New(Options{SourceRoot: filepath.Clean(filepath.Join(filepath.Dir(file), "../..")), StorageRoot: t.TempDir(), LeaseEpoch: func(context.Context, auth.Principal) (int, error) { return 1, nil }}, func(context.Context, auth.Principal, model.Step, map[string]model.Value) (integration.StepResult, error) {
		calls++
		return integration.StepResult{DispatchState: "dispatched", VerificationState: "verified"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close(ctx)
	r, err := integration.NewWithOptions(b.Execute, integration.Options{PreparePlan: b.PreparePlan})
	if err != nil {
		t.Fatal(err)
	}
	session, err := r.Open(ctx, "missing entity fixture")
	if err != nil {
		t.Fatal(err)
	}
	plan, _ := script.Compile(`app("com.example.Fixture").getById("save").click()`)
	op, err := r.StartPlan(ctx, session.SessionID, *plan, nil)
	if err != nil {
		t.Fatal(err)
	}
	wait, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	finished, err := r.Wait(wait, session.SessionID, op.ID)
	if err != nil {
		t.Fatal(err)
	}
	if finished.Status != "failed" || calls != 0 || !strings.Contains(finished.Error, "effect.businessKey") {
		t.Fatalf("missing key input ran: %+v calls=%d", finished, calls)
	}
	id, err := r.RunReference(ctx, session.SessionID, op.ID)
	if err != nil {
		t.Fatal(err)
	}
	scoped, user, err := b.bound(ctx, p, 1)
	if err != nil {
		t.Fatal(err)
	}
	user.mu.Lock()
	run, err := load(scoped, user.server, p, id)
	user.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if len(run.Effects) != 0 || len(run.Attempts) != 0 {
		t.Fatal("missing entity key committed dispatch intent")
	}
}
