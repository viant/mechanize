package durable

import (
	"context"
	"errors"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/data/beginattempt"
	"github.com/viant/mechanize/data/createrun"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
	"path/filepath"
	"runtime"
	"testing"
)

func TestStateComponentsCASGuardsAndIsolation(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	source := filepath.Clean(filepath.Join(filepath.Dir(file), "../.."))
	p, _ := auth.NewPrincipal("fixture:issuer", "", "alice", []string{"desktop:control"})
	ctx := auth.WithPrincipal(context.Background(), p)
	builder, err := New(Options{SourceRoot: source, StorageRoot: t.TempDir(), MaxUsers: 2, LeaseEpoch: func(context.Context, auth.Principal) (int, error) { return 1, nil }}, func(context.Context, auth.Principal, model.Step, map[string]model.Value) (integration.StepResult, error) {
		return integration.StepResult{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer builder.Close(ctx)
	plan, err := script.Compile(`app("com.example.Fixture").getById("save").click()`)
	if err != nil {
		t.Fatal(err)
	}
	plan.Bindings = append(plan.Bindings, model.Binding{Name: "summary", Type: "value", Value: &model.Value{Kind: model.StringValue, String: "initial"}})
	planID, err := builder.PreparePlan(ctx, p, "active", "session", *plan, nil)
	if err != nil {
		t.Fatal(err)
	}
	value := model.Value{Kind: model.StringValue, String: "literal ${x} $ quote\"\nline"}
	if _, err = builder.StatePatch(ctx, p, "active", 1, map[string]model.Value{"summary": value}); !errors.Is(err, ErrStatePatchUnavailable) {
		t.Fatalf("missing runtime integration: %v", err)
	}
	// This isolated fixture owns run admission. Production must supply a real
	// runtime guard that also refreshes the paused typed context before release.
	held := false
	builder.options.StateMutationGuard = func(context.Context, auth.Principal, string) (func(), error) {
		held = true
		return func() { held = false }, nil
	}
	refreshes := 0
	builder.options.RefreshVariables = func(_ context.Context, _ auth.Principal, _ string, values map[string]model.Value) error {
		if !held {
			t.Fatal("admission released before runtime refresh")
		}
		if values["summary"].String != value.String {
			t.Fatal("runtime refresh did not receive committed typed values")
		}
		refreshes++
		return nil
	}
	if _, err = builder.StatePatch(ctx, p, "active", 1, map[string]model.Value{"summary": value}); err == nil {
		t.Fatal("active run mutated")
	}
	scoped, user, err := builder.bound(ctx, p, 1)
	if err != nil {
		t.Fatal(err)
	}
	paused := &createrun.Run{}
	paused.SetNamespace(pointer(p.Namespace))
	paused.SetId(pointer("paused"))
	paused.SetPlanId(pointer(planID))
	paused.SetStatus(pointer("paused"))
	paused.SetRevision(pointer(1))
	paused.SetCreatedAt(pointer(now()))
	paused.SetUpdatedAt(pointer(now()))
	create := &createrun.CreateRunInput{}
	create.SetNamespace(p.Namespace)
	create.SetCreateRun([]*createrun.Run{paused})
	if _, err = invoke(scoped, user.server, "createrun", "CreateRun", "POST", create, true); err != nil {
		t.Fatal(err)
	}
	state, err := builder.StateGet(ctx, p, "paused")
	if err != nil {
		t.Fatal(err)
	}
	if state.Revision != 1 || len(state.Variables) != 0 {
		t.Fatalf("initial state %+v", state)
	}
	if _, err = builder.StatePatch(ctx, p, "paused", 1, map[string]model.Value{"undeclared": value}); err == nil {
		t.Fatal("undeclared plan binding mutated")
	}
	state, err = builder.StateGet(ctx, p, "paused")
	if err != nil || state.Revision != 1 || len(state.Variables) != 0 || refreshes != 0 {
		t.Fatalf("rejected binding patch changed state: %+v %v", state, err)
	}
	state, err = builder.StatePatch(ctx, p, "paused", 1, map[string]model.Value{"summary": value})
	if err != nil {
		t.Fatal(err)
	}
	if state.Revision != 2 || state.Variables["summary"].String != value.String || refreshes != 1 || held {
		t.Fatalf("typed state %+v", state)
	}
	if _, err = builder.StatePatch(ctx, p, "paused", 1, map[string]model.Value{"summary": {Kind: model.StringValue, String: "stale"}}); err == nil {
		t.Fatal("stale state revision accepted")
	}
	if _, err = builder.StatePatch(ctx, p, "paused", 2, map[string]model.Value{"effects.clear": value}); err == nil {
		t.Fatal("invalid metadata-shaped name accepted")
	}
	state, err = builder.StateGet(ctx, p, "paused")
	if err != nil || state.Revision != 2 || state.Variables["summary"].String != value.String {
		t.Fatalf("failed patch changed state %+v %v", state, err)
	}
	foreign, _ := auth.NewPrincipal("fixture:issuer", "", "bob", []string{"desktop:control"})
	foreignCtx := auth.WithPrincipal(context.Background(), foreign)
	if _, err = builder.StateGet(foreignCtx, foreign, "paused"); err == nil {
		t.Fatal("foreign user read run state")
	}
	if _, err = builder.StatePatch(foreignCtx, foreign, "paused", 2, map[string]model.Value{"summary": value}); err == nil {
		t.Fatal("foreign user wrote run state")
	}
	// Refresh failure is a truthful committed result; durable state is not rolled back.
	refreshCause := errors.New("private fixture refresh failure")
	builder.options.RefreshVariables = func(context.Context, auth.Principal, string, map[string]model.Value) error {
		if !held {
			t.Fatal("guard released before failed refresh")
		}
		return refreshCause
	}
	committed := model.Value{Kind: model.StringValue, String: "committed after refresh failure"}
	state, err = builder.StatePatch(ctx, p, "paused", 2, map[string]model.Value{"summary": committed})
	var committedErr *StatePatchCommittedError
	if !errors.As(err, &committedErr) || !errors.Is(err, refreshCause) || state.Revision != 3 || state.Variables["summary"].String != committed.String || !state.NeedsAttention || held {
		t.Fatalf("refresh failure lost committed truth: %+v %v", state, err)
	}
	if committedErr.CommittedState().Revision != 3 {
		t.Fatal("committed error lost revision")
	}
	state, err = builder.StateGet(ctx, p, "paused")
	if err != nil || state.Revision != 3 || state.Status != "paused" || state.Variables["summary"].String != committed.String || state.NeedsAttention {
		t.Fatalf("durable state changed or attention persisted as invented status: %+v %v", state, err)
	}
	// Add a real committed intent via the generated graph. Even this paused
	// fixture context must not allow state mutation across an unresolved effect.
	scoped, err = data.WithScope(ctx, data.Scope{Namespace: p.Namespace, LeaseEpoch: 1})
	if err != nil {
		t.Fatal(err)
	}
	a := &beginattempt.Attempt{}
	a.SetNamespace(pointer(p.Namespace))
	a.SetId(pointer("state-a"))
	a.SetRunId(pointer("paused"))
	a.SetPlanId(pointer(planID))
	a.SetStepId(pointer("state-step"))
	a.SetLeaseEpoch(pointer(1))
	a.SetState(pointer("intent"))
	a.SetCreatedAt(pointer(now()))
	intent := &beginattempt.Intent{}
	intent.SetNamespace(pointer(p.Namespace))
	intent.SetId(pointer("state-effect"))
	intent.SetAttemptId(pointer("state-a"))
	intent.SetRunId(pointer("paused"))
	intent.SetBusinessKey(pointer("fixture-key"))
	intent.SetState(pointer("intent"))
	intent.SetRevision(pointer(1))
	a.SetIntents([]*beginattempt.Intent{intent})
	event := &beginattempt.Event{}
	event.SetNamespace(pointer(p.Namespace))
	event.SetId(pointer("state-event"))
	event.SetRunId(pointer("paused"))
	event.SetAttemptId(pointer("state-a"))
	event.SetSequence(pointer(1))
	event.SetKind(pointer("intent"))
	event.SetPayloadJson(pointer("{}"))
	event.SetCreatedAt(pointer(now()))
	a.SetEvents([]*beginattempt.Event{event})
	run := &beginattempt.Run{}
	run.SetNamespace(pointer(p.Namespace))
	run.SetId(pointer("paused"))
	run.SetRevision(pointer(3))
	run.SetAttempts([]*beginattempt.Attempt{a})
	begin := &beginattempt.BeginAttemptInput{}
	begin.SetNamespace(p.Namespace)
	begin.SetBeginAttempt([]*beginattempt.Run{run})
	if _, err = invoke(scoped, user.server, "beginattempt", "BeginAttempt", "PATCH", begin, true); err != nil {
		t.Fatal(err)
	}
	state, err = builder.StateGet(ctx, p, "paused")
	if err != nil || state.Revision != 4 || len(state.UnresolvedEffects) != 1 {
		t.Fatalf("unresolved projection %+v %v", state, err)
	}
	if _, err = builder.TransitionRun(ctx, p, "paused", 4, "paused"); err == nil {
		t.Fatal("unresolved effect allowed safe pause transition")
	}
	if _, err = builder.StatePatch(ctx, p, "paused", 4, map[string]model.Value{"summary": value}); err == nil {
		t.Fatal("state changed across unresolved effect")
	}
}
