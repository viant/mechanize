package beginattempt

import (
	"context"
	"testing"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data"
	xhandler "github.com/viant/xdatly/handler"
)

func TestBeginAttemptPreviousEffectsGuardChecksStateAndScope(t *testing.T) {
	p, _ := auth.NewPrincipal("fixture:issuer", "", "intent-guard", nil)
	ctx, err := data.WithScope(context.Background(), data.Scope{Namespace: p.Namespace, LeaseEpoch: 1})
	if err != nil {
		t.Fatal(err)
	}
	pointer := func(value string) *string { return &value }
	run := &Run{}
	run.SetNamespace(pointer(p.Namespace))
	run.SetId(pointer("run"))
	revision := 1
	run.SetRevision(&revision)
	run.SetAttempts([]*Attempt{{}})
	for _, test := range []struct {
		name   string
		rows   []*UnresolvedEffect
		reject bool
	}{
		{"initial", nil, false},
		{"resolved historical absence", []*UnresolvedEffect{{Namespace: pointer(p.Namespace), RunId: pointer("run"), State: pointer("absent")}}, false},
		{"resolved historical confirmation", []*UnresolvedEffect{{Namespace: pointer(p.Namespace), RunId: pointer("run"), State: pointer("confirmed")}}, false},
		{"intent", []*UnresolvedEffect{{Namespace: pointer(p.Namespace), RunId: pointer("run"), State: pointer("intent")}}, true},
		{"unknown", []*UnresolvedEffect{{Namespace: pointer(p.Namespace), RunId: pointer("run"), State: pointer("unknown")}}, true},
		{"pending after resolved", []*UnresolvedEffect{{Namespace: pointer(p.Namespace), RunId: pointer("run"), State: pointer("confirmed")}, {Namespace: pointer(p.Namespace), RunId: pointer("run"), State: pointer("intent")}}, true},
		{"missing state", []*UnresolvedEffect{{Namespace: pointer(p.Namespace), RunId: pointer("run")}}, true},
		{"unsupported state", []*UnresolvedEffect{{Namespace: pointer(p.Namespace), RunId: pointer("run"), State: pointer("other")}}, true},
		{"foreign namespace resolved", []*UnresolvedEffect{{Namespace: pointer("foreign"), RunId: pointer("run"), State: pointer("absent")}}, true},
		{"foreign run resolved", []*UnresolvedEffect{{Namespace: pointer(p.Namespace), RunId: pointer("other-run"), State: pointer("confirmed")}}, true},
		{"missing scope", []*UnresolvedEffect{{State: pointer("absent")}}, true},
		{"nil row", []*UnresolvedEffect{nil}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			previous := &Run{Unresolved: test.rows}
			state := xhandler.LifecycleContext[Run, xhandler.NoParent, BeginAttemptOutput]{}
			state.Previous = previous
			err := RunLifecycleHooks.Validate(ctx, run, state)
			if (err != nil) != test.reject {
				t.Fatalf("guard rejection=%v want=%v: %v", err != nil, test.reject, err)
			}
		})
	}
	state := xhandler.LifecycleContext[Run, xhandler.NoParent, BeginAttemptOutput]{}
	state.Previous = &Run{}
	if err := RunLifecycleHooks.Validate(context.Background(), run, state); err == nil {
		t.Fatal("missing trusted data scope admitted intent")
	}
}

func TestBeginAttemptIngressRejectsForeignClaimsBeforeLinkCopy(t *testing.T) {
	p, _ := auth.NewPrincipal("fixture:issuer", "", "intent-ingress", nil)
	ctx, err := data.WithScope(context.Background(), data.Scope{Namespace: p.Namespace, LeaseEpoch: 1})
	if err != nil {
		t.Fatal(err)
	}
	ptr := func(value string) *string { return &value }
	fixture := func() *BeginAttemptInput {
		run := &Run{}
		run.SetNamespace(ptr(p.Namespace))
		run.SetId(ptr("run"))
		a := &Attempt{}
		a.SetId(ptr("attempt")) // other relationship fields genuinely omitted
		intent := &Intent{}
		intent.SetId(ptr("effect"))
		intent.SetRunId(ptr("run"))
		event := &Event{}
		event.SetId(ptr("event"))
		event.SetRunId(ptr("run"))
		a.SetIntents([]*Intent{intent})
		a.SetEvents([]*Event{event})
		run.SetAttempts([]*Attempt{a})
		input := &BeginAttemptInput{}
		input.SetNamespace(p.Namespace)
		input.SetBeginAttempt([]*Run{run})
		return input
	}
	if err := fixture().Init(ctx); err != nil {
		t.Fatalf("safe omitted parent-produced fields rejected: %v", err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*BeginAttemptInput)
	}{
		{"foreign root", func(i *BeginAttemptInput) { i.BeginAttempt[0].SetNamespace(ptr("foreign")) }},
		{"foreign attempt", func(i *BeginAttemptInput) { i.BeginAttempt[0].Attempts[0].SetNamespace(ptr("foreign")) }},
		{"foreign intent", func(i *BeginAttemptInput) { i.BeginAttempt[0].Attempts[0].Intents[0].SetNamespace(ptr("foreign")) }},
		{"foreign event", func(i *BeginAttemptInput) { i.BeginAttempt[0].Attempts[0].Events[0].SetNamespace(ptr("foreign")) }},
		{"other attempt run", func(i *BeginAttemptInput) { i.BeginAttempt[0].Attempts[0].SetRunId(ptr("other")) }},
		{"other intent run", func(i *BeginAttemptInput) { i.BeginAttempt[0].Attempts[0].Intents[0].SetRunId(ptr("other")) }},
		{"other event run", func(i *BeginAttemptInput) { i.BeginAttempt[0].Attempts[0].Events[0].SetRunId(ptr("other")) }},
		{"other intent attempt", func(i *BeginAttemptInput) { i.BeginAttempt[0].Attempts[0].Intents[0].SetAttemptId(ptr("other")) }},
		{"other event attempt", func(i *BeginAttemptInput) { i.BeginAttempt[0].Attempts[0].Events[0].SetAttemptId(ptr("other")) }},
		{"explicit null scope", func(i *BeginAttemptInput) { i.BeginAttempt[0].Attempts[0].SetNamespace(nil) }},
		{"explicit null derived relationship", func(i *BeginAttemptInput) { i.BeginAttempt[0].Attempts[0].Intents[0].SetAttemptId(nil) }},
		{"unproduced missing run", func(i *BeginAttemptInput) { i.BeginAttempt[0].Attempts[0].Events[0].RunId = nil }},
		{"unbounded attempts", func(i *BeginAttemptInput) {
			a := i.BeginAttempt[0].Attempts[0]
			i.BeginAttempt[0].SetAttempts([]*Attempt{a, a})
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := fixture()
			test.mutate(input)
			if err := input.Init(ctx); err == nil {
				t.Fatal("invalid raw graph admitted")
			}
		})
	}
}
