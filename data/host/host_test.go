package host

import (
	"context"
	"github.com/viant/datly/exec"
	"github.com/viant/datly/spec"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/data/beginattempt"
	"github.com/viant/mechanize/data/commitoutcome"
	"github.com/viant/mechanize/data/createrun"
	"github.com/viant/mechanize/data/publishplan"
	"github.com/viant/xdatly/handler"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestGeneratedPlanCommitAndNamespaceIsolation(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	source := filepath.Clean(filepath.Join(filepath.Dir(file), "../.."))
	scope := data.Scope{Namespace: strings.Repeat("a", 64), LeaseEpoch: 1}
	ctx, err := data.WithScope(context.Background(), scope)
	if err != nil {
		t.Fatal(err)
	}
	server, err := Open(ctx, source, t.TempDir(), scope)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Shutdown(context.Background())
	ptr := func(value string) *string { return &value }
	row := &publishplan.PlanRevision{}
	row.SetNamespace(ptr(scope.Namespace))
	row.SetId(ptr("p1"))
	row.SetObjectiveId(ptr("objective"))
	row.SetContentHash(ptr("hash"))
	row.SetContentJson(ptr(`{"steps":[]}`))
	row.SetCreatedAt(ptr("2026-10-01T00:00:00Z"))
	input := &publishplan.PublishPlanRevisionInput{}
	input.SetNamespace(scope.Namespace)
	input.SetPublishPlanRevision([]*publishplan.PlanRevision{row})
	var outcome handler.Outcome
	target := exec.ComponentTarget{Component: spec.Key{Kind: spec.KindComponent, Scope: "github.com/viant/mechanize/data/publishplan", Name: "PublishPlanRevision"}, Route: spec.RouteRef{Method: "POST", Path: "/internal/data/publishplan"}}
	_, err = server.InvokeComponent(ctx, exec.ComponentRequest{Target: target, Input: input, Completion: func(actual handler.Outcome) { outcome = actual }})
	if err != nil {
		t.Fatal(err)
	}
	if !outcome.CommitConfirmed() {
		t.Fatalf("not durable: %+v", outcome)
	}
	number := func(v int) *int { return &v }
	run := &createrun.Run{}
	run.SetNamespace(ptr(scope.Namespace))
	run.SetId(ptr("r1"))
	run.SetPlanId(ptr("p1"))
	run.SetStatus(ptr("running"))
	run.SetRevision(number(1))
	run.SetCreatedAt(ptr("now"))
	run.SetUpdatedAt(ptr("now"))
	create := &createrun.CreateRunInput{}
	create.SetNamespace(scope.Namespace)
	create.SetCreateRun([]*createrun.Run{run})
	invoke := func(pkg, name, method string, input any) (any, error) {
		return server.InvokeComponent(ctx, exec.ComponentRequest{Target: exec.ComponentTarget{Component: spec.Key{Kind: spec.KindComponent, Scope: "github.com/viant/mechanize/data/" + pkg, Name: name}, Route: spec.RouteRef{Method: method, Path: "/internal/data/" + pkg}}, Input: input, Completion: func(v handler.Outcome) { outcome = v }})
	}
	if _, err = invoke("createrun", "CreateRun", "POST", create); err != nil {
		t.Fatal(err)
	}
	a := &beginattempt.Attempt{}
	a.SetNamespace(ptr(scope.Namespace))
	a.SetId(ptr("a1"))
	a.SetRunId(ptr("r1"))
	a.SetPlanId(ptr("p1"))
	a.SetStepId(ptr("s1"))
	a.SetLeaseEpoch(number(1))
	a.SetState(ptr("intent"))
	a.SetCreatedAt(ptr("now"))
	intent := &beginattempt.Intent{}
	intent.SetNamespace(ptr(scope.Namespace))
	intent.SetId(ptr("e1"))
	intent.SetAttemptId(ptr("a1"))
	intent.SetRunId(ptr("r1"))
	intent.SetBusinessKey(ptr("key"))
	intent.SetState(ptr("intent"))
	intent.SetRevision(number(1))
	a.SetIntents([]*beginattempt.Intent{intent})
	event := &beginattempt.Event{}
	event.SetNamespace(ptr(scope.Namespace))
	event.SetId(ptr("ev1"))
	event.SetRunId(ptr("r1"))
	event.SetAttemptId(ptr("a1"))
	event.SetSequence(number(1))
	event.SetKind(ptr("intent"))
	event.SetPayloadJson(ptr("{}"))
	event.SetCreatedAt(ptr("now"))
	a.SetEvents([]*beginattempt.Event{event})
	beginRun := &beginattempt.Run{}
	beginRun.SetNamespace(ptr(scope.Namespace))
	beginRun.SetId(ptr("r1"))
	beginRun.SetRevision(number(1))
	beginRun.SetUpdatedAt(ptr("later"))
	beginRun.SetAttempts([]*beginattempt.Attempt{a})
	begin := &beginattempt.BeginAttemptInput{}
	begin.SetNamespace(scope.Namespace)
	begin.SetBeginAttempt([]*beginattempt.Run{beginRun})
	if _, err = invoke("beginattempt", "BeginAttempt", "PATCH", begin); err != nil {
		t.Fatal(err)
	}
	if !outcome.CommitConfirmed() {
		t.Fatalf("intent not committed: %+v", outcome)
	}

	// An unresolved committed effect must prevent a second native dispatch.
	a.SetId(ptr("a2"))
	intent.SetId(ptr("e2"))
	intent.SetAttemptId(ptr("a2"))
	event.SetId(ptr("ev3"))
	event.SetAttemptId(ptr("a2"))
	event.SetSequence(number(3))
	beginRun.SetRevision(number(2))
	if _, err = invoke("beginattempt", "BeginAttempt", "PATCH", begin); err == nil || !strings.Contains(err.Error(), "unresolved effect") {
		t.Fatalf("unresolved guard did not hold: %v", err)
	}
	effect := &commitoutcome.Effect{}
	effect.SetNamespace(ptr(scope.Namespace))
	effect.SetId(ptr("e1"))
	effect.SetAttemptId(ptr("a1"))
	effect.SetRunId(ptr("r1"))
	effect.SetRevision(number(1))
	effect.SetState(ptr("confirmed"))
	effect.SetEvidenceJson(ptr("{}"))
	resultEvent := &commitoutcome.Event{}
	resultEvent.SetNamespace(ptr(scope.Namespace))
	resultEvent.SetId(ptr("ev2"))
	resultEvent.SetRunId(ptr("r1"))
	resultEvent.SetAttemptId(ptr("a1"))
	resultEvent.SetSequence(number(2))
	resultEvent.SetKind(ptr("outcome"))
	resultEvent.SetPayloadJson(ptr("{}"))
	resultEvent.SetCreatedAt(ptr("now"))
	effect.SetEvents([]*commitoutcome.Event{resultEvent})
	commit := &commitoutcome.CommitOutcomeInput{}
	commit.SetNamespace(scope.Namespace)
	commit.SetCommitOutcome([]*commitoutcome.Effect{effect})
	if _, err = invoke("commitoutcome", "CommitOutcome", "PATCH", commit); err != nil {
		t.Fatal(err)
	}
	if !outcome.CommitConfirmed() {
		t.Fatalf("outcome not committed: %+v", outcome)
	}

	foreign, _ := data.WithScope(context.Background(), data.Scope{Namespace: strings.Repeat("b", 64)})
	if _, err = server.InvokeComponent(foreign, exec.ComponentRequest{Target: target, Input: input}); err == nil {
		t.Fatal("cross-user bound input accepted")
	}
}
