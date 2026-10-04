package endly

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
)

func TestOperationOutputsOwnedExplicitCompletedRead(t *testing.T) {
	ctx := actor(t, "outputs-owner")
	principal, _ := auth.FromContext(ctx)
	principal.ClientID = "client-a"
	ctx = auth.WithPrincipal(ctx, principal)
	runtime, err := New(func(context.Context, auth.Principal, model.Step, map[string]model.Value) (StepResult, error) {
		v := model.Value{Kind: model.ObjectValue, Object: map[string]model.Value{"answer": {Kind: model.StringValue, String: "2"}}}
		return StepResult{Value: &v}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	session, err := runtime.Open(ctx, "outputs")
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close(ctx, session.SessionID)
	plan, err := script.Compile(`let result = app("com.example.Fixture").getById("result").read("staticText")`)
	if err != nil {
		t.Fatal(err)
	}
	op, err := runtime.StartPlan(ctx, session.SessionID, *plan, map[string]model.Value{"private": {Kind: model.StringValue, String: "do-not-export"}})
	if err != nil {
		t.Fatal(err)
	}
	deadline, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if _, err = runtime.Wait(deadline, session.SessionID, op.ID); err != nil {
		t.Fatal(err)
	}
	got, err := runtime.OperationOutputs(ctx, session.SessionID, op.ID, []string{"result"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Storage != "ephemeralRuntime" || len(got.Outputs) != 1 || got.Outputs["result"].Object["answer"].String != "2" {
		t.Fatalf("bad outputs: %+v", got)
	}
	got.Outputs["result"].Object["answer"] = model.Value{Kind: model.StringValue, String: "mutated"}
	again, err := runtime.OperationOutputs(ctx, session.SessionID, op.ID, []string{"result"})
	if err != nil || again.Outputs["result"].Object["answer"].String != "2" {
		t.Fatal("snapshot aliases runtime memory")
	}
	other := principal
	other.ClientID = "client-b"
	for _, test := range []struct {
		ctx                context.Context
		session, operation string
		names              []string
	}{{auth.WithPrincipal(ctx, other), session.SessionID, op.ID, []string{"result"}}, {actor(t, "other-owner"), session.SessionID, op.ID, []string{"result"}}, {ctx, session.SessionID, "wrong-operation", []string{"result"}}, {ctx, session.SessionID, op.ID, []string{"private"}}, {ctx, session.SessionID, op.ID, nil}, {ctx, session.SessionID, op.ID, []string{"binding.result"}}} {
		if _, err = runtime.OperationOutputs(test.ctx, test.session, test.operation, test.names); err == nil {
			t.Fatal("invalid or unauthorized outputs request admitted")
		}
	}
}
func TestCaptureOutputsSensitiveBoundedAndCopied(t *testing.T) {
	r := &Runtime{}
	p := &program{plan: model.Plan{Inputs: map[string]model.InputDefinition{"credential": {Sensitive: true}}}, values: map[string]model.Value{"input.credential": {Kind: model.StringValue, String: "secret-fixture"}}}
	step := model.Step{Action: "element.read", Bind: "result"}
	for _, v := range []model.Value{{Kind: model.StringValue, String: "prefix secret-fixture suffix"}, {Kind: model.StringValue, String: strings.Repeat("x", 8193)}, {Kind: model.ReferenceValue, Ref: "input.credential"}, {Kind: model.ObjectValue, Object: map[string]model.Value{"password": {Kind: model.StringValue, String: "hidden"}}}} {
		r.captureOutput(p, step, v)
		if p.outputs["result"].reason == "" {
			t.Fatal("unsafe output retained")
		}
	}
	original := model.Value{Kind: model.ArrayValue, Array: []model.Value{{Kind: model.NumberValue, Number: 2}}}
	r.captureOutput(p, step, original)
	original.Array[0].Number = 9
	if p.outputs["result"].value.Array[0].Number != 2 {
		t.Fatal("capture aliases executor output")
	}
	for i := 0; i < 40; i++ {
		step.Bind = string(rune('a' + i))
		r.captureOutput(p, step, model.Value{Kind: model.StringValue, String: strings.Repeat("x", 8000)})
	}
	total := 0
	for _, v := range p.outputs {
		total += v.bytes
	}
	if len(p.outputs) > 32 || total > maxOperationOutputBytes {
		t.Fatal("retention not bounded")
	}
}
func TestOperationOutputsRejectRunningAndFailure(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	r, _ := New(func(context.Context, auth.Principal, model.Step, map[string]model.Value) (StepResult, error) {
		close(started)
		<-release
		return StepResult{}, context.Canceled
	})
	ctx := actor(t, "pending-output")
	session, _ := r.Open(ctx, "pending")
	defer r.Close(ctx, session.SessionID)
	plan, _ := script.Compile(`let result = app("com.example.Fixture").getById("result").read("staticText")`)
	op, err := r.StartPlan(ctx, session.SessionID, *plan, nil)
	if err != nil {
		t.Fatal(err)
	}
	<-started
	if _, err = r.OperationOutputs(ctx, session.SessionID, op.ID, []string{"result"}); err == nil || !strings.Contains(err.Error(), "successful completion required") {
		t.Fatal("pending output admitted")
	}
	close(release)
	deadline, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	r.Wait(deadline, session.SessionID, op.ID)
	if _, err = r.OperationOutputs(ctx, session.SessionID, op.ID, []string{"result"}); err == nil {
		t.Fatal("failed output admitted")
	}
}
