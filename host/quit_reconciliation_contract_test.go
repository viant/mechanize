package host

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/viant/mechanize/auth"
	native "github.com/viant/mechanize/backend/darwin"
	"github.com/viant/mechanize/engine/durable"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/objective"
)

func quitContext() durable.ReconciliationContext {
	c := extensionsContext()
	c.Step.Action = "app.quit"
	c.Step.Target = model.Selector{Surface: c.Step.Target.Surface, Cardinality: "one"}
	c.Step.Arguments = nil
	c.Step.Effect.BusinessKey = map[string]model.Value{"bundleID": reconciliationString(c.Step.Target.Surface.BundleID)}
	raw, _ := json.Marshal(c.Step.Effect.BusinessKey)
	c.BusinessKey = string(raw)
	c.Original.DispatchState = "unknown"
	return c
}
func TestQuitReconciliationRequiresEnrolledImmutableOriginalIdentity(t *testing.T) {
	ctx, p := reconciliationActor(t)
	resolver := nativeEffectReconciliationResolver([]string{nativeQuitContract})
	c := quitContext()
	before, _ := json.Marshal(c)
	contract, err := resolver(ctx, p, c)
	if err != nil || contract.ID != nativeQuitContract || contract.Predicate.Adapter != "nativeProcess" {
		t.Fatalf("quit contract %+v %v", contract, err)
	}
	contract.Predicate.Inputs["processStartToken"] = reconciliationString("1:1")
	contract.Predicate.Scope.Target.Surface.ProcessID = 99
	after, _ := json.Marshal(c)
	if string(before) != string(after) {
		t.Fatal("original plan mutated")
	}
	if _, err := nativeEffectReconciliationResolver([]string{declaredEffectReconciliationContract})(ctx, p, c); err == nil {
		t.Fatal("quit adopted without explicit enrollment")
	}
	for _, change := range []func(*durable.ReconciliationContext){
		func(c *durable.ReconciliationContext) { c.Step.Action = "app.activate" },
		func(c *durable.ReconciliationContext) {
			c.Step.Target.Surface.ProcessID = 0
			c.Step.Target.Surface.ProcessStartToken = ""
		},
		func(c *durable.ReconciliationContext) { c.Step.Target.Surface.ProcessStartToken = "invalid" },
		func(c *durable.ReconciliationContext) { c.BusinessKey = "changed" },
		func(c *durable.ReconciliationContext) {
			c.Step.Effect.Reconcile = declaredContext().Step.Effect.Reconcile
		},
	} {
		bad := quitContext()
		change(&bad)
		if _, err := resolver(ctx, p, bad); err == nil {
			t.Fatal("unqualified quit adopted")
		}
	}
}

type quitReconcileReader struct {
	target                          model.Surface
	exited, unavailable, wrongBirth bool
	reads                           int
}

func (f *quitReconcileReader) Close() error { return nil }
func (f *quitReconcileReader) Call(_ context.Context, r native.Request) (native.Reply, error) {
	if r.Lease != nil {
		return native.Reply{}, errors.New("reconciliation acquired control lease")
	}
	reply := native.Reply{HelperEpoch: "readonly-epoch"}
	switch r.Method {
	case "doctor":
		reply.Result = json.RawMessage(`{"supportedMethods":["app.exitStatus"]}`)
	case "app.exitStatus":
		f.reads++
		var params struct {
			ExpectedApp string `json:"expectedApp"`
			PID         int    `json:"pid"`
			Token       string `json:"startToken"`
			Launch      string `json:"launchTime"`
		}
		if json.Unmarshal(r.Params, &params) != nil || params.ExpectedApp != f.target.BundleID || params.PID != f.target.ProcessID || params.Token != f.target.ProcessStartToken || params.Launch != "kernel:"+f.target.ProcessStartToken {
			return native.Reply{}, errors.New("changed original process")
		}
		token := f.target.ProcessStartToken
		if f.wrongBirth {
			token = "1:1"
		}
		reply.Result, _ = json.Marshal(map[string]any{"bundleID": f.target.BundleID, "pid": f.target.ProcessID, "startToken": token, "launchTime": "kernel:" + f.target.ProcessStartToken, "observationAvailable": !f.unavailable, "exitConfirmed": f.exited})
	default:
		return native.Reply{}, errors.New("reconciliation attempted non-exit method: " + r.Method)
	}
	return reply, nil
}
func TestDelayedQuitReconciliationReadsOriginalExitWithoutReplay(t *testing.T) {
	for _, mode := range []string{"delayed exit", "unsaved dialog", "unavailable", "wrong birth"} {
		t.Run(mode, func(t *testing.T) {
			ctx, p := reconciliationActor(t)
			c := quitContext()
			before, _ := json.Marshal(c)
			contract, err := nativeEffectReconciliationResolver([]string{nativeQuitContract})(ctx, p, c)
			if err != nil {
				t.Fatal(err)
			}
			fixture := &quitReconcileReader{target: c.Step.Target.Surface}
			reader, err := native.NewReadOnlyCaller(fixture, func(context.Context) (native.Caller, error) { t.Fatal("unexpected helper restart"); return nil, nil })
			if err != nil {
				t.Fatal(err)
			}
			gateway, err := native.NewGateway(reader, native.GatewayOptions{AllowedBundles: []string{c.Step.Target.Surface.BundleID}})
			if err != nil {
				t.Fatal(err)
			}
			defer gateway.Close()
			adapter, err := objective.NewNativeProcessExit(func(ctx context.Context, p auth.Principal, s model.Surface) (bool, objective.NativeEvidence, error) {
				proof, err := gateway.ProcessExit(ctx, p, s)
				return proof.ExitConfirmed, objective.NativeEvidence{HelperEpoch: proof.HelperEpoch, TargetRef: proof.TargetRef, ObservedAt: proof.ObservedAt}, err
			})
			if err != nil {
				t.Fatal(err)
			}
			evaluator, err := objective.New(map[string]objective.Enrollment{"nativeProcess": adapter.Enrollment()})
			if err != nil {
				t.Fatal(err)
			}
			first, err := evaluator.Evaluate(ctx, p, contract.Predicate, c.Values)
			if err != nil || first.Truth != objective.False {
				t.Fatalf("pending quit should remain unconfirmed: %+v %v", first, err)
			}
			fixture.exited = mode != "unsaved dialog"
			fixture.unavailable = mode == "unavailable"
			fixture.wrongBirth = mode == "wrong birth"
			later, err := evaluator.Evaluate(ctx, p, contract.Predicate, c.Values)
			want := objective.Unknown
			if mode == "delayed exit" {
				want = objective.True
			}
			if mode == "unsaved dialog" {
				want = objective.False
			}
			if err != nil || later.Truth != want || fixture.reads != 2 {
				t.Fatalf("late exit %+v %v, reads %d", later, err, fixture.reads)
			}
			if objective.RequireBusinessSuccess(later) == nil {
				t.Fatal("process evidence became business authority")
			}
			after, _ := json.Marshal(c)
			if string(before) != string(after) {
				t.Fatal("reconciliation rewrote original plan")
			}
		})
	}
}
