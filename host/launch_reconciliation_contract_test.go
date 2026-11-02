package host

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/viant/mechanize/auth"
	native "github.com/viant/mechanize/backend/darwin"
	"github.com/viant/mechanize/engine/durable"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/objective"
)

func launchContext() durable.ReconciliationContext {
	c := quitContext()
	c.Step.Action = "app.open"
	c.Step.Target.Surface.ProcessID = 0
	c.Step.Target.Surface.ProcessStartToken = ""
	c.Original.VerificationState = "unknown"
	c.Original.Value = &model.Value{Kind: model.ObjectValue, Object: map[string]model.Value{
		"bundleID":   reconciliationString(c.Step.Target.Surface.BundleID),
		"pid":        {Kind: model.NumberValue, Number: 42},
		"startToken": reconciliationString("1790000000:1"),
		"launchTime": reconciliationString("kernel:1790000000:1"),
		"active":     {Kind: model.BoolValue, Bool: false},
	}}
	return c
}

func TestLaunchReconciliationRequiresOriginalReceiptAndExplicitEnrollment(t *testing.T) {
	ctx, p := reconciliationActor(t)
	resolver := nativeEffectReconciliationResolver([]string{nativeLaunchContract})
	c := launchContext()
	before, _ := json.Marshal(c)
	contract, err := resolver(ctx, p, c)
	if err != nil || contract.ID != nativeLaunchContract || contract.Predicate.Scope.Target.Surface.ProcessID != 42 {
		t.Fatalf("contract %+v: %v", contract, err)
	}
	contract.Predicate.Scope.Target.Surface.ProcessID = 77
	contract.Predicate.Inputs["processStartToken"] = reconciliationString("2:2")
	after, _ := json.Marshal(c)
	if string(before) != string(after) {
		t.Fatal("original launch evidence mutated")
	}
	if _, err = nativeEffectReconciliationResolver(nil)(ctx, p, c); err == nil || !strings.Contains(err.Error(), "not enrolled") {
		t.Fatalf("unenrolled launch: %v", err)
	}
	for _, tc := range []struct {
		name   string
		change func(*durable.ReconciliationContext)
	}{
		{"lost reply", func(c *durable.ReconciliationContext) { c.Original.Value = nil }},
		{"wrong bundle", func(c *durable.ReconciliationContext) {
			c.Original.Value.Object["bundleID"] = reconciliationString("com.foreign.app")
		}},
		{"missing birth", func(c *durable.ReconciliationContext) { delete(c.Original.Value.Object, "startToken") }},
		{"invalid birth", func(c *durable.ReconciliationContext) {
			c.Original.Value.Object["startToken"] = reconciliationString("invalid")
		}},
		{"wrong launch time", func(c *durable.ReconciliationContext) {
			c.Original.Value.Object["launchTime"] = reconciliationString("kernel:1:1")
		}},
		{"zero pid", func(c *durable.ReconciliationContext) {
			c.Original.Value.Object["pid"] = model.Value{Kind: model.NumberValue}
		}},
		{"extra receipt field", func(c *durable.ReconciliationContext) { c.Original.Value.Object["extra"] = reconciliationString("x") }},
		{"not dispatched", func(c *durable.ReconciliationContext) { c.Original.DispatchState = "notDispatched" }},
		{"changed key", func(c *durable.ReconciliationContext) { c.BusinessKey = "changed" }},
		{"replacement predicate", func(c *durable.ReconciliationContext) {
			c.Step.Effect.Reconcile = declaredContext().Step.Effect.Reconcile
		}},
		{"prelaunch pid", func(c *durable.ReconciliationContext) {
			c.Step.Target.Surface.ProcessID = 42
			c.Step.Target.Surface.ProcessStartToken = "1790000000:1"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := launchContext()
			tc.change(&bad)
			if _, err := resolver(ctx, p, bad); err == nil {
				t.Fatal("unqualified launch adopted")
			}
		})
	}
}

type launchReconcileReader struct {
	target model.Surface
	mode   string
	reads  int
}

func (f *launchReconcileReader) Close() error { return nil }
func (f *launchReconcileReader) Call(_ context.Context, r native.Request) (native.Reply, error) {
	if r.Lease != nil {
		return native.Reply{}, errors.New("launch reconciliation acquired input lease")
	}
	reply := native.Reply{HelperEpoch: "read-only"}
	switch r.Method {
	case "doctor":
		reply.Result = json.RawMessage(`{}`)
	case "apps.list":
		f.reads++
		var params map[string]string
		if json.Unmarshal(r.Params, &params) != nil || len(params) != 1 || params["expectedApp"] != f.target.BundleID {
			return native.Reply{}, errors.New("wrong inventory scope")
		}
		app := map[string]any{"bundleID": f.target.BundleID, "pid": f.target.ProcessID, "startToken": f.target.ProcessStartToken, "launchTime": "kernel:" + f.target.ProcessStartToken}
		if f.mode == "wrong birth" {
			app["startToken"] = "1:1"
		}
		if f.mode == "wrong bundle" {
			app["bundleID"] = "com.foreign.app"
		}
		apps := []map[string]any{app}
		if f.mode == "exited" {
			apps = nil
		}
		if f.mode == "duplicate" {
			apps = append(apps, app)
		}
		reply.Result, _ = json.Marshal(map[string]any{"complete": f.mode != "incomplete", "apps": apps})
	default:
		return native.Reply{}, errors.New("unexpected mutation or read: " + r.Method)
	}
	return reply, nil
}

func TestLaunchRecoveryChecksReceiptedBirthWithoutReplayingLaunch(t *testing.T) {
	for _, mode := range []string{"running", "exited", "incomplete", "wrong birth", "wrong bundle", "duplicate"} {
		t.Run(mode, func(t *testing.T) {
			ctx, p := reconciliationActor(t)
			c := launchContext()
			contract, err := nativeEffectReconciliationResolver([]string{nativeLaunchContract})(ctx, p, c)
			if err != nil {
				t.Fatal(err)
			}
			fixture := &launchReconcileReader{target: contract.Predicate.Scope.Target.Surface, mode: mode}
			reader, err := native.NewReadOnlyCaller(fixture, func(context.Context) (native.Caller, error) { t.Fatal("unexpected restart"); return nil, nil })
			if err != nil {
				t.Fatal(err)
			}
			gateway, err := native.NewGateway(reader, native.GatewayOptions{AllowedBundles: []string{fixture.target.BundleID}})
			if err != nil {
				t.Fatal(err)
			}
			defer gateway.Close()
			adapter, err := objective.NewNativeProcessRunning(func(ctx context.Context, p auth.Principal, s model.Surface) (bool, objective.NativeEvidence, error) {
				proof, err := gateway.ProcessRunning(ctx, p, s)
				return proof.Running, objective.NativeEvidence{HelperEpoch: proof.HelperEpoch, TargetRef: proof.TargetRef, ObservedAt: proof.ObservedAt}, err
			})
			if err != nil {
				t.Fatal(err)
			}
			evaluator, err := objective.New(map[string]objective.Enrollment{"nativeLaunchProcess": adapter.Enrollment()})
			if err != nil {
				t.Fatal(err)
			}
			result, err := evaluator.Evaluate(ctx, p, contract.Predicate, c.Values)
			want := objective.Unknown
			if mode == "running" {
				want = objective.True
			}
			if mode == "exited" || mode == "wrong birth" || mode == "wrong bundle" || mode == "duplicate" {
				want = objective.False
			}
			if err != nil || result.Truth != want || fixture.reads != 1 {
				t.Fatalf("result %+v err=%v reads=%d", result, err, fixture.reads)
			}
			if objective.RequireBusinessSuccess(result) == nil {
				t.Fatal("liveness became business success")
			}
		})
	}
}
