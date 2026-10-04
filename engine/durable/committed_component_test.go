package durable

import (
	"context"
	"testing"

	"github.com/viant/datly/exec"
	"github.com/viant/datly/spec"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data"
)

func TestCommittedBridgeRequiresLiveIntentHeldLockAndExactTarget(t *testing.T) {
	for _, mode := range []string{"noIntent", "noLock", "expiredLock", "revokedIntent", "maskedIntent", "otherBuilder", "otherClient", "wrongEpoch", "wrongName", "wrongRoute", "wrongMethod", "foreignComponent", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			ctx, p := privateActor(t)
			ctx, err := data.WithScope(ctx, data.Scope{Namespace: p.Namespace, LeaseEpoch: 7})
			if err != nil {
				t.Fatal(err)
			}
			b := &Builder{}
			locked, revokeLock := b.withHeldUserLock(ctx, p, &userHost{})
			defer revokeLock()
			record := data.CommittedStepIntent{Namespace: p.Namespace, ClientID: p.ClientID, RunID: "run", PlanID: "plan", StepID: "step", AttemptID: "attempt", EffectID: "effect", LeaseEpoch: 7, RunRevision: 2, SessionID: "session", OperationID: "operation"}
			active, revoke, err := data.WithCommittedStepIntent(locked, p, record)
			if err != nil {
				t.Fatal(err)
			}
			defer revoke()
			request := exec.ComponentRequest{Target: exec.ComponentTarget{Component: spec.Key{Kind: spec.KindComponent, Scope: "github.com/viant/mechanize/data/loadplan", Name: "LoadPlan"}, Route: spec.RouteRef{Method: "GET", Path: "/internal/data/loadplan"}}}
			switch mode {
			case "noIntent":
				active = locked
			case "noLock":
				active, _, err = data.WithCommittedStepIntent(ctx, p, record)
			case "expiredLock":
				revokeLock()
			case "revokedIntent":
				revoke()
			case "maskedIntent":
				active = data.WithoutCommittedStepIntent(active)
			case "otherBuilder":
				b = &Builder{}
			case "otherClient":
				p.ClientID = "other"
				active = auth.WithPrincipal(active, p)
			case "wrongEpoch":
				active, err = data.WithScope(active, data.Scope{Namespace: p.Namespace, LeaseEpoch: 8})
			case "wrongName":
				request.Target.Component.Name = "LoadRun"
			case "wrongRoute":
				request.Target.Route.Path = "/internal/data/loadrun"
			case "wrongMethod":
				request.Target.Route.Method = "POST"
			case "foreignComponent":
				request.Target.Component.Scope = "github.com/viant/mechanize/data/consentcreate"
			case "cancelled":
				var cancel context.CancelFunc
				active, cancel = context.WithCancel(active)
				cancel()
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err = b.InvokeCommittedComponent(active, p, request); err == nil || err.Error() == "committed component runtime unavailable" {
				t.Fatal("unqualified committed call accepted")
			}
		})
	}
}
