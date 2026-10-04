package host

import (
	"context"
	"encoding/json"
	"github.com/viant/datly/exec"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data"
	bindings "github.com/viant/mechanize/data/chromeattemptbindinglist"
	"github.com/viant/mechanize/data/loadplan"
	"github.com/viant/mechanize/model"
	"testing"
)

func TestCollectRetirementHistoryUsesScopedGeneratedReads(t *testing.T) {
	p, f, m, rows := retirementMatchFixture(t, false)
	_, a := retirementAuthorityFixture(t)
	a.Namespace = p.Namespace
	a.ClientID = p.ClientID
	a.ProfileChannel = f.ProfileChannel
	a.BrowserInstance = f.BrowserInstance
	a.OldBrokerEpoch = f.BrokerEpoch
	a.OldChannelEpoch = f.ChannelEpoch
	a.OldScopeHash = f.ScopeHash
	a.Phase = "intended"
	a.PriorRevision = 0
	a.Manifests = nil
	a.TransitionID = data.ChromeRetirementID(a.Namespace, a.ClientID, a.ProfileChannel, a.BrowserInstance, a.RequestID)
	ctx, err := data.WithScope(auth.WithPrincipal(context.Background(), p), data.Scope{Namespace: p.Namespace})
	if err != nil {
		t.Fatal(err)
	}
	ctx, err = data.WithChromeRetirementAuthority(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	plan := model.Plan{Steps: []model.Step{{ID: *rows[0].StepId, Action: "element.press"}}}
	raw, _ := json.Marshal(struct {
		Plan model.Plan `json:"plan"`
	}{plan})
	hash := data.ChromeAttemptRawDigest(string(raw))
	rows[0].PlanContentDigest = retirementValue(hash)
	rows[0].StepDigest = retirementValue(data.ChromeRetirementDigest(plan.Steps[0]))
	calls := 0
	invoke := func(ctx context.Context, actor auth.Principal, r exec.ComponentRequest) (any, error) {
		calls++
		if actor.Namespace != p.Namespace || actor.ClientID != p.ClientID || r.Target.Route.Method != "GET" {
			t.Fatal("read scope changed")
		}
		switch r.Target.Component.Name {
		case "ListChromeAttemptBindings":
			in := r.Input.(*bindings.ListChromeAttemptBindingsInput)
			if in.Namespace != p.Namespace || in.ClientID != p.ClientID || in.BrokerEpoch != f.BrokerEpoch || in.ScopeHash != f.ScopeHash {
				t.Fatal("query fence changed")
			}
			return &bindings.ListChromeAttemptBindingsOutput{Data: rows}, nil
		case "LoadPlan":
			in := r.Input.(*loadplan.LoadPlanInput)
			if in.Namespace != p.Namespace || in.PlanID != *rows[0].PlanId {
				t.Fatal("plan scope changed")
			}
			return &loadplan.LoadPlanOutput{Data: []*loadplan.PlanRevision{{Namespace: retirementValue(p.Namespace), Id: rows[0].PlanId, ContentHash: retirementValue(hash), ContentJson: retirementValue(string(raw))}}}, nil
		}
		t.Fatal("unexpected component")
		return nil, nil
	}
	if digest, err := collectChromeRetirementHistory(ctx, p, f, m, invoke); err != nil || len(digest) != 64 || calls != 2 {
		t.Fatal("generated history failed", err, calls)
	}
	f.ChannelEpoch = "changed"
	calls = 0
	if _, err = collectChromeRetirementHistory(ctx, p, f, m, invoke); err == nil || calls != 0 {
		t.Fatal("changed fence issued a read")
	}
}
