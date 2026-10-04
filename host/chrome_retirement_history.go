package host

import (
	"context"
	"github.com/viant/datly/exec"
	"github.com/viant/datly/spec"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data"
	bindings "github.com/viant/mechanize/data/chromeattemptbindinglist"
	"github.com/viant/mechanize/data/loadplan"
)

// collectChromeRetirementHistory obtains binding graphs and original plans only
// through generated components while the lifecycle invoker holds admission.
func collectChromeRetirementHistory(ctx context.Context, p auth.Principal, fence ChromeRetirementFence, manifests []data.ChromeRetirementManifest, invoke committedComponentInvoker) (string, error) {
	a, err := data.RequireChromeRetirementAuthority(ctx)
	if err != nil || invoke == nil || a.Namespace != p.Namespace || a.ClientID != p.ClientID || a.ProfileChannel != fence.ProfileChannel || a.BrowserInstance != fence.BrowserInstance || a.OldBrokerEpoch != fence.BrokerEpoch || a.OldChannelEpoch != fence.ChannelEpoch || a.OldScopeHash != fence.ScopeHash {
		return "", errRetirementMatch
	}
	call := func(pkg, name string, input any) (any, error) {
		return invoke(ctx, p, exec.ComponentRequest{Target: exec.ComponentTarget{Component: spec.Key{Kind: spec.KindComponent, Scope: "github.com/viant/mechanize/data/" + pkg, Name: name}, Route: spec.RouteRef{Method: "GET", Path: "/internal/data/" + pkg}}, Input: input})
	}
	in := &bindings.ListChromeAttemptBindingsInput{}
	in.SetNamespace(p.Namespace)
	in.SetClientID(p.ClientID)
	in.SetProfileChannel(fence.ProfileChannel)
	in.SetBrowserInstance(fence.BrowserInstance)
	in.SetBrokerEpoch(fence.BrokerEpoch)
	in.SetChannelEpoch(fence.ChannelEpoch)
	in.SetScopeHash(fence.ScopeHash)
	value, err := call("chromeattemptbindinglist", "ListChromeAttemptBindings", in)
	if err != nil {
		return "", errRetirementMatch
	}
	rows, ok := value.(*bindings.ListChromeAttemptBindingsOutput)
	if !ok || rows == nil || len(rows.Data) >= 65 {
		return "", errRetirementMatch
	}
	// Reject uncorrelated rows before using their identifiers for further reads.
	if _, err = MatchChromeRetirementBindings(p, fence, manifests, rows.Data); err != nil {
		return "", err
	}
	plans := map[string]*loadplan.PlanRevision{}
	for _, row := range rows.Data {
		if _, exists := plans[*row.PlanId]; exists {
			continue
		}
		request := &loadplan.LoadPlanInput{}
		request.SetNamespace(p.Namespace)
		request.SetPlanID(*row.PlanId)
		value, err = call("loadplan", "LoadPlan", request)
		if err != nil {
			return "", errRetirementMatch
		}
		out, ok := value.(*loadplan.LoadPlanOutput)
		if !ok || out == nil || len(out.Data) != 1 || out.Data[0] == nil {
			return "", errRetirementMatch
		}
		plans[*row.PlanId] = out.Data[0]
	}
	if _, err = data.RequireChromeRetirementAuthority(ctx); err != nil {
		return "", errRetirementMatch
	}
	return MatchChromeRetirementHistory(p, fence, manifests, rows.Data, plans)
}
