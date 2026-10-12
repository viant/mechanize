package chrome

import (
	"context"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
	"strings"
	"testing"
)

func TestBrowserActionsRequireDurableBoundProduction(t *testing.T) {
	g, p, ctx, _ := controlFixtureVersion(t, 2)
	surface := model.Surface{Kind: "web", Origin: "https://fixture.test"}
	if _, err := g.ActivateTab(ctx, p, surface, "caller-attempt"); err == nil {
		t.Fatal("raw production activation admitted")
	}
	if _, err := g.Navigate(ctx, p, surface, "https://fixture.test/next", "caller-attempt"); err == nil {
		t.Fatal("raw production navigation admitted")
	}
	a, err := g.AdmitControl(ctx, p, surface)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := script.Compile(`web.tab(origin: "https://fixture.test").activateTab()`)
	if err != nil {
		t.Fatal(err)
	}
	s := plan.Steps[0]
	if _, err := g.ExecuteControl(ctx, p, s, nil, a); err == nil {
		t.Fatal("unbound activation admitted")
	}
	calls := 0
	_, err = g.ExecuteControlBound(ctx, p, s, nil, a, strings.Repeat("a", 64), func(context.Context, auth.Principal, BoundMutation) (BindingCommit, error) {
		calls++
		return BindingCommit{}, nil
	})
	if err == nil || calls != 1 {
		t.Fatal("missing commit confirmation allowed", calls, err)
	}
	plan, err = script.Compile(`web.tab(origin: "https://fixture.test").navigate("https://fixture.test/next")`)
	if err != nil {
		t.Fatal(err)
	}
	calls = 0
	_, err = g.ExecuteControlBound(ctx, p, plan.Steps[0], nil, a, strings.Repeat("b", 64), func(context.Context, auth.Principal, BoundMutation) (BindingCommit, error) {
		calls++
		return BindingCommit{}, nil
	})
	if err == nil || calls != 0 {
		t.Fatal("origin-only navigation reached committed dispatch", calls, err)
	}
}

func TestBrowserActionFingerprintBindsURLAndNoLocator(t *testing.T) {
	cmd := Command{Action: "browser.navigate", Identity: Identity{ProfileChannel: "p", BrowserInstance: "b", TabID: 1, DocumentID: "d", Generation: 1}, BrokerEpoch: "broker", ChannelEpoch: "channel", ScopeHash: strings.Repeat("a", 64), AttemptID: strings.Repeat("b", 64), ControlLease: &Lease{ID: "lease", Generation: 1}, Args: map[string]any{"url": "https://fixture.test/one"}}
	a, err := FingerprintMutationV2(cmd)
	if err != nil {
		t.Fatal(err)
	}
	cmd.Args["url"] = "https://fixture.test/two"
	b, err := FingerprintMutationV2(cmd)
	if err != nil || a == b {
		t.Fatal("destination not fingerprint bound")
	}
	cmd.Locator = &Locator{Strategy: "id", Value: "x", Exact: true}
	if _, err := FingerprintMutationV2(cmd); err == nil {
		t.Fatal("browser locator accepted")
	}
	cmd.Locator = nil
	cmd.Action = "browser.activate"
	cmd.Args = nil
	if _, err := FingerprintMutationV2(cmd); err != nil {
		t.Fatal(err)
	}
}

func TestBoundBrowserActionsDispatchOnceAndRetireExactNavigationLease(t *testing.T) {
	for _, action := range []string{"activateTab()", `navigate("https://fixture.test/next")`} {
		t.Run(action, func(t *testing.T) {
			g, p, ctx, count := controlFixtureVersion(t, 2)
			if strings.HasPrefix(action, "navigate") {
				g.broker.mu.Lock()
				c := g.broker.channels[channelKey("p1", "b1")]
				c.grant.AllWebsites = true
				c.grant.Origins = nil
				g.broker.mu.Unlock()
			}
			surface := model.Surface{Kind: "web", Origin: "https://fixture.test"}
			a, err := g.AdmitControl(ctx, p, surface)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := script.Compile(`web.tab(origin: "https://fixture.test").` + action)
			if err != nil {
				t.Fatal(err)
			}
			commits := 0
			result, err := g.ExecuteControlBound(ctx, p, plan.Steps[0], nil, a, strings.Repeat("a", 64), func(_ context.Context, _ auth.Principal, d BoundMutation) (BindingCommit, error) {
				commits++
				if d.Action != plan.Steps[0].Action || d.ControlLease != a.Lease || d.Fingerprint.Version != 2 {
					t.Fatal("unbound descriptor")
				}
				return BindingCommit{BindingID: strings.Repeat("c", 64), CommitConfirmed: true, ReadbackMatched: true}, nil
			})
			if err != nil || result.DispatchState != "dispatched" || result.VerificationState != "unknown" || count.Load() != 1 || commits != 1 {
				t.Fatal("bound browser dispatch failed", result, err, commits, count.Load())
			}
			if strings.HasPrefix(action, "navigate") {
				g.broker.mu.Lock()
				c := g.broker.channels[channelKey("p1", "b1")]
				c.documents[0].DocumentID = "replacement-document"
				g.broker.mu.Unlock()
				if g.VerifyControl(ctx, p, a) == nil {
					t.Fatal("retired old lease still dispatches")
				}
			}
			if ok, err := g.RetireControl(ctx, p, a); err != nil || !ok {
				t.Fatal("exact proof retirement failed", err)
			}
			if _, err := g.ExecuteControlBound(ctx, p, plan.Steps[0], nil, a, strings.Repeat("a", 64), func(context.Context, auth.Principal, BoundMutation) (BindingCommit, error) {
				t.Fatal("replayed commit")
				return BindingCommit{}, nil
			}); err == nil {
				t.Fatal("retired attempt replayed")
			}
		})
	}
}
