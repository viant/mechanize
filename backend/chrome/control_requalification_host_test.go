//go:build mechanize_integration

package chrome_test

import (
	"context"
	"fmt"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/host"
	automation "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
	"strings"
	"testing"
	"time"
)

func TestHostAbandonsFailedRequalificationThroughRealGateway(t *testing.T) {
	for _, stale := range []bool{true, false} {
		t.Run(fmt.Sprint(stale), func(t *testing.T) {
			g, ctx, _, surface, makeStale, retained, stats := chrome.ControlRequalificationFixtureForTest(t)
			ctx = auth.WithConsentBinding(ctx, auth.ConsentBinding{GrantID: "fixture-grant", SessionID: "fixture-session", Purpose: "synthetic control cleanup"})
			profile := host.WebControlProfile{ProfileChannel: "p1", BrowserInstance: "b1", ExtensionOrigin: "chrome-extension://" + strings.Repeat("a", 32) + "/", Origins: []string{surface.Origin}}
			records, dispatches, retirements := 0, 0, 0
			options := host.WebControlProviderForIntegration(g, func(context.Context, auth.Principal) error { records++; return nil })
			options.Owner = context.Background()
			options.Enrolled = func(context.Context, auth.Principal) (host.WebControlScope, error) {
				return host.WebControlScope{Profiles: []host.WebControlProfile{profile}}, nil
			}
			options.Authorize = func(c context.Context, p auth.Principal, s model.Surface) (*consent.Lease, error) {
				return &consent.Lease{Context: c, Release: func() {}}, nil
			}
			retire := options.Retire
			options.Retire = func(c context.Context, p auth.Principal, a host.WebControlAuthority) (host.WebControlCleanup, error) {
				retirements++
				return retire(c, p, a)
			}
			execute := options.ExecutePinned
			options.ExecutePinned = func(c context.Context, p auth.Principal, step model.Step, v map[string]model.Value, a host.WebControlAuthority) (automation.StepResult, error) {
				dispatches++
				return execute(c, p, step, v, a)
			}
			manager, e := host.NewWebControlManager(*options)
			if e != nil {
				t.Fatal(e)
			}
			plan, e := script.Compile(`web.tab(origin:"https://fixture.test").getById("save",exact:true).click()`)
			if e != nil {
				t.Fatal(e)
			}
			runtime, e := automation.New(func(c context.Context, p auth.Principal, step model.Step, _ map[string]model.Value) (automation.StepResult, error) {
				prepared, epoch, e := manager.Prepare(c, p, step)
				if e != nil {
					return automation.StepResult{}, e
				}
				scoped, e := data.WithScope(prepared, data.Scope{Namespace: p.Namespace, LeaseEpoch: epoch})
				if e != nil {
					return automation.StepResult{}, e
				}
				if stale {
					makeStale()
				}
				result, e := manager.Execute(scoped, p, step, nil)
				expectedState, expectedDispatches := "dispatched", 1
				if stale {
					expectedState = "notDispatched"
					expectedDispatches = 0
				}
				acquires, inputs := stats()
				if (e != nil) != stale || result.DispatchState != expectedState || retirements != 1 || dispatches != expectedDispatches || records != 0 || acquires != 1 || inputs != int64(expectedDispatches) {
					t.Error("original pin was re-admitted or cleanup/dispatch failed", e, acquires, inputs)
				}
				_, fresh, e := manager.Prepare(c, p, step)
				if e != nil || fresh <= epoch || !retained() {
					t.Error("fresh real gateway remained busy or history changed", fresh, e)
				}
				if e = manager.Close(c); e != nil {
					t.Error("fresh prepared pin failed Close", e)
				}
				return automation.StepResult{DispatchState: "notDispatched", VerificationState: "verified"}, nil
			})
			if e != nil {
				t.Fatal(e)
			}
			session, e := runtime.Open(ctx, "joined gateway fixture")
			if e != nil {
				t.Fatal(e)
			}
			defer runtime.Close(ctx, session.SessionID)
			operation, e := runtime.StartPlan(ctx, session.SessionID, *plan, nil)
			if e != nil {
				t.Fatal(e)
			}
			deadline, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			completed, e := runtime.Wait(deadline, session.SessionID, operation.ID)
			if e != nil || completed.Status != "succeeded" {
				t.Fatal("joined callback failed", completed, e)
			}
			expectedDispatches := 1
			if stale {
				expectedDispatches = 0
			}
			if retirements != 2 || dispatches != expectedDispatches || records != 0 || !retained() {
				t.Fatal("fixture did not exercise guarded cleanup")
			}
		})
	}
}
