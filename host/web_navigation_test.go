package host

import (
	"context"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
	"testing"
)

func TestWebNavigationIndependentlyAuthorizesDestination(t *testing.T) {
	for _, allowDestination := range []bool{false, true} {
		t.Run(map[bool]string{false: "sourceOnly", true: "both"}[allowDestination], func(t *testing.T) {
			f := newWebControlFixture(t)
			plan, err := script.Compile(`web.tab(origin: "https://fixture.test").navigate("https://destination.test/next")`)
			if err != nil {
				t.Fatal(err)
			}
			f.step = plan.Steps[0]
			f.ready.Actions = append(f.ready.Actions, "browser.navigate")
			destinations := 0
			f.manager.options.Authorize = func(ctx context.Context, p auth.Principal, s model.Surface) (*consent.Lease, error) {
				if s.Origin == "https://destination.test" {
					destinations++
					if !allowDestination {
						return nil, auth.ErrUnauthorized
					}
				}
				return &consent.Lease{Context: ctx, Release: func() {}}, nil
			}
			withWebExecution(t, f, func(ctx context.Context, p auth.Principal, step model.Step) {
				prepared, epoch, err := f.manager.Prepare(ctx, p, step)
				if err != nil {
					t.Error(err)
					return
				}
				scoped, _ := data.WithScope(prepared, data.Scope{Namespace: p.Namespace, LeaseEpoch: epoch})
				result, err := f.manager.Execute(scoped, p, step, nil)
				if destinations != 1 {
					t.Error("destination consent omitted")
				}
				if !allowDestination && (err == nil || f.dispatches != 0 || result.DispatchState != "notDispatched") {
					t.Error("source-only consent authorized destination")
				}
				if allowDestination && (err != nil || f.dispatches != 1 || result.VerificationState != "unknown") {
					t.Error("qualified navigation failed", err)
				}
			})
		})
	}
}
