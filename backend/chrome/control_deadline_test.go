package chrome

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
)

func TestBoundControlCarriesDeclaredTimeoutIntoTransportCommit(t *testing.T) {
	g, p, ctx, count := controlFixtureVersion(t, 2)
	surface := model.Surface{Kind: "web", Origin: "https://fixture.test"}
	a, err := g.AdmitControl(ctx, p, surface)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := script.Compile(`web.tab(origin: "https://fixture.test").activateTab()`)
	if err != nil {
		t.Fatal(err)
	}
	step := plan.Steps[0]
	step.TimeoutMs = 1000
	started := time.Now()
	commits := 0
	result, err := g.ExecuteControlBound(ctx, p, step, nil, a, strings.Repeat("e", 64), func(held context.Context, _ auth.Principal, _ BoundMutation) (BindingCommit, error) {
		commits++
		deadline, ok := held.Deadline()
		if !ok || deadline.After(started.Add(1100*time.Millisecond)) || !deadline.After(started) {
			t.Fatal("transport inherited generic RPC deadline", deadline, ok)
		}
		return BindingCommit{BindingID: strings.Repeat("c", 64), CommitConfirmed: true, ReadbackMatched: true}, nil
	})
	if err != nil || result.DispatchState != "dispatched" || commits != 1 || count.Load() != 1 {
		t.Fatal(result, err, commits, count.Load())
	}
}
