package chrome

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
)

func packagedSelectReply(command Command) (Reply, error) {
	_, file, _, _ := runtime.Caller(0)
	source := filepath.Clean(filepath.Join(filepath.Dir(file), "../.."))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	input, _ := json.Marshal(command)
	child := exec.CommandContext(ctx, "node", filepath.Join(source, "backend/chrome/testdata/select_content.cjs"), source)
	child.Stdin = bytes.NewReader(input)
	output, err := child.Output()
	if err != nil {
		return Reply{}, err
	}
	var reply Reply
	err = json.Unmarshal(output, &reply)
	return reply, err
}

// Actual Broker socket, Gateway bound dispatch and packaged JS fingerprint/DOM/
// content receipts. OS peer proof and durable binding acknowledgement are seams.
func TestNegotiatedSelectBoundSocketChangesPublicOptionOnce(t *testing.T) {
	g, p, ctx, count := controlFixtureVersion(t, 2, func() string { return "selectDOM" })
	caps, err := g.ControlCapabilitiesFor(ctx, p)
	if err != nil || !caps["web:selectOption"] || caps["web:checkedSet"] || caps["web:checkedClear"] || count.Load() != 0 {
		t.Fatal("select capability lacks negotiated metadata or broadens unsupported actions")
	}
	plan, err := script.Compile(`web.tab(origin:"https://fixture.test").getById("color",exact:true).select("green",timeout:3s)`)
	if err != nil {
		t.Fatal(err)
	}
	step := plan.Steps[0]
	a, err := g.AdmitControl(ctx, p, step.Target.Surface)
	if err != nil {
		t.Fatal(err)
	}
	if a.SelectOptionVersion != 1 {
		t.Fatal("authenticated hello feature lost in pinned authority")
	}
	commits := 0
	attempt := strings.Repeat("a", 64)
	commit := func(_ context.Context, actor auth.Principal, b BoundMutation) (BindingCommit, error) {
		commits++
		if actor.ClientID != p.ClientID || b.Action != "element.select" || b.BrowserAttemptID != attempt || b.ControlLease != a.Lease || b.Fingerprint.Version != 2 {
			return BindingCommit{}, fmt.Errorf("original binding differs")
		}
		return BindingCommit{BindingID: strings.Repeat("b", 64), CommitConfirmed: true, ReadbackMatched: true}, nil
	}
	result, err := g.ExecuteControlBound(ctx, p, step, nil, a, attempt, commit)
	if err != nil || result.DispatchState != "dispatched" || count.Load() != 1 || commits != 1 {
		t.Fatal("packaged bound select did not dispatch once", err)
	}
	result, err = g.ExecuteControlBound(ctx, p, step, nil, a, attempt, commit)
	if err != nil || result.DispatchState != "dispatched" || count.Load() != 1 || commits != 1 {
		t.Fatal("original select receipt was replayed or recommitted", err)
	}
	step.Arguments["value"] = model.Value{Kind: model.StringValue, String: "blue"}
	if _, err = g.ExecuteControlBound(ctx, p, step, nil, a, attempt, commit); err == nil || count.Load() != 1 {
		t.Fatal("conflicting original attempt admitted")
	}
	if retired, err := g.RetireControl(ctx, p, a); !retired || err != nil {
		t.Fatal("select authority did not retire", err)
	}
}

func TestSelectRequiresCurrentNegotiatedVersionAndCommittedBinding(t *testing.T) {
	g, p, ctx, count := controlFixtureVersion(t, -2)
	caps, err := g.ControlCapabilitiesFor(ctx, p)
	if err != nil || caps["web:selectOption"] {
		t.Fatal("old worker advertised select")
	}
	plan, _ := script.Compile(`web.tab(origin:"https://fixture.test").getById("color",exact:true).select("green")`)
	a, err := g.AdmitControl(ctx, p, plan.Steps[0].Target.Surface)
	if err != nil {
		t.Fatal(err)
	}
	commit := func(context.Context, auth.Principal, BoundMutation) (BindingCommit, error) {
		t.Fatal("unnegotiated select reached binding writer")
		return BindingCommit{}, nil
	}
	r, err := g.ExecuteControlBound(ctx, p, plan.Steps[0], nil, a, strings.Repeat("a", 64), commit)
	if err == nil || r.DispatchState != "notDispatched" || count.Load() != 0 {
		t.Fatal("unnegotiated select dispatched")
	}
}
