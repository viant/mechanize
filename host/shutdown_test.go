package host

import (
	"context"
	"errors"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
	native "github.com/viant/mechanize/backend/darwin"
	"github.com/viant/mechanize/engine/durable"
	automation "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
)

func TestHostShutdownRetainsDatlyUntilNoncooperativeEndlyWorkJoins(t *testing.T) {
	h, f := hostControlFixture(t)
	if _, err := h.controlLeaseEpoch(f.ctx, f.principal); err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	var err error
	h.Runtime, err = automation.New(func(context.Context, auth.Principal, model.Step, map[string]model.Value) (automation.StepResult, error) {
		close(started)
		<-release
		return automation.StepResult{DispatchState: "notDispatched", VerificationState: "unknown"}, errors.New("fixturejoined")
	})
	if err != nil {
		t.Fatal(err)
	}
	session, err := h.Runtime.Open(f.ctx, "pendingdatastore")
	if err != nil {
		t.Fatal(err)
	}
	_, file, _, _ := runtime.Caller(0)
	h.durable, err = durable.New(durable.Options{SourceRoot: filepath.Dir(filepath.Dir(file)), StorageRoot: t.TempDir(), LeaseEpoch: func(context.Context, auth.Principal) (int, error) { return 1, nil }}, func(context.Context, auth.Principal, model.Step, map[string]model.Value) (automation.StepResult, error) {
		return automation.StepResult{}, errors.New("unused")
	})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := script.Compile(`app("com.fixture.app").getById("fixture", exact: true).read("text")`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.durable.PreparePlan(f.ctx, f.principal, "retained-run", session.SessionID, *plan, nil); err != nil {
		t.Fatal(err)
	}
	if _, err = h.Runtime.StartPlan(f.ctx, session.SessionID, *plan, nil); err != nil {
		t.Fatal(err)
	}
	<-started
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err = h.Close(ctx); !errors.Is(err, automation.ErrShutdownPending) {
		t.Fatalf("host prematurelydeclaredclosed %v", err)
	}
	if f.alive {
		t.Fatal("physicalhelper inhibition waitedforblockedEndly")
	}
	if _, err = h.durable.StateGet(f.ctx, f.principal, "retained-run"); err != nil {
		t.Fatalf("DatlyclosedwhileEndly stillownswork %v", err)
	}
	close(release)
	joined, done := context.WithTimeout(context.Background(), 5*time.Second)
	defer done()
	if err = h.Close(joined); err != nil {
		t.Fatalf("joinedhost cleanup %v", err)
	}
	if _, err = h.durable.StateGet(f.ctx, f.principal, "retained-run"); err == nil {
		t.Fatal("Datlynotclosedafterconfirmedjoin")
	}
}

type shutdownReadCaller struct{ closes int }

func (c *shutdownReadCaller) Call(context.Context, native.Request) (native.Reply, error) {
	return native.Reply{}, errors.New("unused")
}
func (c *shutdownReadCaller) Close() error { c.closes++; return nil }
func TestHostShutdownClosesEveryOwnedReadGatewayOnce(t *testing.T) {
	caller := &shutdownReadCaller{}
	gateway, err := native.NewGateway(caller, native.GatewayOptions{AllApplications: true})
	if err != nil {
		t.Fatal(err)
	}
	h := &Host{native: gateway, nativeByUser: map[string]*native.Gateway{"first": gateway, "same-client-alias": gateway}}
	if err = h.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if caller.closes != 1 {
		t.Fatalf("owned readclient closecount %d", caller.closes)
	}
}
