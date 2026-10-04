package stopboundary_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/viant/datly/bootstrap/connector"
	"github.com/viant/datly/exec"
	"github.com/viant/datly/spec"
	"github.com/viant/datly/standalone"
	"github.com/viant/datly/standalone/config"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/data/loadrun"
	"github.com/viant/mechanize/data/stopboundary"
	"github.com/viant/xdatly/handler"
)

func ptr[T any](v T) *T { return &v }

type fixture struct {
	ctx    context.Context
	p      auth.Principal
	db     *sql.DB
	server *standalone.Server
}

func openFixture(t *testing.T) *fixture {
	t.Helper()
	p, err := auth.NewPrincipal("fixture", "", "alice", []string{"desktop:observe"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := auth.WithPrincipal(context.Background(), p)
	ctx, err = data.WithScope(ctx, data.Scope{Namespace: p.Namespace})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := data.Provision(ctx, t.TempDir(), data.Scope{Namespace: p.Namespace})
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite3", cfg.DSN)
	if err != nil {
		t.Fatal(err)
	}
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "../.."))
	server, err := standalone.New(ctx, standalone.Options{Config: &config.Config{BaseDir: root, Connector: "user", Connectors: []connector.Config{cfg}, GoBootstrap: &config.Packages{Packages: []string{"github.com/viant/mechanize/data/stopboundary", "github.com/viant/mechanize/data/loadrun"}}}, Holders: []any{stopboundary.StopBoundaryComponent{}, loadrun.LoadRunComponent{}}})
	if err != nil {
		t.Fatal(err)
	}
	if err = server.Reload(ctx, 1); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Shutdown(context.Background()); _ = db.Close() })
	return &fixture{ctx, p, db, server}
}
func (f *fixture) seed(t *testing.T, name string) (data.StopBoundaryAuthority, context.Context) {
	t.Helper()
	ns := f.p.Namespace
	run := data.ReconcileEffectKey("stop-run", name)
	plan := data.ReconcileEffectKey("stop-plan", name)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	// SQL provisions an isolated test fixture only; behavior uses generated components.
	for _, s := range []struct {
		q string
		a []any
	}{
		{"INSERT INTO plan_revisions(namespace,id,objective_id,content_hash,content_json,created_at) VALUES(?,?,?,?,?,?)", []any{ns, plan, run, "fixture-hash", "{}", now}},
		{"INSERT INTO runs(namespace,id,plan_id,status,revision,endly_session_id,endly_operation_id,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)", []any{ns, run, plan, "running", 3, "session", "operation", now, now}},
		{"INSERT INTO attempts(namespace,id,run_id,step_id,plan_id,lease_epoch,state,created_at) VALUES(?,?,?,?,?,?,?,?)", []any{ns, "attempt-" + run, run, "original-step", plan, 1, "intent", now}},
		{"INSERT INTO effects(namespace,id,attempt_id,run_id,business_key,state,revision,evidence_json) VALUES(?,?,?,?,?,?,?,?)", []any{ns, "effect-" + run, "attempt-" + run, run, "original-key", "unknown", 2, `{"dispatchState":"dispatched","verificationState":"unknown"}`}},
		{"INSERT INTO events(namespace,id,run_id,attempt_id,sequence,kind,payload_json,created_at) VALUES(?,?,?,?,?,?,?,?)", []any{ns, "outcome-" + run, run, "attempt-" + run, 1, "outcome", "original-outcome", now}},
	} {
		if _, err := f.db.ExecContext(f.ctx, s.q, s.a...); err != nil {
			t.Fatal(err)
		}
	}
	a := data.StopBoundaryAuthority{Namespace: ns, RunID: run, PlanID: plan, RequestID: "request-" + name, EndlySessionID: "session", EndlyOperationID: "operation", QuiescenceProof: "fixture-Endly-terminal-physical-fence-held", RunRevision: 3, AuditSequence: 2, Now: now}
	guard, err := data.WithStateMutationPermit(f.ctx, ns, run)
	if err != nil {
		t.Fatal(err)
	}
	return a, guard
}
func authority(t *testing.T, ctx context.Context, a data.StopBoundaryAuthority) (context.Context, data.StopBoundaryAuthority) {
	t.Helper()
	ctx, err := data.WithStopBoundaryAuthority(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	a, err = data.RequireStopBoundaryAuthority(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return ctx, a
}
func body(a data.StopBoundaryAuthority) *stopboundary.StopBoundaryInput {
	e := &stopboundary.Event{}
	e.SetNamespace(ptr(a.Namespace))
	e.SetId(ptr(a.AuditID))
	e.SetRunId(ptr(a.RunID))
	e.SetSequence(ptr(a.AuditSequence))
	e.SetKind(ptr("stopped_boundary"))
	e.SetPayloadJson(ptr(a.AuditPayloadJSON))
	e.SetCreatedAt(ptr(a.Now))
	r := &stopboundary.Run{}
	r.SetNamespace(ptr(a.Namespace))
	r.SetId(ptr(a.RunID))
	r.SetRevision(ptr(a.RunRevision))
	r.SetStatus(ptr("paused"))
	r.SetUpdatedAt(ptr(a.Now))
	r.SetEvents([]*stopboundary.Event{e})
	in := &stopboundary.StopBoundaryInput{}
	in.SetNamespace(a.Namespace)
	in.SetStopBoundary([]*stopboundary.Run{r})
	return in
}
func (f *fixture) invoke(ctx context.Context, in *stopboundary.StopBoundaryInput) (handler.Outcome, error) {
	var o handler.Outcome
	_, err := f.server.InvokeComponent(ctx, exec.ComponentRequest{Target: exec.ComponentTarget{Component: spec.Key{Kind: spec.KindComponent, Scope: "github.com/viant/mechanize/data/stopboundary", Name: "StopBoundary"}, Route: spec.RouteRef{Method: "PATCH", Path: "/internal/data/stopboundary"}}, Input: in, Completion: func(v handler.Outcome) { o = v }})
	return o, err
}
func (f *fixture) load(t *testing.T, id string) *loadrun.Run {
	t.Helper()
	in := &loadrun.LoadRunInput{}
	in.SetNamespace(f.p.Namespace)
	in.SetRunID(id)
	out, err := f.server.InvokeComponent(f.ctx, exec.ComponentRequest{Target: exec.ComponentTarget{Component: spec.Key{Kind: spec.KindComponent, Scope: "github.com/viant/mechanize/data/loadrun", Name: "LoadRun"}, Route: spec.RouteRef{Method: "GET", Path: "/internal/data/loadrun"}}, Input: in})
	if err != nil {
		t.Fatal(err)
	}
	rows := out.(*loadrun.LoadRunOutput).Data
	if len(rows) != 1 {
		t.Fatal("missing scoped fixture")
	}
	return rows[0]
}
func TestGeneratedStopBoundaryPreservesUnknownAndOriginalOutcome(t *testing.T) {
	f := openFixture(t)
	a, g := f.seed(t, "commit")
	ctx, a := authority(t, g, a)
	o, err := f.invoke(ctx, body(a))
	if err != nil {
		t.Fatal(err)
	}
	if !o.CommitConfirmed() {
		t.Fatal("unconfirmed generated commit")
	}
	r := f.load(t, a.RunID)
	if *r.Status != "paused" || *r.Revision != 4 || *r.PlanId != a.PlanID || *r.EndlySessionId != a.EndlySessionID || *r.EndlyOperationId != a.EndlyOperationID || len(r.Effects) != 1 || len(r.Milestones) != 0 || len(r.Attempts) != 1 || len(r.Events) != 2 {
		t.Fatalf("incorrect stopped projection %+v", r)
	}
	e := r.Effects[0]
	if *e.State != "unknown" || *e.Revision != 2 || *e.BusinessKey != "original-key" || *e.EvidenceJson != `{"dispatchState":"dispatched","verificationState":"unknown"}` {
		t.Fatal("original unknown effect changed")
	}
	var audit data.StopBoundaryAudit
	found := false
	original := false
	for _, e := range r.Events {
		if *e.Kind == "outcome" {
			original = *e.PayloadJson == "original-outcome"
		}
		if *e.Id == a.AuditID {
			found = *e.Kind == "stopped_boundary" && *e.PayloadJson == a.AuditPayloadJSON
			if json.Unmarshal([]byte(*e.PayloadJson), &audit) != nil {
				t.Fatal("invalid audit")
			}
		}
	}
	if !found || !original {
		t.Fatal("audit or original outcome missing")
	}
	expected := data.StopBoundaryAudit{PriorRunRevision: 3, RunID: a.RunID, PlanID: a.PlanID, RequestID: a.RequestID, EndlySessionID: a.EndlySessionID, EndlyOperationID: a.EndlyOperationID, QuiescenceProof: a.QuiescenceProof}
	if err = data.MatchStopBoundaryAudit(a.AuditPayloadJSON, expected); err != nil {
		t.Fatal(err)
	}
	// Reply-loss adoption uses immutable readback. Rewriting the same request fails.
	if _, err = f.invoke(ctx, body(a)); err == nil {
		t.Fatal("duplicate writer accepted")
	}
	if data.MatchStopBoundaryAudit(a.AuditPayloadJSON+` {}`, expected) == nil {
		t.Fatal("adoption accepted trailing JSON")
	}
	if data.MatchStopBoundaryAudit(a.AuditPayloadJSON[:len(a.AuditPayloadJSON)-1]+`,"success":true}`, expected) == nil {
		t.Fatal("adoption accepted undeclared outcome")
	}
	expected.EndlyOperationID = "different-operation"
	if data.MatchStopBoundaryAudit(a.AuditPayloadJSON, expected) == nil {
		t.Fatal("adoption rebound correlation")
	}
	r = f.load(t, a.RunID)
	if *r.Revision != 4 || len(r.Events) != 2 {
		t.Fatal("duplicate changed history")
	}
}
func TestGeneratedStopBoundaryRejectsUntrustedStaleOrForgedIngress(t *testing.T) {
	for _, name := range []string{"missingAuthority", "staleRevision", "stalePlan", "wrongOperation", "wrongNamespace", "ledgerOutcome", "changedCorrelation", "wrongAudit", "changedCursor", "terminal"} {
		t.Run(name, func(t *testing.T) {
			f := openFixture(t)
			a, g := f.seed(t, name)
			switch name {
			case "staleRevision":
				a.RunRevision = 2
			case "stalePlan":
				a.PlanID = "other-plan"
			case "wrongOperation":
				a.EndlyOperationID = "other-operation"
			case "changedCursor":
				a.AuditSequence = 8
			case "terminal":
				if _, err := f.db.Exec("UPDATE runs SET status='failed' WHERE namespace=? AND id=?", a.Namespace, a.RunID); err != nil {
					t.Fatal(err)
				}
			}
			ctx, a := authority(t, g, a)
			in := body(a)
			switch name {
			case "missingAuthority":
				ctx = g
			case "wrongNamespace":
				in.SetNamespace("foreign")
			case "ledgerOutcome":
				in.StopBoundary[0].Events[0].SetAttemptId(ptr("original-attempt"))
			case "changedCorrelation":
				in.StopBoundary[0].SetEndlyOperationId(ptr("different"))
			case "wrongAudit":
				in.StopBoundary[0].Events[0].SetPayloadJson(ptr(`{"success":true}`))
			}
			if _, err := f.invoke(ctx, in); err == nil {
				t.Fatal("invalid boundary accepted")
			}
			r := f.load(t, a.RunID)
			if *r.Revision != 3 || len(r.Events) != 1 || *r.Effects[0].State != "unknown" || len(r.Milestones) != 0 {
				t.Fatal("rejected graph changed history")
			}
		})
	}
}
func TestStopBoundaryAuthorityRequiresVerifiedIdentityAndHeldPermit(t *testing.T) {
	f := openFixture(t)
	a, g := f.seed(t, "authority")
	if _, err := data.WithStopBoundaryAuthority(f.ctx, a); err == nil {
		t.Fatal("missing permit accepted")
	}
	a.QuiescenceProof = ""
	if _, err := data.WithStopBoundaryAuthority(g, a); err == nil {
		t.Fatal("empty quiescence proof accepted")
	}
	a.QuiescenceProof = "proof"
	a.Now = time.Now().Add(-time.Minute).Format(time.RFC3339Nano)
	if _, err := data.WithStopBoundaryAuthority(g, a); err == nil {
		t.Fatal("stale authority accepted")
	}
	a.Now = time.Now().Format(time.RFC3339Nano)
	cancelled, cancel := context.WithCancel(g)
	cancel()
	if _, err := data.WithStopBoundaryAuthority(cancelled, a); err == nil {
		t.Fatal("cancelled stopped-boundary authority accepted")
	}
	ctx, a := authority(t, g, a)
	foreign, err := auth.NewPrincipal("fixture", "", "bob", []string{"desktop:observe"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = data.RequireStopBoundaryAuthority(auth.WithPrincipal(ctx, foreign)); err == nil {
		t.Fatal("foreign authority accepted")
	}
}

func TestGeneratedStopBoundaryRollsBackRunWhenAuditInsertFails(t *testing.T) {
	f := openFixture(t)
	a, g := f.seed(t, "rollback")
	other, _ := f.seed(t, "collision-holder")
	ctx, a := authority(t, g, a)
	// Force a database uniqueness failure after validation, using only disposable fixture setup.
	if _, err := f.db.Exec("INSERT INTO events(namespace,id,run_id,sequence,kind,payload_json,created_at) VALUES(?,?,?,?,?,?,?)", a.Namespace, a.AuditID, other.RunID, 2, "fixture", "{}", a.Now); err != nil {
		t.Fatal(err)
	}
	o, err := f.invoke(ctx, body(a))
	if err == nil || o.CommitConfirmed() {
		t.Fatal("conflicting audit insert committed")
	}
	r := f.load(t, a.RunID)
	if *r.Status != "running" || *r.Revision != 3 || len(r.Events) != 1 || *r.Effects[0].State != "unknown" {
		t.Fatal("audit failure did not roll back complete graph")
	}
}
