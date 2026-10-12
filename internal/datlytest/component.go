// Package datlytest provides private typed Datly fixture operations. It is never
// registered by production composition and accepts no SQL or connector input.
package datlytest

import (
	"context"
	"errors"
	"github.com/viant/datly/bootstrap/connector"
	dexec "github.com/viant/datly/exec"
	rhandler "github.com/viant/datly/runtime/handler"
	"github.com/viant/datly/runtime/handler/custom"
	"github.com/viant/datly/spec"
	"github.com/viant/datly/standalone"
	"github.com/viant/datly/standalone/config"
	"github.com/viant/mechanize/internal/datlytest/auditcounts"
	"github.com/viant/mechanize/internal/datlytest/authority"
	"github.com/viant/xdatly"
	"github.com/viant/xdatly/handler"
)

const Scope = "github.com/viant/mechanize/internal/datlytest"

type Component struct {
	Fixture xdatly.Component[Input, Output] `component:"Fixture,path=/internal/test/graph,method=POST,connector=user,handler=NewFixture"`
}

func (Component) DatlyHandler(name string) func() (rhandler.TypedHandler, error) {
	if name == "NewFixture" {
		return custom.Factory(NewFixture)
	}
	return nil
}

type Plan struct {
	Namespace   string `sqlx:"namespace"`
	ID          string `sqlx:"id"`
	ObjectiveID string `sqlx:"objective_id"`
	ContentHash string `sqlx:"content_hash"`
	ContentJSON string `sqlx:"content_json"`
	CreatedAt   string `sqlx:"created_at"`
}
type Run struct {
	Namespace   string  `sqlx:"namespace"`
	ID          string  `sqlx:"id"`
	PlanID      string  `sqlx:"plan_id"`
	Status      string  `sqlx:"status"`
	Revision    int     `sqlx:"revision"`
	SessionID   *string `sqlx:"endly_session_id"`
	OperationID *string `sqlx:"endly_operation_id"`
	CreatedAt   string  `sqlx:"created_at"`
	UpdatedAt   string  `sqlx:"updated_at"`
}
type Attempt struct {
	Namespace  string `sqlx:"namespace"`
	ID         string `sqlx:"id"`
	RunID      string `sqlx:"run_id"`
	StepID     string `sqlx:"step_id"`
	PlanID     string `sqlx:"plan_id"`
	LeaseEpoch int    `sqlx:"lease_epoch"`
	State      string `sqlx:"state"`
	CreatedAt  string `sqlx:"created_at"`
}
type Effect struct {
	Namespace    string `sqlx:"namespace"`
	ID           string `sqlx:"id"`
	AttemptID    string `sqlx:"attempt_id"`
	RunID        string `sqlx:"run_id"`
	BusinessKey  string `sqlx:"business_key"`
	State        string `sqlx:"state"`
	Revision     int    `sqlx:"revision"`
	EvidenceJSON string `sqlx:"evidence_json"`
}
type Event struct {
	Namespace   string  `sqlx:"namespace"`
	ID          string  `sqlx:"id"`
	RunID       string  `sqlx:"run_id"`
	AttemptID   *string `sqlx:"attempt_id"`
	Sequence    int     `sqlx:"sequence"`
	Kind        string  `sqlx:"kind"`
	PayloadJSON string  `sqlx:"payload_json"`
	CreatedAt   string  `sqlx:"created_at"`
}
type Milestone struct {
	Namespace    string `sqlx:"namespace"`
	ID           string `sqlx:"id"`
	RunID        string `sqlx:"run_id"`
	AttemptID    string `sqlx:"attempt_id"`
	State        string `sqlx:"state"`
	EvidenceJSON string `sqlx:"evidence_json"`
}
type Graph struct {
	Plan       *Plan
	Run        *Run
	Attempts   []Attempt
	Effects    []Effect
	Events     []Event
	Milestones []Milestone
}
type Input struct {
	Namespace string `parameter:"Namespace,kind=query,in=namespace,required"`
	Mode      string `parameter:"Mode,kind=body,in=mode,required"`
	Graph     *Graph `parameter:"Graph,kind=body,in=graph"`
	RunID     string `parameter:"RunID,kind=body,in=runId"`
}
type Output struct {
	Applied bool `json:"applied"`
}
type fixture struct{}

func NewFixture() handler.Contract[Input, Output] { return &fixture{} }
func (*fixture) Exec(ctx context.Context, session handler.Session, in *Input, out *Output) error {
	if e := authority.Require(ctx, in.Namespace); e != nil {
		return e
	}
	deps := struct {
		DML handler.DML `bind:"kind=dml,required"`
	}{}
	if e := session.Binder().Bind(ctx, &deps); e != nil {
		return e
	}
	check := func(namespace string) error {
		if namespace != in.Namespace {
			return errors.New("fixture crossed namespace")
		}
		return nil
	}
	switch in.Mode {
	case "graph":
		if in.Graph == nil {
			return errors.New("typed fixture graph required")
		}
		g := in.Graph
		if g.Plan != nil {
			if e := check(g.Plan.Namespace); e != nil {
				return e
			}
			if e := deps.DML.Insert("plan_revisions", g.Plan); e != nil {
				return e
			}
		}
		if g.Run != nil {
			if e := check(g.Run.Namespace); e != nil {
				return e
			}
			if e := deps.DML.Insert("runs", g.Run); e != nil {
				return e
			}
		}
		for i := range g.Attempts {
			v := &g.Attempts[i]
			if e := check(v.Namespace); e != nil {
				return e
			}
			if e := deps.DML.Insert("attempts", v); e != nil {
				return e
			}
		}
		for i := range g.Effects {
			v := &g.Effects[i]
			if e := check(v.Namespace); e != nil {
				return e
			}
			if e := deps.DML.Insert("effects", v); e != nil {
				return e
			}
		}
		for i := range g.Events {
			v := &g.Events[i]
			if e := check(v.Namespace); e != nil {
				return e
			}
			if e := deps.DML.Insert("events", v); e != nil {
				return e
			}
		}
		for i := range g.Milestones {
			v := &g.Milestones[i]
			if e := check(v.Namespace); e != nil {
				return e
			}
			if e := deps.DML.Insert("milestones", v); e != nil {
				return e
			}
		}
	case "failedRun":
		if in.RunID == "" {
			return errors.New("fixture run required")
		}
		if e := deps.DML.Execute("UPDATE runs SET status='failed' WHERE namespace=? AND id=?", in.Namespace, in.RunID); e != nil {
			return e
		}
	case "missingSession":
		if in.RunID == "" {
			return errors.New("fixture run required")
		}
		if e := deps.DML.Execute("UPDATE runs SET endly_session_id=NULL WHERE namespace=? AND id=?", in.Namespace, in.RunID); e != nil {
			return e
		}
	default:
		return errors.New("unsupported typed fixture operation")
	}
	out.Applied = true
	return nil
}
func Open(ctx context.Context, cfg connector.Config) (*standalone.Server, error) {
	server, e := standalone.New(ctx, standalone.Options{Config: &config.Config{Connector: "user", Connectors: []connector.Config{cfg}, GoBootstrap: &config.Packages{LinkedOnly: true, Packages: []string{Scope, Scope + "/auditcounts"}}}, Holders: []any{Component{}, auditcounts.AuditCountsComponent{}}})
	if e != nil {
		return nil, e
	}
	if e = server.Reload(ctx, 1); e != nil {
		_ = server.Shutdown(context.Background())
		return nil, e
	}
	return server, nil
}
func Apply(ctx context.Context, server *standalone.Server, in Input) error {
	authorized, e := authority.With(ctx, in.Namespace)
	if e != nil {
		return e
	}
	var outcome handler.Outcome
	_, e = server.InvokeComponent(authorized, dexec.ComponentRequest{Target: dexec.ComponentTarget{Component: spec.Key{Kind: spec.KindComponent, Scope: Scope, Name: "Fixture"}, Route: spec.RouteRef{Method: "POST", Path: "/internal/test/graph"}}, Input: &in, Completion: func(o handler.Outcome) { outcome = o }})
	if e != nil {
		return e
	}
	if !outcome.CommitConfirmed() {
		return errors.New("fixture transaction commit unconfirmed")
	}
	return nil
}
func CountAudits(ctx context.Context, server *standalone.Server, namespace string) (auditcounts.Counts, error) {
	var zero auditcounts.Counts
	authorized, e := authority.With(ctx, namespace)
	if e != nil {
		return zero, e
	}
	in := &auditcounts.AuditCountsInput{}
	in.SetNamespace(namespace)
	value, e := server.InvokeComponent(authorized, dexec.ComponentRequest{Target: dexec.ComponentTarget{Component: spec.Key{Kind: spec.KindComponent, Scope: Scope + "/auditcounts", Name: "AuditCounts"}, Route: spec.RouteRef{Method: "GET", Path: "/internal/test/auditcounts"}}, Input: in})
	if e != nil {
		return zero, e
	}
	out, ok := value.(*auditcounts.AuditCountsOutput)
	if !ok || len(out.Data) != 1 || out.Data[0] == nil {
		return zero, errors.New("exact scoped audit counts required")
	}
	return *out.Data[0], nil
}
