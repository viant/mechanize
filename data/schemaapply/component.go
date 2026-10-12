// Package schemaapply is a private Datly infrastructure component. Its only
// mutations are host-embedded, versioned schema scripts through scoped DML.
package schemaapply

import (
	"context"
	"errors"
	"fmt"

	dexec "github.com/viant/datly/exec"
	rhandler "github.com/viant/datly/runtime/handler"
	"github.com/viant/datly/runtime/handler/custom"
	"github.com/viant/datly/spec"
	"github.com/viant/mechanize/data/schemaauthority"
	"github.com/viant/mechanize/data/schemasnapshot"
	"github.com/viant/xdatly"
	"github.com/viant/xdatly/handler"
)

const Scope = "github.com/viant/mechanize/data/schemaapply"

type Component struct {
	Apply xdatly.Component[Input, Output] `component:"Apply,path=/internal/data/schemaapply,method=POST,connector=user,handler=NewApply"`
}

func (Component) DatlyHandler(name string) func() (rhandler.TypedHandler, error) {
	if name == "NewApply" {
		return custom.Factory(NewApply)
	}
	return nil
}

type Input struct {
	Namespace string `parameter:"Namespace,kind=query,in=namespace,required" json:"namespace"`
	Expected  int    `parameter:"Expected,kind=body,in=expected,required" json:"expected"`
	Version   int    `parameter:"Version,kind=body,in=version,required" json:"version"`
}
type Output struct {
	Version int `json:"version"`
}
type apply struct{}

func NewApply() handler.Contract[Input, Output] { return &apply{} }
func (in *Input) Init(ctx context.Context) error {
	if _, e := schemaauthority.Require(ctx, in.Namespace); e != nil {
		return e
	}
	if in.Expected < 0 || in.Expected >= schemaauthority.Version || in.Version != in.Expected+1 {
		return errors.New("one exact next schema migration required")
	}
	return nil
}
func (*apply) Exec(ctx context.Context, session handler.Session, in *Input, out *Output) error {
	authority, e := schemaauthority.Require(ctx, in.Namespace)
	if e != nil {
		return e
	}
	deps := struct {
		DML     handler.DML                `bind:"kind=dml,required"`
		Starter handler.TransactionStarter `bind:"kind=transactionStarter,required"`
		Invoker dexec.ComponentInvoker     `bind:"kind=component_invoker,required"`
	}{}
	if e = session.Binder().Bind(ctx, &deps); e != nil {
		return e
	}
	// Datly owns this transaction and the child's version read; no DB/Tx escapes.
	if e = deps.Starter.Start(ctx); e != nil {
		return e
	}
	current, e := Read(ctx, deps.Invoker, in.Namespace)
	if e != nil {
		return e
	}
	if current.Version != in.Expected {
		return errors.New("schema version changed before migration")
	}
	sql, e := authority.Migration(in.Version)
	if e != nil {
		return e
	}
	if e = deps.DML.Execute(sql); e != nil {
		return e
	}
	// Only a bounded, host-selected integer is rendered here; no caller SQL.
	if e = deps.DML.Execute(fmt.Sprintf("PRAGMA user_version=%d", in.Version)); e != nil {
		return e
	}
	out.Version = in.Version
	return nil
}
func Read(ctx context.Context, invoker dexec.ComponentInvoker, namespace string) (schemasnapshot.SchemaState, error) {
	var zero schemasnapshot.SchemaState
	if _, e := schemaauthority.Require(ctx, namespace); e != nil {
		return zero, e
	}
	in := &schemasnapshot.SchemaSnapshotInput{}
	in.SetNamespace(namespace)
	value, e := invoker.InvokeComponent(ctx, dexec.ComponentRequest{Target: dexec.ComponentTarget{Component: spec.Key{Kind: spec.KindComponent, Scope: "github.com/viant/mechanize/data/schemasnapshot", Name: "SchemaSnapshot"}, Route: spec.RouteRef{Method: "GET", Path: "/internal/data/schemasnapshot"}}, Input: in})
	if e != nil {
		return zero, e
	}
	out, ok := value.(*schemasnapshot.SchemaSnapshotOutput)
	if !ok || out == nil || len(out.Data) != 1 || out.Data[0] == nil {
		return zero, errors.New("exact schema metadata required")
	}
	return *out.Data[0], nil
}
