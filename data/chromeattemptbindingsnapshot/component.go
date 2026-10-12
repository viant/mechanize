// Package chromeattemptbindingsnapshot composes generated readers in one
// Datly-owned snapshot. It creates no transport, database pool or writer.
package chromeattemptbindingsnapshot

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/viant/datly/exec"
	rh "github.com/viant/datly/runtime/handler"
	"github.com/viant/datly/runtime/handler/custom"
	"github.com/viant/datly/spec"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data"
	page "github.com/viant/mechanize/data/chromeattemptbindingpage"
	"github.com/viant/xdatly"
	"github.com/viant/xdatly/handler"
)

type Component struct {
	Contract xdatly.Component[Input, Output] `component:"SnapshotChromeAttemptBindings,path=/internal/data/chromeattemptbindingsnapshot,method=GET,connector=user,handler=NewSnapshot,internal=true" componentCallPolicy:"imperative"`
}
type Input struct{}
type Output struct {
	Data []*page.Binding `json:"data"`
}
type snapshot struct{}

func NewSnapshot() handler.Contract[Input, Output] { return &snapshot{} }
func (Component) DatlyHandler(name string) func() (rh.TypedHandler, error) {
	if name == "NewSnapshot" {
		return custom.Factory(NewSnapshot)
	}
	return nil
}
func (*Input) Init(ctx context.Context) error {
	_, err := data.RequireChromeReconnectBindingReadAuthority(ctx)
	return err
}
func (*snapshot) Exec(ctx context.Context, session handler.Session, _ *Input, out *Output) error {
	if session == nil || session.Binder() == nil || out == nil {
		return errors.New("binding snapshot capability unavailable")
	}
	scope, err := data.RequireChromeReconnectBindingReadAuthority(ctx)
	if err != nil {
		return err
	}
	deps := struct {
		Invoker exec.ComponentInvoker      `bind:"kind=component_invoker,required"`
		Starter handler.TransactionStarter `bind:"kind=transactionStarter,required"`
	}{}
	if err = session.Binder().Bind(ctx, &deps); err != nil {
		return err
	}
	if deps.Invoker == nil || deps.Starter == nil {
		return errors.New("binding snapshot transaction unavailable")
	}
	ctx = exec.WithTransactionIsolation(ctx, exec.IsolationSerializable)
	if err = deps.Starter.Start(ctx); err != nil {
		return err
	}
	rows, err := collect(ctx, scope, deps.Invoker.InvokeComponent)
	if err != nil {
		return err
	}
	if _, err = data.RequireChromeReconnectBindingReadAuthority(ctx); err != nil {
		return err
	}
	out.Data = rows
	return nil
}
func collect(ctx context.Context, scope data.ChromeReconnectBindingReadScope, invoke func(context.Context, exec.ComponentRequest) (any, error)) ([]*page.Binding, error) {
	p, err := auth.FromContext(ctx)
	if err != nil {
		return nil, err
	}
	rows := make([]*page.Binding, 0)
	size := 0
	seen := map[string]bool{}
	after := ""
	for {
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		in := &page.PageChromeAttemptBindingsInput{}
		in.SetNamespace(p.Namespace)
		in.SetProfileChannel(scope.ProfileChannel)
		in.SetBrowserInstance(scope.BrowserInstance)
		in.SetScopeHash(scope.ScopeHash)
		in.SetAfterID(after)
		value, e := invoke(ctx, exec.ComponentRequest{Target: exec.ComponentTarget{Component: spec.Key{Kind: spec.KindComponent, Scope: "github.com/viant/mechanize/data/chromeattemptbindingpage", Name: "PageChromeAttemptBindings"}, Route: spec.RouteRef{Method: "GET", Path: "/internal/data/chromeattemptbindingpage"}}, Input: in})
		if e != nil {
			return nil, e
		}
		result, ok := value.(*page.PageChromeAttemptBindingsOutput)
		if !ok || result == nil || len(result.Data) > data.ChromeReconnectBindingPageSize {
			return nil, errors.New("invalid complete binding page")
		}
		if len(rows)+len(result.Data) > data.ChromeReconnectBindingCapacity {
			return nil, errors.New("complete reconnect binding coverage exceeds capacity")
		}
		for _, row := range result.Data {
			if row == nil || row.Id == nil || *row.Id <= after || seen[*row.Id] || row.Namespace == nil || *row.Namespace != p.Namespace || row.ProfileChannel == nil || *row.ProfileChannel != scope.ProfileChannel || row.BrowserInstance == nil || *row.BrowserInstance != scope.BrowserInstance || row.BrokerEpoch == nil || *row.BrokerEpoch == "" || row.ChannelEpoch == nil || *row.ChannelEpoch == "" || row.ScopeHash == nil || *row.ScopeHash != scope.ScopeHash {
				return nil, errors.New("binding page scope or cursor mismatch")
			}
			encoded, e := json.Marshal(row)
			if e != nil {
				return nil, e
			}
			size += len(encoded)
			if size > 32*1024*1024 {
				return nil, errors.New("complete binding metadata exceeds capacity")
			}
			seen[*row.Id] = true
			after = *row.Id
			rows = append(rows, row)
		}
		if len(result.Data) == 0 {
			break
		}
	}
	return rows, ctx.Err()
}
