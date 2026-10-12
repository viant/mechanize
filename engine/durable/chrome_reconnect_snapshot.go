package durable

import (
	"context"
	"errors"
	"github.com/viant/datly/exec"
	"github.com/viant/datly/spec"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data"
	page "github.com/viant/mechanize/data/chromeattemptbindingpage"
	snapshot "github.com/viant/mechanize/data/chromeattemptbindingsnapshot"
)

// ChromeReconnectBindingSnapshot requires the existing held lifecycle admission
// lock. Datly additionally owns a SERIALIZABLE transaction across all pages and
// child relations, so this projection does not rely on a process-local mutex
// for database consistency. It confers no input or reconciliation authority.
func (b *Builder) ChromeReconnectBindingSnapshot(ctx context.Context, p auth.Principal) ([]*page.Binding, error) {
	actual, err := auth.FromContext(ctx)
	if b == nil || err != nil || actual.Namespace != p.Namespace || actual.ClientID != p.ClientID || !actual.HasScope("desktop:control") {
		return nil, auth.ErrUnauthorized
	}
	if _, err = data.RequireChromeReconnectBindingReadAuthority(ctx); err != nil {
		return nil, err
	}
	user, release, marked, err := b.heldInvocation(ctx, p)
	if err != nil {
		return nil, err
	}
	if !marked {
		return nil, errHeldUserLockExpired
	}
	defer release()
	if user == nil || user.server == nil {
		return nil, errors.New("reconnect snapshot runtime unavailable")
	}
	value, err := user.server.InvokeComponent(ctx, exec.ComponentRequest{Target: exec.ComponentTarget{Component: spec.Key{Kind: spec.KindComponent, Scope: "github.com/viant/mechanize/data/chromeattemptbindingsnapshot", Name: "SnapshotChromeAttemptBindings"}, Route: spec.RouteRef{Method: "GET", Path: "/internal/data/chromeattemptbindingsnapshot"}}, Input: &snapshot.Input{}})
	if err != nil {
		return nil, err
	}
	out, ok := value.(*snapshot.Output)
	if !ok || out == nil {
		return nil, errors.New("complete reconnect snapshot unavailable")
	}
	if _, err = data.RequireChromeReconnectBindingReadAuthority(ctx); err != nil {
		return nil, err
	}
	return out.Data, nil
}
