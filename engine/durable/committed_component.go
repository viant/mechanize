package durable

import (
	"context"
	"errors"

	"github.com/viant/datly/exec"
	"github.com/viant/datly/spec"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data"
)

// InvokeCommittedComponent is the private binding bridge during synchronous
// dispatch. It cannot acquire a new user lock or mint a committed intent. The
// existing scope (including lease epoch) must survive every generated call.
func (b *Builder) InvokeCommittedComponent(ctx context.Context, p auth.Principal, request exec.ComponentRequest) (any, error) {
	if b == nil || p.ClientID == "" || !p.HasScope("desktop:control") {
		return nil, auth.ErrUnauthorized
	}
	if _, err := data.RequireCommittedStepIntent(ctx, p); err != nil {
		return nil, err
	}
	const prefix = "github.com/viant/mechanize/data/"
	allowed := map[string]struct{ name, method string }{
		prefix + "loadplan":                   {"LoadPlan", "GET"},
		prefix + "loadrun":                    {"LoadRun", "GET"},
		prefix + "chromeattemptbindingcreate": {"CreateChromeAttemptBinding", "POST"},
		prefix + "chromeattemptbindingget":    {"LoadChromeAttemptBinding", "GET"},
	}
	target := request.Target
	entry, ok := allowed[target.Component.Scope]
	if !ok || target.Component.Kind != spec.KindComponent || target.Component.Name != entry.name || target.Route.Method != entry.method || target.Route.Path != "/internal/data/"+target.Component.Scope[len(prefix):] {
		return nil, errors.New("component is not in committed binding exposure policy")
	}
	user, release, marked, err := b.heldInvocation(ctx, p)
	if err != nil {
		return nil, err
	}
	if !marked {
		return nil, errHeldUserLockExpired
	}
	defer release()
	if _, err = data.RequireCommittedStepIntent(ctx, p); err != nil {
		return nil, err
	}
	if user == nil || user.server == nil {
		return nil, errors.New("committed component runtime unavailable")
	}
	return user.server.InvokeComponent(ctx, request)
}
