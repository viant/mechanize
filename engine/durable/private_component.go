package durable

import (
	"context"
	"errors"
	"github.com/viant/datly/exec"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data"
)

// InvokePrivateComponent is a scoped infrastructure bridge for the selected
// consent and scenario components. Their generated contracts own validation/reads/writes.
// It is not a transport endpoint, raw SQL service or generic DAO.
func (b *Builder) InvokePrivateComponent(ctx context.Context, p auth.Principal, request exec.ComponentRequest) (any, error) {
	allowed := map[string]bool{"consentcreate": true, "consentrequests": true, "consentdecide": true, "consentgrants": true, "consentconsume": true, "consentrevoke": true, "consenttrusted": true, "applicationpolicyread": true, "applicationpolicywrite": true, "scenariopublish": true, "scenariolist": true, "recoveryload": true, "repairadmit": true}
	const prefix = "github.com/viant/mechanize/data/"
	scope := request.Target.Component.Scope
	if len(scope) <= len(prefix) || scope[:len(prefix)] != prefix || !allowed[scope[len(prefix):]] {
		return nil, errors.New("private component is not in host exposure policy")
	}
	// A trusted Execute callback already owns this exact user's admission lock.
	// Re-enter only the restricted component bridge, with the same actor and fresh
	// data scope; no external request can construct the package-private marker.
	held, release, marked, err := b.heldInvocation(ctx, p)
	if marked {
		if err != nil {
			return nil, err
		}
		defer release()
		ctx, err = data.WithScope(ctx, data.Scope{Namespace: p.Namespace})
		if err != nil {
			return nil, err
		}
		return held.server.InvokeComponent(ctx, request)
	}
	ctx, user, err := b.bound(ctx, p, 0)
	if err != nil {
		return nil, err
	}
	user.mu.Lock()
	defer user.mu.Unlock()
	return user.server.InvokeComponent(ctx, request)
}
