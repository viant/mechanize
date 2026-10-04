package durable

import (
	"context"
	"errors"
	"github.com/viant/datly/exec"
	"github.com/viant/datly/spec"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data"
	"time"
)

// PrepareRepairAdmission materializes the fixed generated writer before the
// host collects short-lived evidence. It performs no mutation and accepts no
// caller-selected component or storage target.
func (b *Builder) PrepareRepairAdmission(ctx context.Context, p auth.Principal) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	ctx, user, err := b.bound(ctx, p, 0)
	if err != nil {
		return err
	}
	user.mu.Lock()
	defer user.mu.Unlock()
	return user.server.PrepareComponent(ctx, spec.Key{Kind: spec.KindComponent, Scope: "github.com/viant/mechanize/data/repairadmit", Name: "AdmitRepair"})
}

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
