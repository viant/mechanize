package durable

import (
	"context"
	"errors"
	"github.com/viant/datly/exec"
	"github.com/viant/datly/spec"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data"
)

type RetirementComponentInvoker func(context.Context, auth.Principal, exec.ComponentRequest) (any, error)

// WithChromeRetirementComponents holds the user admission lock across the trusted
// lifecycle callback. Acquire the browser lifecycle lane inside this callback:
// ordinary execution also acquires the user lock before the browser lane.
func (b *Builder) WithChromeRetirementComponents(ctx context.Context, p auth.Principal, fn func(context.Context, RetirementComponentInvoker) error) error {
	actual, err := auth.FromContext(ctx)
	if b == nil || fn == nil || err != nil || p.Validate() != nil || actual.Namespace != p.Namespace || actual.ClientID != p.ClientID || actual.ClientID == "" || !actual.HasScope("desktop:control") {
		return auth.ErrUnauthorized
	}
	if _, exists := ctx.Value(heldUserLockKey{}).(*heldUserLock); exists {
		return errors.New("retirement cannot nest inside an active durable callback")
	}
	ctx, user, err := b.bound(ctx, actual, 0)
	if err != nil {
		return err
	}
	user.mu.Lock()
	defer user.mu.Unlock()
	if err = ctx.Err(); err != nil {
		return err
	}
	held, revoke := b.withHeldUserLock(ctx, actual, user)
	defer revoke()
	return fn(held, b.invokeRetirementComponent)
}

func retirementComponentAllowed(request exec.ComponentRequest) bool {
	const prefix = "github.com/viant/mechanize/data/"
	allowed := map[string]struct{ name, method string }{"chromeretirementget": {"LoadChromeRetirement", "GET"}, "chromeretirementwrite": {"WriteChromeRetirement", "PATCH"}, "chromeattemptbindinglist": {"ListChromeAttemptBindings", "GET"}, "loadplan": {"LoadPlan", "GET"}}
	for pkg, entry := range allowed {
		t := request.Target
		if t.Component.Kind == spec.KindComponent && t.Component.Scope == prefix+pkg && t.Component.Name == entry.name && t.Route.Method == entry.method && t.Route.Path == "/internal/data/"+pkg {
			return true
		}
	}
	return false
}

func (b *Builder) invokeRetirementComponent(ctx context.Context, p auth.Principal, request exec.ComponentRequest) (any, error) {
	if b == nil || !retirementComponentAllowed(request) {
		return nil, errors.New("component outside retirement lifecycle exposure policy")
	}
	a, err := data.RequireChromeRetirementAuthority(ctx)
	if err != nil || a.Namespace != p.Namespace || a.ClientID != p.ClientID {
		return nil, auth.ErrUnauthorized
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
		return nil, errors.New("retirement component runtime unavailable")
	}
	return user.server.InvokeComponent(ctx, request)
}
