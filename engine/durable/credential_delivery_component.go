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

type CredentialDeliveryComponentInvoker func(context.Context, auth.Principal, exec.ComponentRequest) (any, error)

// WithCredentialDeliveryComponents holds the real per-user durable lock. Acquire
// delivery/exposure/browser authority inside this callback; never invert the
// existing user-lock-before-browser-lane order. It grants no consent itself.
func (b *Builder) WithCredentialDeliveryComponents(ctx context.Context, p auth.Principal, fn func(context.Context, CredentialDeliveryComponentInvoker) error) error {
	actual, err := auth.FromContext(ctx)
	if b == nil || fn == nil || err != nil || p.Validate() != nil || actual.Namespace != p.Namespace || actual.ClientID != p.ClientID || actual.ClientID == "" || !actual.HasScope("desktop:control") {
		return auth.ErrUnauthorized
	}
	if _, exists := ctx.Value(heldUserLockKey{}).(*heldUserLock); exists {
		return errors.New("private credential delivery cannot nest inside an active durable callback")
	}
	ctx, user, err := b.bound(ctx, actual, 0)
	if err != nil {
		return err
	}
	// Private preparation has an explicit request deadline. A concurrent
	// operation holding the user lock must not turn bounded cleanup into an
	// uninterruptible wait.
	for !user.mu.TryLock() {
		timer := time.NewTimer(5 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	defer user.mu.Unlock()
	if err = ctx.Err(); err != nil {
		return err
	}
	held, revoke := b.withHeldUserLock(ctx, actual, user)
	defer revoke()
	return fn(held, b.invokeCredentialDeliveryComponent)
}

func credentialDeliveryComponentAllowed(request exec.ComponentRequest) bool {
	const prefix = "github.com/viant/mechanize/data/"
	allowed := map[string]struct{ name, method string }{"credentialprotectionscopereserve": {"CredentialProtectionScopeReserve", "POST"}, "credentialprotectionscopeget": {"CredentialProtectionScopeGet", "GET"}, "credentialpreparationfinish": {"CredentialPreparationFinish", "PATCH"}, "credentialrecoveryload": {"CredentialRecoveryLoad", "GET"}, "credentialpreparationreserve": {"CredentialPreparationReserve", "POST"}, "credentialpreparationget": {"CredentialPreparationGet", "GET"}, "credentialdeliveryreserve": {"CredentialDeliveryReserve", "POST"}, "credentialdeliveryget": {"CredentialDeliveryGet", "GET"}, "credentialdeliveryfinish": {"CredentialDeliveryFinish", "PATCH"}}
	for pkg, entry := range allowed {
		t := request.Target
		if t.Component.Kind == spec.KindComponent && t.Component.Scope == prefix+pkg && t.Component.Name == entry.name && t.Route.Method == entry.method && t.Route.Path == "/internal/data/"+pkg {
			return true
		}
	}
	return false
}

func (b *Builder) invokeCredentialDeliveryComponent(ctx context.Context, p auth.Principal, request exec.ComponentRequest) (any, error) {
	if b == nil || !credentialDeliveryComponentAllowed(request) {
		return nil, errors.New("component outside private credential delivery lifecycle exposure policy")
	}
	if request.Target.Component.Name == "CredentialProtectionScopeReserve" || request.Target.Component.Name == "CredentialProtectionScopeGet" {
		a, err := data.RequireCredentialProtectionScopeAuthority(ctx)
		if err != nil || a.Namespace != p.Namespace || a.ClientID != p.ClientID {
			return nil, auth.ErrUnauthorized
		}
	} else if request.Target.Component.Name == "CredentialRecoveryLoad" {
		// Generated reader independently restricts exact namespace/client/preparation.
	} else if request.Target.Component.Name == "CredentialPreparationFinish" || request.Target.Component.Name == "CredentialPreparationReserve" || request.Target.Component.Name == "CredentialPreparationGet" {
		a, err := data.RequireCredentialPreparationAuthority(ctx)
		if err != nil || a.Namespace != p.Namespace || a.ClientID != p.ClientID {
			return nil, auth.ErrUnauthorized
		}
	} else {
		a, err := data.RequireCredentialDeliveryAuthority(ctx)
		if err != nil || a.Record.Namespace != p.Namespace || a.Record.ClientID != p.ClientID {
			return nil, auth.ErrUnauthorized
		}
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
		return nil, errors.New("private credential delivery component runtime unavailable")
	}
	return user.server.InvokeComponent(ctx, request)
}
