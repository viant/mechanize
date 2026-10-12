package durable

import (
	"context"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data"
)

// CredentialProtectionRecoverySnapshot reads only generated protection metadata.
// An existing dispatch callback already owns user.mu: reuse its authenticated,
// revocable capability and hold its invocation gate for the entire projection.
// Outside dispatch, use the existing private lifecycle lock without exporting
// its invoker or permitting nested lifecycle writes.
func (b *Builder) CredentialProtectionRecoverySnapshot(ctx context.Context, p auth.Principal) ([]CredentialProtection, error) {
	actual, e := auth.FromContext(ctx)
	if b == nil || e != nil || p.Validate() != nil || actual.Namespace != p.Namespace || actual.ClientID != p.ClientID || !actual.HasScope("desktop:control") {
		return nil, auth.ErrUnauthorized
	}
	user, release, marked, e := b.heldInvocation(ctx, p)
	if e != nil {
		return nil, e
	}
	if !marked {
		var result []CredentialProtection
		e = b.WithCredentialDeliveryComponents(ctx, p, func(held context.Context, _ CredentialDeliveryComponentInvoker) error {
			var err error
			result, err = b.CredentialProtectionRecoverySnapshot(held, p)
			return err
		})
		return result, e
	}
	defer release()
	if user == nil || user.server == nil {
		return nil, data.ErrCredentialDeliveryAuthority
	}
	snapshots, e := readCredentialProtectionProjection(ctx, p, nil, user.server.InvokeComponent)
	if e != nil {
		return nil, e
	}
	for i := range snapshots {
		prep, attempts, e := readCredentialRecovery(ctx, p, snapshots[i].Scope.PreparationID, user.server.InvokeComponent)
		if e != nil {
			return nil, e
		}
		snapshots[i].Preparation = prep
		snapshots[i].Attempts = attempts
	}
	if e = ctx.Err(); e != nil {
		return nil, e
	}
	return snapshots, nil
}
