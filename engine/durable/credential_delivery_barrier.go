package durable

import (
	"context"
	"github.com/viant/datly/exec"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/data/credentialdeliveryblocked"
)

// CredentialDeliveryBlocked reads only a namespace-local count before exposure
// admission, including after restart. Errors block; false is not cleanup proof.
func (b *Builder) CredentialDeliveryBlocked(ctx context.Context, p auth.Principal) (bool, error) {
	actual, e := auth.FromContext(ctx)
	if b == nil || e != nil || actual.Validate() != nil || actual.Namespace != p.Namespace || actual.ClientID != p.ClientID || p.ClientID == "" || (!actual.HasScope("desktop:control") && !actual.HasScope("desktop:observe")) {
		return true, auth.ErrUnauthorized
	}
	user, release, held, e := b.heldInvocation(ctx, p)
	if e != nil {
		return true, e
	}
	if held {
		defer release()
	} else {
		ctx, user, e = b.bound(ctx, p, 0)
		if e != nil {
			return true, e
		}
		user.mu.Lock()
		defer user.mu.Unlock()
	}
	if user == nil || user.server == nil {
		return true, data.ErrCredentialDeliveryAuthority
	}
	in := &credentialdeliveryblocked.CredentialDeliveryBlockedInput{}
	in.SetNamespace(p.Namespace)
	value, e := user.server.InvokeComponent(ctx, exec.ComponentRequest{Target: credentialDeliveryTarget("credentialdeliveryblocked", "CredentialDeliveryBlocked", "GET"), Input: in})
	if e != nil {
		return true, data.ErrCredentialDeliveryAuthority
	}
	out, ok := value.(*credentialdeliveryblocked.CredentialDeliveryBlockedOutput)
	if !ok || len(out.Data) != 1 || out.Data[0].Blocked < 0 || out.Data[0].Blocked > 1 {
		return true, data.ErrCredentialDeliveryAuthority
	}
	return out.Data[0].Blocked != 0, nil
}
