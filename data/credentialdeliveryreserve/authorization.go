package credentialdeliveryreserve

import (
	"context"
	"github.com/viant/mechanize/data"
)

func (in *CredentialDeliveryReserveInput) Init(ctx context.Context) error {
	if _, ok := data.CredentialSourceLifecycleScope(ctx); ok {
		return data.ErrCredentialDeliveryAuthority
	}
	a, e := data.RequireCredentialDeliveryAuthority(ctx)
	if e != nil {
		return e
	}
	if in.Namespace != a.Record.Namespace || in.ClientID != a.Record.ClientID || in.AttemptID != a.Record.AttemptID || len(in.CredentialDeliveryReserve) != 1 {
		return data.ErrCredentialDeliveryAuthority
	}
	return nil
}
