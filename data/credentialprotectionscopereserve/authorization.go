package credentialprotectionscopereserve

import (
	"context"
	"github.com/viant/mechanize/data"
)

func (in *CredentialProtectionScopeReserveInput) Init(ctx context.Context) error {
	a, e := data.RequireCredentialProtectionScopeAuthority(ctx)
	if e != nil {
		return e
	}
	if in.Namespace != a.Namespace || in.ClientID != a.ClientID || in.PreparationID != a.PreparationID || len(in.CredentialProtectionScopeReserve) != 1 {
		return data.ErrCredentialDeliveryAuthority
	}
	return nil
}
