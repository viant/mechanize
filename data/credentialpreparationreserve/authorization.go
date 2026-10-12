package credentialpreparationreserve

import (
	"context"
	"github.com/viant/mechanize/data"
)

func (in *CredentialPreparationReserveInput) Init(ctx context.Context) error {
	a, e := data.RequireCredentialPreparationAuthority(ctx)
	if e != nil {
		return e
	}
	if in.Namespace != a.Namespace || in.ClientID != a.ClientID || in.PreparationID != a.PreparationID || len(in.CredentialPreparationReserve) != 1 {
		return data.ErrCredentialDeliveryAuthority
	}
	return nil
}
