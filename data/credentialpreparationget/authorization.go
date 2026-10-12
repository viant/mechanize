package credentialpreparationget

import (
	"context"
	"github.com/viant/mechanize/data"
)

func (in *CredentialPreparationGetInput) Init(ctx context.Context) error {
	a, e := data.RequireCredentialPreparationAuthority(ctx)
	if e != nil {
		return e
	}
	if in.Namespace != a.Namespace || in.ClientID != a.ClientID || in.PreparationID != a.PreparationID {
		return data.ErrCredentialDeliveryAuthority
	}
	return nil
}
