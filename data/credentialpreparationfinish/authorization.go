package credentialpreparationfinish

import (
	"context"
	"github.com/viant/mechanize/data"
)

func (in *CredentialPreparationFinishInput) Init(ctx context.Context) error {
	r, e := data.RequireCredentialPreparationAuthority(ctx)
	if e != nil || r.ProtectionState != "closed" || r.Revision != 2 || in.Namespace != r.Namespace || in.ClientID != r.ClientID || in.PreparationID != r.PreparationID || len(in.CredentialPreparationFinish) != 1 {
		return data.ErrCredentialDeliveryAuthority
	}
	return nil
}
