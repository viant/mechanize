package credentialdeliveryfinish

import (
	"context"
	"github.com/viant/mechanize/data"
)

func (in *CredentialDeliveryFinishInput) Init(ctx context.Context) error {
	a, e := data.RequireCredentialDeliveryAuthority(ctx)
	if e != nil {
		return e
	}
	if in.Namespace != a.Record.Namespace || in.ClientID != a.Record.ClientID || in.AttemptID != a.Record.AttemptID || len(in.CredentialDeliveryFinish) != 1 {
		return data.ErrCredentialDeliveryAuthority
	}
	return nil
}
