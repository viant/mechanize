package credentialdeliveryget

import (
	"context"
	"github.com/viant/mechanize/data"
)

func (in *CredentialDeliveryGetInput) Init(ctx context.Context) error {
	a, e := data.RequireCredentialDeliveryAuthority(ctx)
	if e != nil {
		return e
	}
	if in.Namespace != a.Record.Namespace || in.ClientID != a.Record.ClientID || in.AttemptID != a.Record.AttemptID {
		return data.ErrCredentialDeliveryAuthority
	}
	return nil
}
