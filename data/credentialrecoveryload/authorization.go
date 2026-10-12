package credentialrecoveryload

import (
	"context"
	"encoding/hex"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data"
)

func (in *CredentialRecoveryLoadInput) Init(ctx context.Context) error {
	p, e := auth.FromContext(ctx)
	id, ie := hex.DecodeString(in.PreparationID)
	if e != nil || p.Validate() != nil || !p.HasScope("desktop:control") || p.ClientID == "" || p.Namespace != in.Namespace || p.ClientID != in.ClientID || ie != nil || len(id) != 32 || hex.EncodeToString(id) != in.PreparationID {
		return data.ErrCredentialDeliveryAuthority
	}
	_, e = data.RequireScope(ctx, p.Namespace)
	return e
}
