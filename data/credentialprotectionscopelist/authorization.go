package credentialprotectionscopelist

import (
	"context"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data"
)

func (in *CredentialProtectionScopeListInput) Init(ctx context.Context) error {
	p, e := auth.FromContext(ctx)
	if e != nil || p.Validate() != nil || p.ClientID == "" || p.Namespace != in.Namespace || (!p.HasScope("desktop:control") && !p.HasScope("desktop:observe")) {
		return auth.ErrUnauthorized
	}
	_, e = data.RequireScope(ctx, in.Namespace)
	return e
}
