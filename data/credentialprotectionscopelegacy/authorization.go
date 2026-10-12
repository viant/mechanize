package credentialprotectionscopelegacy

import (
	"context"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data"
	"net/url"
)

func (in *CredentialProtectionScopeLegacyInput) Init(ctx context.Context) error {
	p, e := auth.FromContext(ctx)
	u, ue := url.Parse(in.Origin)
	if e != nil || p.Validate() != nil || p.ClientID == "" || p.Namespace != in.Namespace || p.ClientID != in.ClientID || !p.HasScope("desktop:control") && !p.HasScope("desktop:observe") || ue != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Scheme+"://"+u.Host != in.Origin {
		return auth.ErrUnauthorized
	}
	_, e = data.RequireScope(ctx, in.Namespace)
	return e
}
