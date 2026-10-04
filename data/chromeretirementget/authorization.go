package chromeretirementget

import (
	"context"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data"
)

func (in *LoadChromeRetirementInput) Init(ctx context.Context) error {
	p, err := auth.FromContext(ctx)
	if err != nil || p.Namespace != in.Namespace || p.ClientID != in.ClientID || in.TransitionID == "" {
		return auth.ErrUnauthorized
	}
	_, err = data.RequireScope(ctx, in.Namespace)
	return err
}
