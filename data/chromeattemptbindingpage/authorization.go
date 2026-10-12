package chromeattemptbindingpage

import (
	"context"
	"errors"
	"github.com/viant/mechanize/data"
)

func (in *PageChromeAttemptBindingsInput) Init(ctx context.Context) error {
	return data.ValidateChromeReconnectBindingPage(ctx, in.Namespace, in.ProfileChannel, in.BrowserInstance, in.ScopeHash, in.AfterID)
}
func (out *PageChromeAttemptBindingsOutput) Finalize(ctx context.Context) error {
	if len(out.Data) > data.ChromeReconnectBindingPageSize {
		out.Data = nil
		return errors.New("binding page exceeded fixed boundary")
	}
	if err := ctx.Err(); err != nil {
		out.Data = nil
		return err
	}
	return nil
}
