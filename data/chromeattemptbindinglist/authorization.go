package chromeattemptbindinglist

import (
	"context"
	"errors"
	"github.com/viant/mechanize/data"
)

func (in *ListChromeAttemptBindingsInput) Init(ctx context.Context) error {
	if err := data.ValidateChromeAttemptBindingReader(ctx, in.Namespace, in.ClientID); err != nil {
		return err
	}
	for _, v := range []string{in.ProfileChannel, in.BrowserInstance, in.BrokerEpoch, in.ChannelEpoch, in.ScopeHash} {
		if v == "" || len(v) > 128 {
			return errors.New("bounded exact channel fence required")
		}
	}
	return nil
}
func (out *ListChromeAttemptBindingsOutput) Finalize(context.Context) error {
	if len(out.Data) > 64 {
		out.Data = nil
		return errors.New("binding enumeration exceeds complete proof bound")
	}
	return nil
}
