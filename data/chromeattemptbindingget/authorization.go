package chromeattemptbindingget

import (
	"context"
	"errors"
	"github.com/viant/mechanize/data"
)

func (in *LoadChromeAttemptBindingInput) Init(ctx context.Context) error {
	if err := data.ValidateChromeAttemptBindingReader(ctx, in.Namespace, in.ClientID); err != nil {
		return err
	}
	if len(in.BrowserAttemptID) != 64 {
		return errors.New("exact browser attempt lookup required")
	}
	return nil
}
