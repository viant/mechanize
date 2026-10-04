package chromeretirementwrite

import (
	"context"
	"errors"
	"github.com/viant/mechanize/data"
)

func (in *WriteChromeRetirementInput) Init(ctx context.Context) error {
	a, err := data.RequireChromeRetirementAuthority(ctx)
	if err != nil {
		return err
	}
	if in.Namespace != a.Namespace || in.ClientID != a.ClientID || in.TransitionID != a.TransitionID || len(in.WriteChromeRetirement) != 1 {
		return errors.New("exact trusted retirement input required")
	}
	return nil
}
