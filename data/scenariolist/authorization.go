package scenariolist

import (
	"context"
	"errors"
	"github.com/viant/mechanize/data"
)

func (input *ListScenariosInput) Init(ctx context.Context) error {
	if _, err := data.RequireScope(ctx, input.Namespace); err != nil {
		return err
	}
	if input.Limit < 1 || input.Limit > 101 {
		return errors.New("scenario reader bound required")
	}
	return nil
}
