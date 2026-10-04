package loadplan

import (
	"context"
	"github.com/viant/mechanize/data"
)

func (input *LoadPlanInput) Init(ctx context.Context) error {
	_, err := data.RequireScope(ctx, input.Namespace)
	return err
}
