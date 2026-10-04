package statepatch

import (
	"context"
	"fmt"
	"github.com/viant/mechanize/data"
)

func (input *StatePatchInput) Init(ctx context.Context) error {
	if len(input.StatePatch) != 1 || input.StatePatch[0].Id == nil {
		return fmt.Errorf("one state run required")
	}
	return data.RequireStateMutationPermit(ctx, input.Namespace, *input.StatePatch[0].Id)
}
